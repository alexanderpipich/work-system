"""
Рассылка сверок — сбор данных и сборка писем на магазин (калька рассылки БП).

Модуль только СОБИРАЕТ смены ТК за период (БЕЗ смен без плана), СТРОИТ письма
для предпросмотра и генерирует XLS-вложение. Отправка, EmailLog и идемпотентность
(ReconciliationNotification) — в роутере по явному нажатию.

Юрлицо «Поставщик (Исполнитель)» — константа COMPANY_NAME_PLAIN, как в БП
(механизма выбора LegalEntity под ТК в проекте нет; согласовано с владельцем).
Два типа сверки: A — 01-15 (рассылка 17-го), B — 01-31 / весь месяц (рассылка 03-го).
"""

import calendar
from datetime import date
from html import escape

from sqlalchemy.orm import Session

from models import ReconciliationNotification, Shift, Store, StoreContact
from planning_pdf import COMPANY_NAME_PLAIN
from reconciliation_xls import build_filename, build_reconciliation_xls, format_hours
from shift_helpers import is_no_plan_shift
from store_helpers import extract_tk_number
from time_helpers import business_today
from unplanned_helpers import MONTHS_GEN, MONTHS_NOM

LEGAL_ENTITY_LABEL = COMPANY_NAME_PLAIN  # «ООО ПРОГРЕСС»

RECON_TYPES = ("A", "B")


# --- Периоды и подписи ---------------------------------------------------

def period_for(recon_type: str, year: int, month: int):
    """(period_from, period_to) для типа сверки. A — 01-15; B — весь месяц."""
    start = date(year, month, 1)
    if recon_type == "A":
        end = date(year, month, 15)
    else:
        last_day = calendar.monthrange(year, month)[1]
        end = date(year, month, last_day)
    return start, end


def period_label_short(recon_type: str) -> str:
    """Короткая подпись периода для темы: 01-15 / 01-31."""
    return "01-15" if recon_type == "A" else "01-31"


def period_label_words(recon_type: str, year: int, month: int) -> str:
    """Подпись периода словами: «01-15 апреля 2026»."""
    return f"{period_label_short(recon_type)} {MONTHS_GEN[month]} {year}"


def month_label_nom(month: int) -> str:
    return MONTHS_NOM[month]


def month_label_file(year: int, month: int) -> str:
    """Для имени файла: «апрель 2026»."""
    return f"{MONTHS_NOM[month].lower()} {year}"


def resolve_default_period(today=None):
    """
    Последняя сверка к рассылке на сегодня (тип, год, месяц):
      после 17 → A текущего месяца; после 03 → B предыдущего; до 03 → A предыдущего.
    """
    today = today or business_today()
    if today.day >= 17:
        return "A", today.year, today.month
    # предыдущий месяц
    prev_year, prev_month = (today.year, today.month - 1) if today.month > 1 else (today.year - 1, 12)
    if today.day >= 3:
        return "B", prev_year, prev_month
    return "A", prev_year, prev_month


# --- Смены ----------------------------------------------------------------

def shifts_for_period(session: Session, date_from, date_to, tk_filter=None):
    """Смены за период, сгруппированные по ТК, БЕЗ смен без плана."""
    rows = (
        session.query(Shift)
        .filter(Shift.shift_date >= date_from, Shift.shift_date <= date_to)
        .all()
    )
    groups = {}
    for s in rows:
        if is_no_plan_shift(s):
            continue
        tk = extract_tk_number(s.store)
        if tk is None:
            continue
        if tk_filter is not None and tk != tk_filter:
            continue
        group = groups.setdefault(tk, {"store_str": s.store, "shifts": []})
        group["shifts"].append(s)
        if len(s.store) > len(group["store_str"]):
            group["store_str"] = s.store
    return groups


# --- Письма ---------------------------------------------------------------

def _subject(tk, recon_type, year, month):
    return (
        f"СВЕРКА / {LEGAL_ENTITY_LABEL} / {month_label_nom(month)} / "
        f"{period_label_short(recon_type)} / ТК {tk}"
    )


def _body(tk, store, period_words):
    location_bits = []
    if store is not None:
        if store.city:
            location_bits.append(store.city)
        if store.object_address:
            location_bits.append(store.object_address)
    location = ", ".join(location_bits)
    location_suffix = f" ({location})" if location else ""

    body_text = (
        "Уважаемые коллеги!\n\n"
        f"Направляем сверку отработанных часов по ТК {tk}{location_suffix} "
        f"за период {period_words}.\n"
        "Сверка — во вложении (XLS).\n\n"
        "Просим сверить данные и подтвердить.\n\n"
        f"С уважением,\n{LEGAL_ENTITY_LABEL}"
    )
    body_html = (
        "<p>Уважаемые коллеги!</p>"
        f"<p>Направляем сверку отработанных часов по ТК {tk}{escape(location_suffix)} "
        f"за период {escape(period_words)}.</p>"
        "<p>Сверка — во вложении (XLS).</p>"
        "<p>Просим сверить данные и подтвердить.</p>"
        f"<p>С уважением,<br>{escape(LEGAL_ENTITY_LABEL)}</p>"
    )
    return body_text, body_html


def collect_reconciliation(session: Session, recon_type, year, month, tk_filter=None) -> dict:
    """
    Собрать магазины к рассылке сверки, построить письма.

    Кандидаты — ТК со сменами (без смен без плана) за период. Возвращает dict:
      to_send: [letter, ...] — магазины с контактами for_reconciliation
      no_contacts: [{tk, store, shift_count, employees_count, hours}, ...]
      total_letters / total_pending / already_sent_count / stores_without_contacts
    """
    period_from, period_to = period_for(recon_type, year, month)
    period_words = period_label_words(recon_type, year, month)
    groups = shifts_for_period(session, period_from, period_to, tk_filter=tk_filter)

    tks = list(groups.keys())
    stores = {}
    if tks:
        stores = {
            st.tk_number: st
            for st in session.query(Store).filter(Store.tk_number.in_(tks)).all()
        }

    sent_keys = {
        row[0]
        for row in session.query(ReconciliationNotification.store_tk)
        .filter(
            ReconciliationNotification.period_from == period_from,
            ReconciliationNotification.period_to == period_to,
            ReconciliationNotification.recon_type == recon_type,
            ReconciliationNotification.status == "sent",
        )
        .all()
    }

    to_send = []
    no_contacts = []
    for tk in sorted(groups.keys()):
        shifts = groups[tk]["shifts"]
        store = stores.get(tk)
        hours = sum(float(s.hours or 0) for s in shifts)
        employees = {s.employee for s in shifts}

        contacts = []
        if store is not None:
            contacts = [
                c.email
                for c in session.query(StoreContact)
                .filter(
                    StoreContact.store_id == store.id,
                    StoreContact.for_reconciliation == True,
                    StoreContact.is_active == True,
                )
                .all()
                if c.email
            ]

        store_label = store.display_name if store is not None else groups[tk]["store_str"]
        if not contacts:
            no_contacts.append({
                "tk": tk,
                "store": store_label,
                "shift_count": len(shifts),
                "employees_count": len(employees),
                "hours": format_hours(hours),
            })
            continue

        body_text, body_html = _body(tk, store, period_words)
        to_send.append({
            "tk": tk,
            "store": store_label,
            "contacts": contacts,
            "subject": _subject(tk, recon_type, year, month),
            "body_html": body_html,
            "body_text": body_text,
            "period": period_words,
            "shift_count": len(shifts),
            "employees_count": len(employees),
            "hours": format_hours(hours),
            "already_sent": tk in sent_keys,
        })

    pending = [l for l in to_send if not l["already_sent"]]
    return {
        "to_send": to_send,
        "no_contacts": no_contacts,
        "total_letters": len(to_send),
        "total_pending": len(pending),
        "already_sent_count": len(to_send) - len(pending),
        "stores_without_contacts": len(no_contacts),
        "period_label": period_words,
        "period_from": period_from,
        "period_to": period_to,
        "recon_type": recon_type,
        "year": year,
        "month": month,
    }


def build_reconciliation_attachment(session: Session, tk, recon_type, year, month):
    """Сгенерировать XLS-сверку по ТК+период+тип, вернуть (filename, bytes)."""
    period_from, period_to = period_for(recon_type, year, month)
    groups = shifts_for_period(session, period_from, period_to, tk_filter=tk)
    shifts = groups.get(tk, {}).get("shifts", [])

    store = session.query(Store).filter(Store.tk_number == tk).first()
    store_name = store.display_name if store is not None else (
        groups.get(tk, {}).get("store_str") or f"ТК-{tk:03d}"
    )
    total_hours = sum(float(s.hours or 0) for s in shifts)

    data = build_reconciliation_xls(
        tk=tk,
        store_name=store_name,
        legal_entity=LEGAL_ENTITY_LABEL,
        period_label=period_label_words(recon_type, year, month),
        shifts=shifts,
    )
    filename = build_filename(tk, LEGAL_ENTITY_LABEL, month_label_file(year, month), total_hours)
    return filename, data

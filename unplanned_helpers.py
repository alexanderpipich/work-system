"""
Email Слой 2 — детекция смен без плана и формирование писем на магазин.

Боевая рассылка по внешним адресам: ничего не отправляется отсюда — модуль
только СОБИРАЕТ данные и СТРОИТ письма для предпросмотра. Отправка и запись
идемпотентности — в роутере по явному нажатию владельца.
"""

import os
from datetime import timedelta
from html import escape

from sqlalchemy.orm import Session

from models import Shift, Store, StoreContact, UnplannedNotification
from shift_helpers import is_no_plan_shift
from store_helpers import extract_tk_number
from time_helpers import business_today

# Порог: уведомлять о сменах без плана старше N дней после даты смены.
UNPLANNED_NOTIFY_DELAY_DAYS = 3

# Юрлицо для темы письма. В Shift юрлица нет — у компании оно единое.
LEGAL_ENTITY_LABEL = os.getenv("UNPLANNED_LEGAL_ENTITY", "ООО Прогресс")

MONTHS_GEN = {
    1: "января", 2: "февраля", 3: "марта", 4: "апреля", 5: "мая", 6: "июня",
    7: "июля", 8: "августа", 9: "сентября", 10: "октября", 11: "ноября", 12: "декабря",
}
MONTHS_NOM = {
    1: "Январь", 2: "Февраль", 3: "Март", 4: "Апрель", 5: "Май", 6: "Июнь",
    7: "Июль", 8: "Август", 9: "Сентябрь", 10: "Октябрь", 11: "Ноябрь", 12: "Декабрь",
}


def format_date_ru(d):
    return f"{d.day} {MONTHS_GEN[d.month]} {d.year}"


def format_hours(h):
    if h is None:
        return "—"
    return str(int(h)) if float(h).is_integer() else str(h)


def cutoff_date():
    return business_today() - timedelta(days=UNPLANNED_NOTIFY_DELAY_DAYS)


def build_letter(tk, store, store_str, shifts, contacts):
    """Сформировать одно письмо на магазин со всеми его сменами без плана."""
    dates = [s.shift_date for s in shifts]
    date_from, date_to = min(dates), max(dates)

    months = sorted({(d.year, d.month) for d in dates})
    month_label = " / ".join(MONTHS_NOM[m] for (_, m) in months)

    if date_from == date_to:
        period = date_from.strftime("%d.%m.%Y")
    else:
        period = f"{date_from.strftime('%d.%m.%Y')}–{date_to.strftime('%d.%m.%Y')}"

    subject = f"Смены без плана / {LEGAL_ENTITY_LABEL} / {month_label} / {period} / ТК {tk}"

    location_bits = []
    if store is not None:
        if store.city:
            location_bits.append(store.city)
        if store.object_address:
            location_bits.append(store.object_address)
    location = ", ".join(location_bits)
    location_suffix = f" ({location})" if location else ""

    lines = [
        f"{s.employee} — {format_date_ru(s.shift_date)} — {format_hours(s.hours)} ч"
        for s in shifts
    ]

    body_text = (
        "Уважаемые коллеги!\n\n"
        f"Информируем о наличии смен без плана по ТК {tk}{location_suffix}:\n"
        + "\n".join(f"- {ln}" for ln in lines)
        + "\n\nПросим перепроверить и при необходимости внести плановые назначения.\n\n"
        f"С уважением,\n{LEGAL_ENTITY_LABEL}"
    )

    html_items = "".join(f"<li>{escape(ln)}</li>" for ln in lines)
    body_html = (
        "<p>Уважаемые коллеги!</p>"
        f"<p>Информируем о наличии смен без плана по ТК {tk}{escape(location_suffix)}:</p>"
        f"<ul>{html_items}</ul>"
        "<p>Просим перепроверить и при необходимости внести плановые назначения.</p>"
        f"<p>С уважением,<br>{escape(LEGAL_ENTITY_LABEL)}</p>"
    )

    return {
        "tk": tk,
        "store": store.display_name if store is not None else store_str,
        "contacts": contacts,
        "subject": subject,
        "body_html": body_html,
        "body_text": body_text,
        "period": period,
        "shifts": [
            {
                "shift_id": s.id,
                "employee": s.employee,
                "date": format_date_ru(s.shift_date),
                "hours": format_hours(s.hours),
            }
            for s in shifts
        ],
        "shift_ids": [s.id for s in shifts],
    }


def collect_unplanned(session: Session, date_from=None, date_to=None, tk_filter=None) -> dict:
    """
    Собрать смены без плана к рассылке, сгруппировать по ТК, построить письма.

    Возвращает dict:
      to_send: [letter, ...] — магазины с контактами for_unplanned
      no_contacts: [{tk, store, shift_count}, ...] — есть смены, но некому слать
      total_letters / total_shifts / stores_without_contacts / cutoff
    """
    cutoff = cutoff_date()
    effective_to = cutoff if date_to is None else min(date_to, cutoff)

    query = session.query(Shift).filter(Shift.shift_date <= effective_to)
    if date_from is not None:
        query = query.filter(Shift.shift_date >= date_from)

    # Только смены с реальными часами (hours > 0). Нулевые/None/отрицательные
    # смены без плана — вероятный баг timebook, директору слать про них нечего.
    # Фильтр ТОЛЬКО здесь (сбор писем), не глобально: кабинет/payroll/детекция —
    # читают нулевые смены без плана как прежде.
    candidates = [
        s
        for s in query.all()
        if is_no_plan_shift(s) and (s.hours or 0) > 0
    ]

    # Идемпотентность: исключить смены с успешно отправленным уведомлением.
    notified_ids = {
        row[0]
        for row in session.query(UnplannedNotification.shift_id)
        .filter(UnplannedNotification.status == "sent")
        .all()
    }
    pending = [s for s in candidates if s.id not in notified_ids]

    groups = {}
    for s in pending:
        tk = extract_tk_number(s.store)
        if tk is None:
            continue
        if tk_filter is not None and tk != tk_filter:
            continue
        group = groups.setdefault(tk, {"store_str": s.store, "shifts": []})
        group["shifts"].append(s)
        if len(s.store) > len(group["store_str"]):
            group["store_str"] = s.store

    tks = list(groups.keys())
    stores = {}
    if tks:
        stores = {
            st.tk_number: st
            for st in session.query(Store).filter(Store.tk_number.in_(tks)).all()
        }

    to_send = []
    no_contacts = []
    for tk in sorted(groups.keys()):
        group = groups[tk]
        store = stores.get(tk)
        shifts_sorted = sorted(group["shifts"], key=lambda s: (s.shift_date, s.employee))

        contacts = []
        if store is not None:
            contacts = [
                c.email
                for c in session.query(StoreContact)
                .filter(
                    StoreContact.store_id == store.id,
                    StoreContact.for_unplanned == True,
                    StoreContact.is_active == True,
                )
                .all()
                if c.email
            ]

        if not contacts:
            no_contacts.append({
                "tk": tk,
                "store": store.display_name if store is not None else group["store_str"],
                "shift_count": len(shifts_sorted),
            })
            continue

        to_send.append(build_letter(tk, store, group["store_str"], shifts_sorted, contacts))

    total_shifts = sum(len(letter["shifts"]) for letter in to_send)
    return {
        "to_send": to_send,
        "no_contacts": no_contacts,
        "total_letters": len(to_send),
        "total_shifts": total_shifts,
        "stores_without_contacts": len(no_contacts),
        "cutoff": cutoff,
    }

"""
Рассылка БП (Бланк планирования) — сбор данных и сборка писем на магазин.

Калька со Слоя 2 (unplanned_helpers): модуль только СОБИРАЕТ данные и СТРОИТ
письма для предпросмотра, плюс генерирует PDF-вложение по ТК+периоду. Отправка,
EmailLog и идемпотентность (BPNotification) — в роутере по явному нажатию.

Период и список сотрудников переиспользуются из Пункта 1 (routers.planning_bp),
генератор PDF — из planning_pdf. Ничего не дублируем.
"""

from html import escape

from sqlalchemy.orm import Session

from models import BPNotification, EmployeeStoreAssignment, Store, StoreContact
from planning_pdf import COMPANY_NAME_PLAIN, build_filename, build_planning_pdf
from routers.planning_bp import PLANNING_DIR, _employees_for_tk, _parse_date, _period
from store_helpers import extract_tk_number
from unplanned_helpers import MONTHS_NOM
from utils import normalize_format

# БП формируется ТОЛЬКО для гипермаркетов (формат ГМ). Прочие форматы (СМ и т.п.)
# и ТК без записи в справочнике магазинов — не кандидаты на бланк планирования.
BP_FORMAT = "ГМ"


def resolve_period(date_from: str, date_to: str):
    """Период из формы; пустые поля → дефолт (сегодня … конец месяца)."""
    default_start, default_end = _period()
    start = _parse_date(date_from) or default_start
    end = _parse_date(date_to) or default_end
    return start, end


def _months_in_range(start, end):
    months = []
    y, m = start.year, start.month
    while (y, m) <= (end.year, end.month):
        months.append((y, m))
        m += 1
        if m > 12:
            m = 1
            y += 1
    return months


def _month_label(start, end):
    return " / ".join(MONTHS_NOM[m] for (_, m) in _months_in_range(start, end))


def _period_label(start, end):
    if start == end:
        return start.strftime("%d.%m.%Y")
    return f"{start.strftime('%d.%m.%Y')}–{end.strftime('%d.%m.%Y')}"


def _build_letter(tk, store, employees, contacts, start, end, already_sent):
    period = _period_label(start, end)
    subject = f"БП / {COMPANY_NAME_PLAIN} / {_month_label(start, end)} / {period} / ТК {tk}"

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
        f"Направляем бланк планирования по ТК {tk}{location_suffix} "
        f"на период {period}.\n"
        "Бланк — во вложении (PDF).\n\n"
        "Просим обеспечить доступ перечисленным в бланке сотрудникам.\n\n"
        f"С уважением,\n{COMPANY_NAME_PLAIN}"
    )
    body_html = (
        "<p>Уважаемые коллеги!</p>"
        f"<p>Направляем бланк планирования по ТК {tk}{escape(location_suffix)} "
        f"на период {escape(period)}.</p>"
        "<p>Бланк — во вложении (PDF).</p>"
        "<p>Просим обеспечить доступ перечисленным в бланке сотрудникам.</p>"
        f"<p>С уважением,<br>{escape(COMPANY_NAME_PLAIN)}</p>"
    )

    return {
        "tk": tk,
        "store": store.display_name if store is not None else f"ТК-{tk:03d}",
        "contacts": contacts,
        "subject": subject,
        "body_html": body_html,
        "body_text": body_text,
        "period": period,
        "employees_count": len(employees),
        "already_sent": already_sent,
    }


def collect_planning_bp(session: Session, date_from, date_to, tk_filter=None) -> dict:
    """
    Собрать магазины к рассылке БП, построить письма.

    Кандидаты — ТК с активными привязками EmployeeStoreAssignment (есть кого
    включить в бланк). Возвращает dict:
      to_send: [letter, ...] — магазины с контактами for_planning
      no_contacts: [{tk, store, employees_count}, ...] — некому слать
      total_letters / total_pending / cutoff-аналогов нет (период задаётся вручную)
    """
    rows = (
        session.query(EmployeeStoreAssignment)
        .filter(EmployeeStoreAssignment.is_active == True)
        .all()
    )
    tks = set()
    for r in rows:
        if not r.employee_name:
            continue
        tk = extract_tk_number(r.store)
        if tk is None:
            continue
        if tk_filter is not None and tk != tk_filter:
            continue
        tks.add(tk)

    stores = {}
    if tks:
        stores = {
            st.tk_number: st
            for st in session.query(Store).filter(Store.tk_number.in_(tks)).all()
        }

    # Уже отправленные за этот период (идемпотентность).
    sent_tks = {
        row[0]
        for row in session.query(BPNotification.store_tk)
        .filter(
            BPNotification.period_from == date_from,
            BPNotification.period_to == date_to,
            BPNotification.status == "sent",
        )
        .all()
    }

    to_send = []
    no_contacts = []
    for tk in sorted(tks):
        store = stores.get(tk)
        # БП только для ГМ: ТК без записи в Store или иного формата — не кандидат.
        if store is None or normalize_format(store.format) != BP_FORMAT:
            continue
        employees = _employees_for_tk(session, tk)

        contacts = []
        if store is not None:
            contacts = [
                c.email
                for c in session.query(StoreContact)
                .filter(
                    StoreContact.store_id == store.id,
                    StoreContact.for_planning == True,
                    StoreContact.is_active == True,
                )
                .all()
                if c.email
            ]

        if not contacts:
            no_contacts.append({
                "tk": tk,
                "store": store.display_name if store is not None else f"ТК-{tk:03d}",
                "employees_count": len(employees),
            })
            continue

        to_send.append(
            _build_letter(tk, store, employees, contacts, date_from, date_to, tk in sent_tks)
        )

    pending = [l for l in to_send if not l["already_sent"]]
    return {
        "to_send": to_send,
        "no_contacts": no_contacts,
        "total_letters": len(to_send),
        "total_pending": len(pending),
        "already_sent_count": len(to_send) - len(pending),
        "stores_without_contacts": len(no_contacts),
        "period_label": _period_label(date_from, date_to),
    }


def build_bp_attachment(session: Session, tk: int, date_from, date_to):
    """Сгенерировать PDF БП по ТК+периоду, вернуть (filename, bytes)."""
    store = session.query(Store).filter(Store.tk_number == tk).first()
    employees = _employees_for_tk(session, tk)

    PLANNING_DIR.mkdir(parents=True, exist_ok=True)
    path = PLANNING_DIR / f"bp_mail_{tk}_{date_from}_{date_to}.pdf"
    build_planning_pdf(
        path,
        tk_number=tk,
        object_address=store.object_address if store is not None else None,
        city=store.city if store is not None else None,
        date_from=date_from,
        date_to=date_to,
        employees=employees,
    )
    return build_filename(tk, date_from), path.read_bytes()

"""«Еженедельный отчёт» (П4.6) — рабочий экран ТМ по понедельникам: данные и xlsx.

Табель за завершившуюся неделю Пн–Вс: строка на (сотрудник, ТК, услуга) — общий
построитель timesheet.build_timesheet_rows (тот же, что у листа «Табель» ведомости).
Город — тарифный регион магазина (пусто → город смены); смена без плана — день 0 с
красной заливкой; Ставка — чистая ЧТС (нет → «НЕТ»); Акция — Σ надбавок к часу по
сменам со ставкой; ФОТ = Σ часы × ЧТС + Акция. Строки без реквизитов — розовые.

Мутации экрана (ставка, ТМ, статусы недели, аванс) — weekly_actions.
"""

from collections import OrderedDict
from datetime import datetime, timedelta
from io import BytesIO

from file_storage import storage_save
from models import Requisite, TmChangeRequest, WeeklyReview, WeeklyTmCheck
from payouts_helpers import (REGISTRY_PREFIX, XLSX_CONTENT_TYPE, default_week, has_card, no_rate_summary,
                             week_monday, week_selection)
from time_helpers import now_utc
from timesheet import build_timesheet_rows, date_range, shift_lines
from utils import normalize_person_name, normalize_text

WEEKLY_SHEET = "Недельный отчёт"
WEEKLY_PREFIX = f"{REGISTRY_PREFIX}/weekly"
HEAD = ["ФИО сотрудника Исполнителя", "Номер ТК", "Город", "Тип", "Услуга"]
TAIL = ["ИЧ", "ТМ", "Ставка", "Акция", "ФОТ"]
NO_RATE = "НЕТ"
NO_TM = "ПУСТО"
TOTAL = "Итог"
NO_PLAN_FILL = "FF0000"
NO_REQUISITES_FILL = "FFC7CE"
MONEY_FORMAT = '#,##0.00\\ "₽"'
WIDTHS = {"A": 32, "B": 7, "C": 14, "D": 6, "E": 36, "M": 7, "N": 18, "O": 13, "P": 13, "Q": 15}
DAY_WIDTH = 7
CLOSED_HINT = "неделя закрыта, обратитесь к экономисту"
NO_REQUISITES_HINT = "нет реквизитов для выплаты"


def last_complete_week(today):
    """Понедельник последней завершившейся недели — той, чьё воскресенье раньше сегодня."""
    return default_week(today)


def resolve_week(value, today):
    """Неделя отчёта: дата округляется вниз до понедельника; незавершённая (и будущая)
    неделя недоступна — берётся последняя завершившаяся; без значения — она же."""
    latest = last_complete_week(today)
    try:
        week_start = week_monday(datetime.strptime(value, "%Y-%m-%d").date())
    except (TypeError, ValueError):
        return latest
    return min(week_start, latest)


def week_days(week_start):
    return date_range(week_start, week_start + timedelta(days=6))


def requisite_lookup(session):
    """(User | None, ФИО) → активный реквизит — как payouts_helpers.active_requisite
    (сначала по user_id, затем по ФИО; последний по id), одним запросом."""
    by_user, by_name = {}, {}
    for req in session.query(Requisite).filter(Requisite.is_active == True).order_by(Requisite.id):  # noqa: E712
        if req.user_id:
            by_user[req.user_id] = req
        if req.employee_name:
            by_name[req.employee_name] = req

    def lookup(user, name):
        return (by_user.get(user.id) if user else None) or by_name.get(normalize_text(name))
    return lookup


def rate_note(rate):
    """Подсказка у индивидуальной ставки: «индивидуальная с dd.mm, <комментарий>»."""
    if rate is None or not normalize_text(rate.employee_name):
        return ""
    note = "индивидуальная"
    if rate.active_from:
        note += f" с {rate.active_from:%d.%m}"
    if normalize_text(rate.comment):
        note += f", {normalize_text(rate.comment)}"
    return note


def weekly_rows(session, week_start):
    """(строки отчёта, смены недели) — строки в порядке файла, по ФИО без учёта регистра."""
    week_end = week_start + timedelta(days=6)
    lines = shift_lines(session, week_start, week_end, include_no_plan=True)
    requisite = requisite_lookup(session)
    cards = {}
    rows = []
    for line in build_timesheet_rows(session, week_start, week_end, lines=lines):
        key = normalize_person_name(line["name"])
        if key not in cards:
            cards[key] = has_card(requisite(line["user"], line["name"]))
        rate = line["rate"]
        rows.append({
            "key": key,
            "name": line["name"],
            "tk": line["tk"],
            "store": line["store"],
            "city": line["city"] or "",
            "format": line["format"] or "",
            "service": line["service"],
            "days": [line["days"].get(day) for day in week_days(week_start)],
            "no_plan_days": [day in line["no_plan_days"] and day not in line["main_days"]
                             for day in week_days(week_start)],
            "hours": line["hours"],
            "tm_id": line["tm_id"],
            "tm": line["tm"] or NO_TM,
            "rate": line["rate_last"] or None,
            "rate_individual": bool(rate is not None and normalize_text(rate.employee_name)),
            "rate_note": rate_note(rate),
            "bonus": round(line["bonus"], 2),
            "fot": round(line["fot"] + line["bonus"], 2),
            "no_rate": line["no_rate"],
            "has_requisites": cards[key],
            "user": line["user"],
            "user_id": line["user_id"],
        })
    return rows, lines


def weekly_report(session, week_start):
    """{week_start, week_end, days, rows, total_hours, total_fot, no_rate, people}: people —
    {ключ ФИО: {name, fot, user, tm_id, has_requisites}} для аванса (ФОТ недели сотрудника)."""
    rows, lines = weekly_rows(session, week_start)
    people = OrderedDict()
    for row in rows:
        person = people.setdefault(row["key"], {"name": row["name"], "fot": 0.0, "user": row["user"],
                                                "tm_id": row["tm_id"], "has_requisites": row["has_requisites"]})
        person["fot"] = round(person["fot"] + row["fot"], 2)
    return {
        "week_start": week_start,
        "week_end": week_start + timedelta(days=6),
        "days": week_days(week_start),
        "rows": rows,
        "total_hours": sum(row["hours"] for row in rows),
        "total_fot": round(sum(row["fot"] for row in rows), 2),
        "no_rate": no_rate_summary((line.service, line.hours) for line in lines
                                   if not line.rate and not line.no_plan),
        "people": people,
    }


def filter_rows(rows, *, tm=0, q="", no_tm=False, no_requisites=False, no_rate=False):
    if tm:
        rows = [r for r in rows if r["tm_id"] == tm]
    if normalize_text(q):
        needle = normalize_person_name(q)
        rows = [r for r in rows if needle in r["key"]]
    if no_tm:
        rows = [r for r in rows if not r["tm_id"]]
    if no_requisites:
        rows = [r for r in rows if not r["has_requisites"]]
    if no_rate:
        rows = [r for r in rows if r["no_rate"]]
    return rows


# ── Статусы недели (блок E) ──────────────────────────────────────────────────

def week_review(session, week_start):
    return session.query(WeeklyReview).filter(WeeklyReview.week_start == week_start).first()


def is_week_closed(session, week_start):
    review = week_review(session, week_start)
    return bool(review and review.closed_at)


def tm_checks(session, week_start):
    """{tm_id: WeeklyTmCheck}."""
    return {c.tm_id: c for c in session.query(WeeklyTmCheck).filter(WeeklyTmCheck.week_start == week_start)}


def pending_tm_requests(session):
    return (session.query(TmChangeRequest).filter(TmChangeRequest.status == "pending")
            .order_by(TmChangeRequest.id).all())


def employees_without_tm(session, week_start):
    """Число сотрудников со сменами недели без ТМ (нет User или User.tm_id пуст) — плашка дашборда ТМ."""
    from models import Shift, User

    names = {normalize_person_name(name) for (name,) in session.query(Shift.employee).filter(
        Shift.shift_date >= week_start, Shift.shift_date <= week_start + timedelta(days=6)).distinct()}
    with_tm = {u.employee_name_norm for u in session.query(User).filter(User.tm_id.isnot(None))}
    return len({name for name in names if name} - with_tm)


def selection_state(session, week_start):
    """{ключ ФИО: AdvanceSelection} недели — то же состояние, что на странице авансов."""
    return week_selection(session, week_start)


# ── xlsx (блок G) ────────────────────────────────────────────────────────────

def weekly_filename(week_start):
    return f"Недельный_отчёт_{week_start:%d.%m.%Y}-{week_start + timedelta(days=6):%d.%m.%Y}.xlsx"


def build_weekly_xlsx(report):
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill

    titles = [str(day.day) for day in report["days"]]
    columns = HEAD + titles + TAIL
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = WEEKLY_SHEET
    sheet.append(columns)
    for cell in sheet[1]:
        cell.font = Font(bold=True)
    red = PatternFill("solid", fgColor=NO_PLAN_FILL)
    pink = PatternFill("solid", fgColor=NO_REQUISITES_FILL)
    for row in report["rows"]:
        sheet.append([row["name"], row["tk"], row["city"] or None, row["format"] or None, row["service"]]
                     + row["days"]
                     + [row["hours"], row["tm"], row["rate"] if row["rate"] else NO_RATE, row["bonus"], row["fot"]])
        cells = sheet[sheet.max_row]
        if not row["has_requisites"]:
            for cell in cells:
                cell.fill = pink
        for index, no_plan in enumerate(row["no_plan_days"]):
            if no_plan:
                cells[len(HEAD) + index].fill = red
        for cell in cells[-3:]:
            if isinstance(cell.value, (int, float)):
                cell.number_format = MONEY_FORMAT
    totals = [TOTAL] + [None] * (len(columns) - 1)
    totals[columns.index("ИЧ")] = report["total_hours"]
    totals[columns.index("ФОТ")] = report["total_fot"]
    sheet.append(totals)
    sheet[sheet.max_row][-1].number_format = MONEY_FORMAT
    sheet.freeze_panes = "A2"
    for letter, width in WIDTHS.items():
        sheet.column_dimensions[letter].width = width
    for index in range(len(titles)):
        sheet.column_dimensions[chr(ord("F") + index)].width = DAY_WIDTH

    buffer = BytesIO()
    workbook.save(buffer)
    return buffer.getvalue()


def save_weekly(session, week_start):
    """Сформировать отчёт, сохранить копию в хранилище; вернуть (ключ, имя файла)."""
    filename = weekly_filename(week_start)
    content = build_weekly_xlsx(weekly_report(session, week_start))
    stamp = now_utc().strftime("%Y%m%d-%H%M%S")
    key = f"{WEEKLY_PREFIX}/{week_start.isoformat()}/{stamp}_{filename}"
    storage_save(key, content, content_type=XLSX_CONTENT_TYPE)
    return key, filename

"""Еженедельный отчёт по сменам (П4.6): табель за завершившуюся неделю Пн–Вс со ставкой и ФОТ.

Справочный отчёт «сколько кто отработал и на какую сумму» — не связан с авансами и
фиксацией. Строки — общий построитель timesheet.build_timesheet_rows (тот же, что у
листа «Табель» ведомости), по сменам недели: город и тип — как в смене (не тарифный
регион), ставка = ЧТС + надбавки последней смены со ставкой, ФОТ = Σ часы × (ЧТС + надбавка).
xlsx — в формате образца коллег, лист «Недельный отчёт», 16 колонок.
"""

from datetime import datetime, timedelta
from io import BytesIO

from file_storage import storage_save
from payouts_helpers import REGISTRY_PREFIX, XLSX_CONTENT_TYPE, default_week, no_rate_summary, week_monday
from time_helpers import now_utc
from timesheet import build_timesheet_rows, date_range, shift_lines

WEEKLY_SHEET = "Недельный отчёт"
WEEKLY_PREFIX = f"{REGISTRY_PREFIX}/weekly"
HEAD = ["ФИО сотрудника Исполнителя", "№", "Город", "Тип", "Услуга"]
TAIL = ["ИЧ", "ТМ", "Ставка", "ФОТ"]
NO_RATE = "НЕТ"
TOTAL = "ИТОГО"
HEADER_FILL = "1F4E79"
MONEY_FORMAT = "#\\ ##0\\ [$₽-419];\\-#\\ ##0\\ [$₽-419]"
HOURS_FORMAT = "0.00"
WIDTHS = {"A": 32, "B": 7, "C": 14, "D": 6, "E": 36, "M": 7, "N": 18, "O": 13, "P": 15}
DAY_WIDTH = 7


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


def day_titles(week_start):
    return [day.strftime("%d.%m") for day in date_range(week_start, week_start + timedelta(days=6))]


def weekly_report(session, week_start):
    """{days, rows, total, no_rate}: rows — строки отчёта в порядке образца (dict по колонкам
    + служебные tm_id/name), total — Σ ФОТ, no_rate — сводка «без ЧТС» как на авансах."""
    week_end = week_start + timedelta(days=6)
    lines = shift_lines(session, week_start, week_end)
    days = date_range(week_start, week_end)
    titles = day_titles(week_start)
    rows = []
    for line in build_timesheet_rows(session, week_start, week_end, lines=lines):
        rate = line["rate_last"]
        row = {"ФИО сотрудника Исполнителя": line["name"], "№": str(line["tk"]), "Город": line["city"] or "",
               "Тип": line["format"] or "", "Услуга": line["service"]}
        for day, title in zip(days, titles):
            row[title] = line["days"].get(day)  # 0 — смена с 0 часов, None — смены нет
        row.update({"ИЧ": line["hours"], "ТМ": line["tm"],
                    "Ставка": rate + line["bonus_last"] if rate else NO_RATE,
                    "ФОТ": round(line["fot"] + line["bonus"], 2)})
        row["tm_id"] = line["tm_id"]
        rows.append(row)
    return {
        "days": titles,
        "rows": rows,
        "total": round(sum(row["ФОТ"] for row in rows), 2),
        "no_rate": no_rate_summary((line.service, line.hours) for line in lines if not line.rate),
    }


def weekly_filename(week_start):
    return f"Недельный_отчёт_{week_start:%d.%m.%Y}-{week_start + timedelta(days=6):%d.%m.%Y}.xlsx"


def build_weekly_xlsx(report):
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill

    columns = HEAD + report["days"] + TAIL
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = WEEKLY_SHEET
    sheet.append(columns)
    for cell in sheet[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor=HEADER_FILL)
    for row in report["rows"]:
        sheet.append([row[column] for column in columns])
    sheet.append([TOTAL] + [None] * (len(columns) - 2) + [report["total"]])
    for cell in sheet["M"][1:-1]:  # «ИЧ», как в образце
        cell.number_format = HOURS_FORMAT
    for letter in ("O", "P"):  # «Ставка», «ФОТ»; «НЕТ» — текст
        for cell in sheet[letter][1:]:
            if isinstance(cell.value, (int, float)):
                cell.number_format = MONEY_FORMAT
    sheet.freeze_panes = "A2"
    for letter, width in WIDTHS.items():
        sheet.column_dimensions[letter].width = width
    for index in range(len(report["days"])):
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

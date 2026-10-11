"""Выплатной табель в формате ведомости (П4.4, блок E): «Табель» + «Ведомость».

Для прогона kind=period — второй xlsx рядом с реестром выплат П3, в формате
ведомости коллег («9-2 ЛОф»):

- «Табель» — строка на (сотрудник, ТК, услуга): тарифный регион, формат, часы
  по дням периода, ИЧ, ТМ, ставка, ФОТ (часы × ставка, без надбавки);
- «Ведомость» — строка на сотрудника: ФОТ, Аванс (advanced_amount), Мед (ЛМК),
  Штраф/Премия (корректировки по знаку), Акция (bonus_amount), Итого к выплате
  (total_amount) и реквизиты. У сотрудника на еженедельном авансе в колонках
  реквизитов — «еженедельно», как в ведомости. Недостача, Зп при уволь.,
  Зарплата, Накладные — пустые (зарезервированы).

Итого к выплате = ФОТ + Акция + Премия − Штраф − Мед − Аванс.
"""

from collections import OrderedDict
from datetime import timedelta
from io import BytesIO

from file_storage import storage_save
from models import AdvanceSelection, PayrollRunItem, Shift, Store, User
from payouts_helpers import REFERRAL_SERVICES, REGISTRY_PREFIX, XLSX_CONTENT_TYPE, requisite_fields
from store_helpers import extract_tk_number
from time_helpers import now_utc
from utils import normalize_city, normalize_format, normalize_person_name, normalize_text

TABEL_SHEET = "Табель"
STATEMENT_SHEET = "Ведомость"
TABEL_HEAD = ["ФИО сотрудника Исполнителя", "Номер ТК", "Город", "Тип", "Услуга"]
TABEL_TAIL = ["ИЧ", "ТМ", "Ставка", "ФОТ"]
STATEMENT_COLUMNS = [
    "ФИО сотрудника Исполнителя", "ИЧ", "ТМ", "ФОТ", "Аванс", "Недостача", "Мед", "Зп при уволь.", "Зарплата",
    "Штраф", "Накладные", "Акция", "Премия", "Итого к Выплате", "Номер карты", "Срок действия", "Телефона",
    "Получатель", "Банк получателя", "Комментарии", "Способ выплаты", "Статус", "Исполнил", "Проверка карт",
    "Проверка тел",
]
# Колонки реквизитов, где у сотрудника на еженедельном авансе стоит «еженедельно».
WEEKLY_COLUMNS = ["Номер карты", "Срок действия", "Телефона", "Получатель", "Банк получателя", "Комментарии"]
WEEKLY = "еженедельно"


def _money(value):
    return round(value or 0, 2)


def _period_days(run):
    day, days = run.date_from, []
    while day <= run.date_to:
        days.append(day)
        day += timedelta(days=1)
    return days


def _store_info(session, run):
    """{строка магазина: (номер ТК, регион, формат)}: регион — тарифный регион ТК, иначе
    город смены; формат — из справочника ТК, иначе из смены."""
    stores = {s.tk_number: s for s in session.query(Store).all()}
    info = {}
    shifts = session.query(Shift.store, Shift.city, Shift.format).filter(
        Shift.shift_date >= run.date_from, Shift.shift_date <= run.date_to).distinct()
    for store_str, city, fmt in shifts:
        tk = extract_tk_number(store_str)
        store = stores.get(tk)
        region = (store.rate_region or store.city) if store else None
        previous = info.get(store_str, (tk, None, None))
        info[store_str] = (tk, region or previous[1] or normalize_city(city) or None,
                           (normalize_format(store.format) if store and store.format else None)
                           or previous[2] or normalize_format(fmt) or None)
    return info


def weekly_names(session, run):
    """Сотрудники на еженедельном авансе: отмечены хотя бы на одну неделю периода."""
    rows = session.query(AdvanceSelection.employee_name).filter(
        AdvanceSelection.week_start >= run.date_from - timedelta(days=6),
        AdvanceSelection.week_start <= run.date_to).all()
    return {normalize_person_name(name) for (name,) in rows}


def statement_rows(session, run):
    """(строки «Табеля», строки «Ведомости») — списки dict по колонкам."""
    items = (session.query(PayrollRunItem).filter(PayrollRunItem.run_id == run.id)
             .order_by(PayrollRunItem.id).all())
    users = {u.employee_name_norm: u for u in session.query(User).all()}
    tm_names = {u.id: u.employee_name for u in users.values()}
    stores = _store_info(session, run)
    weekly = weekly_names(session, run)
    days = _period_days(run)

    def tm_of(key):
        user = users.get(key)
        return tm_names.get(user.tm_id, "") if user and user.tm_id else ""

    tabel = OrderedDict()
    people = OrderedDict()
    for item in items:
        if item.shift_date is None and (item.service or "") in REFERRAL_SERVICES:
            continue  # премия «Приведи друга» — в реестре отдельной строкой, не в табеле
        key = normalize_person_name(item.employee_name)
        person = people.setdefault(key, {
            "name": item.employee_name, "hours": 0.0, "fot": 0.0, "advance": 0.0, "lmk": 0.0, "fine": 0.0,
            "premium": 0.0, "bonus": 0.0, "total": 0.0,
        })
        adjustments = (item.other_amount or 0) + (item.auto_adjustments_amount or 0)
        person["hours"] += item.hours or 0
        person["fot"] += item.amount or 0
        person["advance"] += item.advanced_amount or 0
        person["lmk"] += item.lmk_amount or 0
        person["bonus"] += item.bonus_amount or 0
        person["fine" if adjustments < 0 else "premium"] += abs(adjustments)
        person["total"] += item.total_amount or 0
        if item.shift_date is None:
            continue
        tk, region, fmt = stores.get(item.store, (extract_tk_number(item.store), None, None))
        line = tabel.setdefault((key, normalize_text(item.store), normalize_text(item.service)), {
            "name": item.employee_name, "tk": tk if tk is not None else item.store, "region": region or "",
            "format": fmt or "", "service": item.service or "", "days": {}, "hours": 0.0, "rate": 0.0, "fot": 0.0,
        })
        line["days"][item.shift_date] = line["days"].get(item.shift_date, 0) + (item.hours or 0)
        line["hours"] += item.hours or 0
        line["fot"] += item.amount or 0
        if item.rate and not line["rate"]:
            line["rate"] = item.rate

    day_titles = [str(day.day) for day in days]
    tabel_rows = []
    for (key, _store, _service), line in sorted(tabel.items(),
                                                key=lambda pair: (pair[0][0], str(pair[1]["tk"]), pair[0][2])):
        row = {"ФИО сотрудника Исполнителя": line["name"], "Номер ТК": line["tk"], "Город": line["region"],
               "Тип": line["format"], "Услуга": line["service"]}
        for day, title in zip(days, day_titles):
            row[title] = line["days"].get(day) or None
        row.update({"ИЧ": line["hours"], "ТМ": tm_of(key), "Ставка": line["rate"] or None,
                    "ФОТ": _money(line["fot"])})
        tabel_rows.append(row)

    statement = []
    for key, person in sorted(people.items()):
        row = dict.fromkeys(STATEMENT_COLUMNS)
        row.update({
            "ФИО сотрудника Исполнителя": person["name"], "ИЧ": person["hours"], "ТМ": tm_of(key),
            "ФОТ": _money(person["fot"]), "Аванс": _money(person["advance"]) or None,
            "Мед": _money(person["lmk"]) or None, "Штраф": _money(person["fine"]) or None,
            "Акция": _money(person["bonus"]) or None, "Премия": _money(person["premium"]) or None,
            "Итого к Выплате": _money(person["total"]),
        })
        if key in weekly:
            row.update(dict.fromkeys(WEEKLY_COLUMNS, WEEKLY))
        else:
            req = requisite_fields(session, users.get(key), person["name"])
            row.update({"Номер карты": req["card"], "Срок действия": req["expiry"], "Телефона": req["phone"],
                        "Получатель": req["recipient"], "Банк получателя": req["bank"],
                        "Комментарии": req["comment"]})
            row["Способ выплаты"] = req["label"]
        statement.append(row)
    return day_titles, tabel_rows, statement


def statement_filename(run):
    return f"Ведомость_{run.date_from:%d.%m}-{run.date_to:%d.%m.%Y}.xlsx"


def build_statement_xlsx(day_titles, tabel_rows, statement):
    from openpyxl import Workbook

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = TABEL_SHEET
    columns = TABEL_HEAD + day_titles + TABEL_TAIL
    sheet.append(columns)
    for row in tabel_rows:
        sheet.append([row.get(column) for column in columns])
    sheet.append(["Итог"] + [None] * (len(columns) - 5)
                 + [sum(r["ИЧ"] for r in tabel_rows), None, None, _money(sum(r["ФОТ"] for r in tabel_rows))])

    sheet = workbook.create_sheet(STATEMENT_SHEET)
    sheet.append(STATEMENT_COLUMNS)
    for row in statement:
        sheet.append([row[column] for column in STATEMENT_COLUMNS])
    totals = ["Итог"] + [None] * (len(STATEMENT_COLUMNS) - 1)
    for column in ("ИЧ", "ФОТ", "Аванс", "Мед", "Штраф", "Акция", "Премия", "Итого к Выплате"):
        totals[STATEMENT_COLUMNS.index(column)] = _money(sum(row[column] or 0 for row in statement))
    sheet.append(totals)

    buffer = BytesIO()
    workbook.save(buffer)
    return buffer.getvalue()


def save_statement(session, run):
    """Сформировать ведомость, сохранить копию в хранилище; вернуть (ключ, имя файла)."""
    filename = statement_filename(run)
    content = build_statement_xlsx(*statement_rows(session, run))
    stamp = now_utc().strftime("%Y%m%d-%H%M%S")
    key = f"{REGISTRY_PREFIX}/{run.kind}/{run.id}/{stamp}_{filename}"
    storage_save(key, content, content_type=XLSX_CONTENT_TYPE)
    return key, filename

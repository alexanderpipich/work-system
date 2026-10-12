"""Табель по диапазону дат: строка на (сотрудник, ТК, услуга), часы по дням, ставка, ФОТ.

Один построитель для листа «Табель» выплатной ведомости (П4.4, по строкам прогона)
и еженедельного отчёта (П4.6, по сменам) — чтобы они никогда не разошлись.

Смены без плана в табель не входят (коллеги их не включают); услуги «не из timebook»
отбрасывает payable_shifts. Ставка и надбавка — price_shift, тот же расчёт, что
в build_run_items.
"""

from collections import OrderedDict
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Optional

from models import Shift, User
from payroll_run_helpers import bonus_per_hour, load_hourly_bonuses, payable_shifts, price_shift
from service_catalog import build_service_resolver
from shift_helpers import is_no_plan_shift
from store_helpers import extract_tk_number
from utils import load_rates, normalize_city, normalize_person_name, normalize_text


@dataclass
class TimesheetLine:
    """Одна оплачиваемая смена (или строка прогона) для табеля."""
    employee: str
    store: str
    service: str
    day: date
    hours: float
    rate: float = 0.0           # ЧТС, 0 — ставка не найдена
    amount: float = 0.0         # часы × ЧТС
    bonus: float = 0.0          # надбавка за смену («Акция»)
    bonus_rate: float = 0.0     # надбавка за час на дату смены (0 — без ставки)
    city: Optional[str] = None  # город смены (после normalize_city)
    format: Optional[str] = None


def date_range(date_from, date_to):
    days, day = [], date_from
    while day <= date_to:
        days.append(day)
        day += timedelta(days=1)
    return days


def shift_lines(session, date_from, date_to):
    """Смены диапазона, рассчитанные как в build_run_items (регион ТК, алиасы форматов,
    active_to ставок, надбавки)."""
    rates = load_rates(session)
    resolve = build_service_resolver(session)
    bonuses = load_hourly_bonuses(session)
    shifts = session.query(Shift).filter(Shift.shift_date >= date_from, Shift.shift_date <= date_to).order_by(
        Shift.employee.asc(), Shift.store.asc(), Shift.service.asc(), Shift.shift_date.asc(), Shift.id.asc()).all()
    lines = []
    for shift in payable_shifts(shifts, resolve):
        if is_no_plan_shift(shift):
            continue
        _rate, rate_value, amount, bonus = price_shift(shift, rates, resolve, bonuses)
        lines.append(TimesheetLine(
            employee=shift.employee, store=shift.store, service=shift.service, day=shift.shift_date,
            hours=shift.hours or 0, rate=rate_value, amount=amount, bonus=bonus,
            bonus_rate=bonus_per_hour(bonuses, shift.shift_date) if rate_value else 0,
            city=normalize_city(shift.city) or None, format=normalize_text(shift.format) or None,
        ))
    return lines


def item_lines(items, is_no_plan_item):
    """Строки прогона (PayrollRunItem) со сменой, кроме смен без плана."""
    return [TimesheetLine(employee=item.employee_name, store=item.store, service=item.service,
                          day=item.shift_date, hours=item.hours or 0, rate=item.rate or 0,
                          amount=item.amount or 0, bonus=item.bonus_amount or 0,
                          bonus_rate=(item.bonus_amount or 0) / item.hours if item.hours else 0)
            for item in items if item.shift_date is not None and not is_no_plan_item(item)]


def tm_lookup(session):
    """ФИО → имя ТМ сотрудника ("" — нет ТМ или сотрудник не найден)."""
    users = {u.employee_name_norm: u for u in session.query(User).all()}
    tm_names = {u.id: u.employee_name for u in users.values()}

    def tm_of(name):
        user = users.get(normalize_person_name(name))
        return tm_names.get(user.tm_id, "") if user and user.tm_id else ""
    return tm_of


def build_timesheet_rows(session, date_from, date_to, lines=None):
    """Строки табеля за [date_from, date_to]: lines — готовые TimesheetLine (строки прогона),
    по умолчанию — смены диапазона (shift_lines).

    Строка: name, store, tk, city, format, service, days {date: часы}, hours, rate_first/rate_last
    (ЧТС первой/последней смены со ставкой), bonus_last (надбавка за час последней такой смены),
    fot (Σ часы × ЧТС), bonus (Σ надбавок), no_rate (есть смена без ЧТС), tm. Порядок — ФИО без учёта регистра, затем ТК, затем услуга.
    """
    if lines is None:
        lines = shift_lines(session, date_from, date_to)
    tm_of = tm_lookup(session)
    rows = OrderedDict()
    for line in sorted(lines, key=lambda ln: ln.day):
        if not (date_from <= line.day <= date_to):
            continue
        key = (normalize_person_name(line.employee), normalize_text(line.store), normalize_text(line.service))
        tk = extract_tk_number(line.store)
        row = rows.setdefault(key, {
            "name": line.employee, "store": line.store, "tk": tk if tk is not None else line.store,
            "city": None, "format": None, "service": line.service or "", "days": {}, "hours": 0.0,
            "rate_first": 0.0, "rate_last": 0.0, "bonus_last": 0.0, "fot": 0.0, "bonus": 0.0, "no_rate": False,
        })
        row["city"] = row["city"] or line.city
        row["format"] = row["format"] or line.format
        row["days"][line.day] = row["days"].get(line.day, 0) + line.hours
        row["hours"] += line.hours
        row["fot"] += line.amount
        row["bonus"] += line.bonus
        if line.rate:
            row["rate_first"] = row["rate_first"] or line.rate
            row["rate_last"] = line.rate
            row["bonus_last"] = line.bonus_rate
        else:
            row["no_rate"] = True
    result = sorted(rows.items(), key=lambda pair: (pair[0][0], str(pair[1]["tk"]), pair[0][2]))
    for _key, row in result:
        row["tm"] = tm_of(row["name"])
    return [row for _key, row in result]

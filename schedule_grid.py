"""Сетка «по дням» для табелей — общий механизм для графиков выходов и
выплатных табелей. Раскладывает смены по дням периода; deньги (основная сумма,
ЧТС) навешиваются поверх той же сетки в build_payroll_rows.

Вынесено из routers/schedules.py, чтобы payroll переиспользовал ровно тот же
день-бакетинг, а не дублировал его (см. ТЗ 002)."""

from datetime import timedelta

from shift_helpers import is_no_plan_shift
from utils import pick_rate


def days_between(start_date, end_date):
    days = []
    current_day = start_date

    while current_day <= end_date:
        days.append(current_day)
        current_day += timedelta(days=1)

    return days


def build_schedule_rows(shifts, days, include_city: bool = False):
    table = {}

    for shift in shifts:
        is_no_plan = is_no_plan_shift(shift)
        if include_city:
            key = (shift.employee, shift.city, shift.store, shift.service, is_no_plan)
        else:
            key = (shift.employee, shift.store, shift.service, is_no_plan)

        if key not in table:
            row = {
                "employee": shift.employee,
                "store": shift.store,
                "service": shift.service,
                "is_no_plan": is_no_plan,
                "request_type": shift.request_type,
                "days": {day: 0 for day in days},
                "no_plan_days": {day: False for day in days},
                "total": 0,
            }
            if include_city:
                row["city"] = shift.city
            table[key] = row

        table[key]["days"][shift.shift_date] += shift.hours
        if is_no_plan:
            table[key]["no_plan_days"][shift.shift_date] = True
        table[key]["total"] += shift.hours

    rows = list(table.values())
    if include_city:
        rows.sort(key=lambda x: (x["city"], x["store"], x["employee"], x["service"]))
    else:
        rows.sort(key=lambda x: (x["store"], x["employee"], x["service"]))

    return rows


def build_payroll_rows(shifts, days, rates, include_city: bool = False, resolve=None):
    """Табель «по дням» с деньгами.

    Строка = (ФИО, [город,] магазин, услуга, is_no_plan) — как в графиках, поэтому
    у каждой услуги СВОЯ ЧТС. Основная сумма считается 1:1 как в admin_payroll
    (сумма `часы×ЧТС` по сменам, 0 для смен без плана); меняется только
    гранулярность строк — ИТОГИ часов и денег обязаны совпасть с прежними.

    Корректировки/ЛМК тут НЕ считаются — их навешивают apply_*_to_rows поверх,
    как и раньше (ключ (сотрудник, магазин) / сотрудник — не по услуге)."""
    rows = build_schedule_rows(shifts, days, include_city=include_city)

    money = {}
    for shift in shifts:
        is_no_plan = is_no_plan_shift(shift)
        rate = pick_rate(rates, shift, resolve=resolve)
        rate_value = rate.hourly_rate if rate else 0
        amount = 0 if is_no_plan else (shift.hours * rate_value if rate else 0)

        if include_city:
            key = (shift.employee, shift.city, shift.store, shift.service, is_no_plan)
        else:
            key = (shift.employee, shift.store, shift.service, is_no_plan)

        bucket = money.setdefault(
            key,
            {"amount": 0, "rate_value": 0, "missing_rates": 0, "no_plan_hours": 0},
        )
        bucket["amount"] += amount
        if rate:
            bucket["rate_value"] = rate_value
        if is_no_plan:
            bucket["no_plan_hours"] += shift.hours
        if not rate and not is_no_plan:
            bucket["missing_rates"] += 1

    for row in rows:
        if include_city:
            key = (row["employee"], row["city"], row["store"], row["service"], row["is_no_plan"])
        else:
            key = (row["employee"], row["store"], row["service"], row["is_no_plan"])
        bucket = money.get(key, {})

        # Поля, которых ждут apply_auto/manual/lmk_to_rows и шаблон табеля.
        row["employee_name"] = row["employee"]
        row["hours"] = row["total"]
        row["amount"] = bucket.get("amount", 0)
        row["rate_value"] = bucket.get("rate_value", 0)
        row["missing_rates"] = bucket.get("missing_rates", 0)
        row["no_plan_hours"] = bucket.get("no_plan_hours", 0)
        row["has_no_plan"] = row["is_no_plan"]
        row["manual_key"] = f"{row['employee']}|||{row['store']}"

    return rows

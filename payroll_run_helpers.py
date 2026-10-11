from calendar import monthrange
from datetime import timedelta

from sqlalchemy import text

from database import engine
from lmk_charges import get_lmk_charge_for_employee
from manual_adjustments import get_manual_adjustments_map
from models import HourlyBonus, PayrollRun, PayrollRunItem
from payroll_adjustments import get_payroll_auto_adjustments
from shift_helpers import is_no_plan_shift
from utils import normalize_text, pick_rate


def ensure_payroll_run_closing_columns():
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                ALTER TABLE payroll_runs
                ADD COLUMN IF NOT EXISTS closed_at TIMESTAMP
                """
            )
        )
        connection.execute(
            text(
                """
                ALTER TABLE payroll_runs
                ADD COLUMN IF NOT EXISTS closed_by INTEGER
                """
            )
        )
        connection.execute(
            text(
                """
                ALTER TABLE payroll_adjustments
                ADD COLUMN IF NOT EXISTS target_run_id INTEGER
                """
            )
        )
        connection.execute(
            text(
                """
                ALTER TABLE manual_payroll_adjustments
                ADD COLUMN IF NOT EXISTS applied_run_id INTEGER
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS medical_book_payments (
                    id SERIAL PRIMARY KEY,
                    charge_id INTEGER,
                    run_id INTEGER,
                    employee_name VARCHAR,
                    amount DOUBLE PRECISION DEFAULT 0,
                    created_at TIMESTAMP DEFAULT NOW()
                )
                """
            )
        )
        # П3: вид прогона, связь строки с оплатившим её прогоном, сумма аванса.
        connection.execute(text(
            "ALTER TABLE payroll_runs ADD COLUMN IF NOT EXISTS kind VARCHAR NOT NULL DEFAULT 'period'"
        ))
        connection.execute(text(
            "ALTER TABLE payroll_run_items ADD COLUMN IF NOT EXISTS paid_by_run_id INTEGER"
        ))
        connection.execute(text(
            "ALTER TABLE payroll_run_items ADD COLUMN IF NOT EXISTS advanced_amount DOUBLE PRECISION DEFAULT 0"
        ))
        # П4.4: надбавка к часу.
        connection.execute(text(
            "ALTER TABLE payroll_run_items ADD COLUMN IF NOT EXISTS bonus_amount DOUBLE PRECISION DEFAULT 0"
        ))


# ── Расчёт строк прогона (П3) ────────────────────────────────────────────────
# Общий код фиксации табеля (fix_payroll, economist_fix_payroll), аванса и
# табеля за период. Цикл перенесён из fix_payroll как есть: порядок строк,
# применение ручной корректировки и автокорректировок один раз на ключ
# (сотрудник, магазин), ЛМК один раз на сотрудника, нулевая ставка у смен без
# плана — без изменений. Снимок: tests/test_payroll_snapshot.py.

PAID_RUN_STATUSES = ("fixed", "sent", "closed")  # draft ничего не резервирует
ALL_STORES = "*"  # ручная корректировка «на сотрудника» (вычеты аванса)

RUN_KIND_ADVANCE = "advance"
RUN_KIND_PERIOD = "period"


def is_advance_week(date_from, date_to):
    """Аванс — ровно неделя Пн–Вс."""
    return date_from.weekday() == 0 and date_to == date_from + timedelta(days=6)


def is_half_month(date_from, date_to):
    """Табель — 1–15 или 16–последний день одного месяца."""
    if (date_from.year, date_from.month) != (date_to.year, date_to.month):
        return False
    last_day = monthrange(date_from.year, date_from.month)[1]
    return (date_from.day, date_to.day) in {(1, 15), (16, last_day)}


def half_month_bounds(day):
    """Полумесяц, в который попадает дата: (1, 15) или (16, конец)."""
    if day.day <= 15:
        return day.replace(day=1), day.replace(day=15)
    return day.replace(day=16), day.replace(day=monthrange(day.year, day.month)[1])


def shift_pay_key(employee, store, service, shift_date):
    """Ключ «одна смена — одна оплата»: (сотрудник, магазин, услуга, дата)."""
    return (normalize_text(employee), normalize_text(store), normalize_text(service), shift_date)


def paid_shift_twins(session, shifts, exclude_run_id=None):
    """{ключ смены: PayrollRunItem} — смены, уже оплаченные зафиксированным прогоном."""
    dates = [shift.shift_date for shift in shifts if shift.shift_date]
    if not dates:
        return {}
    query = session.query(PayrollRunItem).join(
        PayrollRun, PayrollRun.id == PayrollRunItem.run_id
    ).filter(
        PayrollRun.status.in_(PAID_RUN_STATUSES),
        PayrollRunItem.shift_date >= min(dates),
        PayrollRunItem.shift_date <= max(dates),
    )
    if exclude_run_id is not None:
        query = query.filter(PayrollRunItem.run_id != exclude_run_id)
    twins = {}
    for item in query.order_by(PayrollRunItem.id.asc()).all():
        twins.setdefault(shift_pay_key(item.employee_name, item.store, item.service, item.shift_date), item)
    return twins


def load_hourly_bonuses(session):
    """Включённые надбавки к часу (П4.4) — один запрос на расчёт."""
    return session.query(HourlyBonus).filter(HourlyBonus.is_active == True).all()  # noqa: E712


def bonus_per_hour(bonuses, day):
    """Σ надбавок, действующих на дату смены."""
    return sum(b.amount_per_hour or 0 for b in bonuses
               if b.active_from <= day and (b.active_to is None or day <= b.active_to))


def payable_shifts(shifts, resolve):
    """Смены, которые оплачиваются из timebook: без услуг с Service.excluded_from_payroll
    (комплектация — по другому отчёту). Резолвер — из build_service_resolver."""
    excluded = getattr(resolve, "excluded", None)
    if excluded is None:
        return list(shifts)
    return [shift for shift in shifts if not excluded(shift)]


def build_run_items(
    session,
    run,
    shifts,
    *,
    date_from,
    date_to,
    rates,
    resolve,
    apply_lmk,
    apply_auto,
    manual="store",
    link_paid=False,
):
    """Создать PayrollRunItem по сменам (в порядке `shifts`) и добавить в сессию.

    manual: "store" — ручная корректировка по (сотрудник, магазин) за точный
    период, как в табеле; "employee" — по (сотрудник, "*"), на первую строку
    сотрудника (вычеты аванса); None — без ручных.
    link_paid: смена, уже оплаченная другим зафиксированным прогоном, получает
    paid_by_run_id и advanced_amount (вычитается из total_amount).
    """
    shifts = payable_shifts(shifts, resolve)
    twins = paid_shift_twins(session, shifts, exclude_run_id=run.id) if link_paid else {}
    manual_map = get_manual_adjustments_map(session, date_from, date_to) if manual else {}

    used_manual_keys = set()
    used_auto_keys = set()
    used_lmk_employees = set()
    items = []
    bonuses = load_hourly_bonuses(session)

    for shift in shifts:
        rate = pick_rate(rates, shift, resolve=resolve)
        rate_value = rate.hourly_rate if rate else 0
        amount = 0 if is_no_plan_shift(shift) else shift.hours * rate_value
        # Надбавка — только к оплачиваемой смене со ставкой (без плана и без ЧТС — 0).
        bonus_amount = 0
        if amount and bonuses and shift.shift_date:
            bonus_amount = shift.hours * bonus_per_hour(bonuses, shift.shift_date)
        manual_key = (normalize_text(shift.employee), normalize_text(shift.store))
        other_amount = 0
        auto_amount = 0
        lmk_amount = 0

        if manual == "employee":
            manual_key_used = (normalize_text(shift.employee), ALL_STORES)
        else:
            manual_key_used = manual_key
        if manual and manual_key_used not in used_manual_keys:
            manual_adjustment = manual_map.get(manual_key_used)
            other_amount = manual_adjustment.amount if manual_adjustment else 0
            used_manual_keys.add(manual_key_used)

        if apply_auto and manual_key not in used_auto_keys:
            auto_amount = get_payroll_auto_adjustments(
                session,
                shift.employee,
                shift.store,
            )["approved_amount"]
            used_auto_keys.add(manual_key)

        if apply_lmk:
            employee_lmk_key = normalize_text(shift.employee)
            if employee_lmk_key not in used_lmk_employees:
                _lmk_charge, lmk_amount = get_lmk_charge_for_employee(
                    session,
                    shift.employee,
                    date_from,
                    date_to,
                )
                if lmk_amount:
                    used_lmk_employees.add(employee_lmk_key)

        twin = twins.get(shift_pay_key(shift.employee, shift.store, shift.service, shift.shift_date))
        # Надбавка двойника выплачена вместе с ним — иначе табель покажет ложный остаток.
        advanced_amount = ((twin.amount or 0) + (twin.bonus_amount or 0)
                           + (twin.manual_adjustments_amount or 0)) if twin else 0

        item = PayrollRunItem(
            run_id=run.id,
            employee_name=shift.employee,
            store=shift.store,
            service=shift.service,
            shift_date=shift.shift_date,
            hours=shift.hours,
            rate=0 if is_no_plan_shift(shift) else rate_value,
            amount=amount,
            other_amount=other_amount,
            auto_adjustments_amount=auto_amount,
            manual_adjustments_amount=other_amount,
            lmk_amount=lmk_amount,
            paid_by_run_id=twin.run_id if twin else None,
            advanced_amount=advanced_amount,
            bonus_amount=bonus_amount,
            total_amount=amount + bonus_amount + other_amount + auto_amount - lmk_amount - advanced_amount,
            comment=None if (rate or is_no_plan_shift(shift)) else "Не найдена ЧТС",
        )
        session.add(item)
        items.append(item)

    return items

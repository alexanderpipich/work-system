from datetime import date

from models import MedicalBookCharge
from utils import normalize_text


def month_start(value: date) -> date:
    return date(value.year, value.month, 1)


def iter_month_starts(date_from: date, date_to: date):
    current = month_start(date_from)
    end = month_start(date_to)

    while current <= end:
        yield current
        if current.month == 12:
            current = date(current.year + 1, 1, 1)
        else:
            current = date(current.year, current.month + 1, 1)


def months_between(start_month: date, current_month: date) -> int:
    return (
        (current_month.year - start_month.year) * 12
        + current_month.month
        - start_month.month
    )


def lmk_amount_for_charge(charge, date_from: date, date_to: date) -> float:
    if charge.status != "active" or (charge.remaining_amount or 0) <= 0:
        return 0

    amount = 0
    for current_month in iter_month_starts(date_from, date_to):
        offset = months_between(charge.start_month, current_month)
        if offset < 0 or offset >= (charge.months_count or 0):
            continue
        amount += charge.monthly_amount or 0

    return min(amount, charge.remaining_amount or 0)


def get_lmk_charge_for_employee(session, employee_name, date_from: date, date_to: date):
    charges = session.query(MedicalBookCharge).filter(
        MedicalBookCharge.employee_name == normalize_text(employee_name),
        MedicalBookCharge.status == "active",
        MedicalBookCharge.remaining_amount > 0,
    ).order_by(
        MedicalBookCharge.start_month.asc(),
        MedicalBookCharge.id.asc(),
    ).all()

    for charge in charges:
        amount = lmk_amount_for_charge(charge, date_from, date_to)
        if amount:
            return charge, amount

    return None, 0


def apply_lmk_charges_to_rows(session, rows, date_from: date, date_to: date):
    used_employees = set()

    for row in rows:
        employee_name = normalize_text(row["employee_name"])
        if employee_name in used_employees:
            charge, amount = None, 0
        else:
            charge, amount = get_lmk_charge_for_employee(
                session,
                employee_name,
                date_from,
                date_to,
            )
            if amount:
                used_employees.add(employee_name)

        row["lmk_charge_id"] = charge.id if charge else None
        row["lmk_amount"] = amount
        row["total_amount"] = (
            (row.get("amount") or 0)
            + (row.get("auto_adjustments") or 0)
            + (row.get("manual_adjustments") or 0)
            - amount
        )


def consume_lmk_charge(session, charge_id, amount):
    if not charge_id or not amount:
        return

    charge = session.query(MedicalBookCharge).filter(
        MedicalBookCharge.id == charge_id,
        MedicalBookCharge.status == "active",
    ).first()

    if not charge:
        return

    charge.remaining_amount = max((charge.remaining_amount or 0) - amount, 0)
    if charge.remaining_amount <= 0:
        charge.status = "completed"

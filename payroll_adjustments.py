from models import PayrollAdjustment, PayrollRun, PayrollRunItem, Shift
from shift_helpers import is_no_plan_shift
from time_helpers import now_utc
from utils import load_rates, pick_rate


def find_or_create_adjustment(
    session,
    employee_name,
    store,
    service,
    shift_date,
    old_hours,
    new_hours,
    rate,
    source_run_id,
    comment
):
    diff_hours = round((new_hours or 0) - (old_hours or 0), 4)

    if diff_hours == 0:
        return 0

    diff_amount = round(diff_hours * (rate or 0), 2)

    existing = session.query(PayrollAdjustment).filter(
        PayrollAdjustment.employee_name == employee_name,
        PayrollAdjustment.store == store,
        PayrollAdjustment.service == service,
        PayrollAdjustment.shift_date == shift_date,
        PayrollAdjustment.source_run_id == source_run_id,
        PayrollAdjustment.status.in_(["pending", "approved", "applied"])
    ).first()

    if existing:
        return 0

    adjustment = PayrollAdjustment(
        employee_name=employee_name,
        store=store,
        service=service,
        shift_date=shift_date,
        old_hours=old_hours or 0,
        new_hours=new_hours or 0,
        diff_hours=diff_hours,
        rate=rate or 0,
        diff_amount=diff_amount,
        source_run_id=source_run_id,
        target_run_id=None,
        status="pending",
        comment=comment,
        created_at=now_utc()
    )

    session.add(adjustment)

    return 1


def reconcile_sent_payroll_runs(session):
    created = 0

    rates = load_rates(session)
    sent_runs = session.query(PayrollRun).filter(
        PayrollRun.status == "sent"
    ).all()

    for run in sent_runs:
        items = session.query(PayrollRunItem).filter(
            PayrollRunItem.run_id == run.id
        ).all()

        snapshot_keys = set()

        for item in items:
            if (item.amount or 0) == 0 and (item.rate or 0) == 0:
                continue

            key = (
                item.employee_name,
                item.store,
                item.service,
                item.shift_date
            )

            snapshot_keys.add(key)

            matching_shifts = session.query(Shift).filter(
                Shift.employee == item.employee_name,
                Shift.store == item.store,
                Shift.service == item.service,
                Shift.shift_date == item.shift_date
            ).all()
            current_shift = next(
                (shift for shift in matching_shifts if not is_no_plan_shift(shift)),
                None,
            )

            old_hours = item.hours or 0
            new_hours = current_shift.hours if current_shift else 0
            rate = item.rate or 0

            created += find_or_create_adjustment(
                session=session,
                employee_name=item.employee_name,
                store=item.store,
                service=item.service,
                shift_date=item.shift_date,
                old_hours=old_hours,
                new_hours=new_hours,
                rate=rate,
                source_run_id=run.id,
                comment=f"Изменение часов после отправки табеля #{run.id} в оплату"
            )

        current_shifts = session.query(Shift).filter(
            Shift.shift_date >= run.date_from,
            Shift.shift_date <= run.date_to
        ).all()

        for shift in current_shifts:
            if is_no_plan_shift(shift):
                continue

            key = (
                shift.employee,
                shift.store,
                shift.service,
                shift.shift_date
            )

            if key in snapshot_keys:
                continue

            rate_obj = pick_rate(rates, shift)
            rate_value = rate_obj.hourly_rate if rate_obj else 0

            created += find_or_create_adjustment(
                session=session,
                employee_name=shift.employee,
                store=shift.store,
                service=shift.service,
                shift_date=shift.shift_date,
                old_hours=0,
                new_hours=shift.hours or 0,
                rate=rate_value,
                source_run_id=run.id,
                comment=f"Новая смена появилась после отправки табеля #{run.id} в оплату"
            )

    session.commit()

    return created


def _adjustment_details(adjustments):
    return [
        {
            "id": item.id,
            "status": item.status,
            "service": item.service or "",
            "shift_date": item.shift_date,
            "old_hours": item.old_hours or 0,
            "new_hours": item.new_hours or 0,
            "diff_hours": item.diff_hours or 0,
            "diff_amount": item.diff_amount or 0,
            "comment": item.comment or "",
            "source_run_id": item.source_run_id,
        }
        for item in adjustments
    ]


def get_payroll_auto_adjustments(session, employee_name, store):
    adjustments = session.query(PayrollAdjustment).filter(
        PayrollAdjustment.employee_name == employee_name,
        PayrollAdjustment.store == store,
        PayrollAdjustment.target_run_id == None,
        PayrollAdjustment.status.in_(["approved", "pending"]),
    ).all()

    approved = [item for item in adjustments if item.status == "approved"]
    pending = [item for item in adjustments if item.status == "pending"]

    return {
        "approved_amount": sum(item.diff_amount or 0 for item in approved),
        "pending_amount": sum(item.diff_amount or 0 for item in pending),
        "approved_ids": [item.id for item in approved],
        "pending_ids": [item.id for item in pending],
        "approved_details": _adjustment_details(approved),
        "pending_details": _adjustment_details(pending),
    }


def apply_auto_adjustments_to_rows(session, rows):
    target_indexes = {}

    for index, row in enumerate(rows):
        key = (row["employee_name"], row["store"])
        current_index = target_indexes.get(key)
        if current_index is None:
            target_indexes[key] = index
        elif rows[current_index].get("has_no_plan") and not row.get("has_no_plan"):
            target_indexes[key] = index

    for row in rows:
        row["auto_adjustments"] = 0
        row["auto_approved_amount"] = 0
        row["auto_pending_amount"] = 0
        row["auto_approved_ids"] = []
        row["auto_pending_ids"] = []
        row["auto_approved_details"] = []
        row["auto_pending_details"] = []

    for key, index in target_indexes.items():
        employee_name, store = key
        auto_adjustments = get_payroll_auto_adjustments(
            session,
            employee_name,
            store,
        )
        row = rows[index]
        row["auto_adjustments"] = auto_adjustments["approved_amount"]
        row["auto_approved_amount"] = auto_adjustments["approved_amount"]
        row["auto_pending_amount"] = auto_adjustments["pending_amount"]
        row["auto_approved_ids"] = auto_adjustments["approved_ids"]
        row["auto_pending_ids"] = auto_adjustments["pending_ids"]
        row["auto_approved_details"] = auto_adjustments["approved_details"]
        row["auto_pending_details"] = auto_adjustments["pending_details"]


def mark_auto_adjustments_target_run(session, employee_name, store, run_id):
    session.query(PayrollAdjustment).filter(
        PayrollAdjustment.employee_name == employee_name,
        PayrollAdjustment.store == store,
        PayrollAdjustment.target_run_id == None,
        PayrollAdjustment.status == "approved",
    ).update(
        {PayrollAdjustment.target_run_id: run_id},
        synchronize_session=False,
    )

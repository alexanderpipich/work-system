from audit_helpers import create_audit_log
from models import (
    ManualPayrollAdjustment,
    MedicalBookCharge,
    MedicalBookPayment,
    PayrollAdjustment,
    PayrollRunItem,
)
from time_helpers import now_utc
from utils import normalize_text


def _run_item_pairs(items):
    return {
        (normalize_text(item.employee_name), normalize_text(item.store))
        for item in items
        if normalize_text(item.employee_name) and normalize_text(item.store)
    }


def _apply_auto_adjustments(session, run, items, request=None, user=None):
    applied = 0

    for employee_name, store in _run_item_pairs(items):
        adjustments = session.query(PayrollAdjustment).filter(
            PayrollAdjustment.employee_name == employee_name,
            PayrollAdjustment.store == store,
            PayrollAdjustment.status == "approved",
            PayrollAdjustment.target_run_id == None,
        ).all()

        for adjustment in adjustments:
            old_value = {"status": adjustment.status, "target_run_id": adjustment.target_run_id}
            adjustment.status = "applied"
            adjustment.target_run_id = run.id
            create_audit_log(
                session,
                request,
                user,
                "adjustment_applied",
                "payroll_adjustment",
                adjustment.id,
                f"{adjustment.employee_name} / {adjustment.store}",
                old_value=old_value,
                new_value={"status": "applied", "target_run_id": run.id},
            )
            applied += 1

    return applied


def _apply_manual_adjustments(session, run, items, request=None, user=None):
    applied = 0

    for employee_name, store in _run_item_pairs(items):
        adjustments = session.query(ManualPayrollAdjustment).filter(
            ManualPayrollAdjustment.employee_name == employee_name,
            ManualPayrollAdjustment.store == store,
            ManualPayrollAdjustment.status == "active",
            ManualPayrollAdjustment.applied_run_id == None,
            ManualPayrollAdjustment.date_from <= run.date_to,
            ManualPayrollAdjustment.date_to >= run.date_from,
        ).all()

        for adjustment in adjustments:
            old_value = {"status": adjustment.status, "applied_run_id": adjustment.applied_run_id}
            adjustment.status = "applied"
            adjustment.applied_run_id = run.id
            create_audit_log(
                session,
                request,
                user,
                "manual_adjustment_applied",
                "manual_payroll_adjustment",
                adjustment.id,
                f"{adjustment.employee_name} / {adjustment.store}",
                old_value=old_value,
                new_value={"status": "applied", "applied_run_id": run.id},
            )
            applied += 1

    return applied


def _apply_lmk_payments(session, run, items, request=None, user=None):
    payments_created = 0
    total_amount = 0

    for item in items:
        amount = item.lmk_amount or 0
        if amount <= 0:
            continue

        charge = session.query(MedicalBookCharge).filter(
            MedicalBookCharge.employee_name == normalize_text(item.employee_name),
            MedicalBookCharge.status == "active",
            MedicalBookCharge.remaining_amount > 0,
        ).order_by(
            MedicalBookCharge.start_month.asc(),
            MedicalBookCharge.id.asc(),
        ).first()

        if not charge:
            continue

        existing_payment = session.query(MedicalBookPayment).filter(
            MedicalBookPayment.charge_id == charge.id,
            MedicalBookPayment.run_id == run.id,
        ).first()

        if existing_payment:
            continue

        payment_amount = min(amount, charge.remaining_amount or 0)
        if payment_amount <= 0:
            continue

        session.add(
            MedicalBookPayment(
                charge_id=charge.id,
                run_id=run.id,
                employee_name=normalize_text(item.employee_name),
                amount=payment_amount,
                created_at=now_utc(),
            )
        )

        old_remaining = charge.remaining_amount or 0
        charge.remaining_amount = max((charge.remaining_amount or 0) - payment_amount, 0)
        if charge.remaining_amount <= 0:
            charge.remaining_amount = 0
            charge.status = "completed"
            create_audit_log(
                session,
                request,
                user,
                "lmk_completed",
                "medical_book_charge",
                charge.id,
                charge.employee_name,
                old_value={"remaining_amount": old_remaining, "status": "active"},
                new_value={"remaining_amount": 0, "status": "completed"},
            )

        create_audit_log(
            session,
            request,
            user,
            "lmk_payment_applied",
            "medical_book_charge",
            charge.id,
            charge.employee_name,
            old_value={"remaining_amount": old_remaining},
            new_value={"remaining_amount": charge.remaining_amount, "payment_amount": payment_amount, "run_id": run.id},
        )

        payments_created += 1
        total_amount += payment_amount

    return payments_created, total_amount


def close_payroll_run(session, run, admin, request=None):
    result = {
        "closed": False,
        "auto_adjustments_applied": 0,
        "manual_adjustments_applied": 0,
        "lmk_payments_created": 0,
        "lmk_total_amount": 0,
    }

    if not run or run.status != "sent":
        return result

    items = session.query(PayrollRunItem).filter(
        PayrollRunItem.run_id == run.id
    ).all()

    result["auto_adjustments_applied"] = _apply_auto_adjustments(session, run, items, request, admin)
    result["manual_adjustments_applied"] = _apply_manual_adjustments(session, run, items, request, admin)

    lmk_payments_created, lmk_total_amount = _apply_lmk_payments(session, run, items, request, admin)
    result["lmk_payments_created"] = lmk_payments_created
    result["lmk_total_amount"] = lmk_total_amount

    run.status = "closed"
    run.closed_at = now_utc()
    run.closed_by = admin.id
    result["closed"] = True

    session.commit()
    return result

from audit_helpers import create_audit_log
from models import ManualPayrollAdjustment, Shift
from time_helpers import now_utc
from utils import normalize_text


def parse_manual_key(key: str) -> tuple[str, str]:
    parts = str(key or "").split("|||", 1)
    if len(parts) != 2:
        return "", ""
    return normalize_text(parts[0]), normalize_text(parts[1])


def parse_money(value) -> float:
    try:
        return float(str(value or "0").replace(",", "."))
    except ValueError:
        return 0


def build_manual_payload(keys, amounts, comments=None) -> dict[tuple[str, str], dict]:
    payload = {}
    keys = keys or []
    amounts = amounts or []
    comments = comments or []

    for index, key in enumerate(keys):
        employee_name, store = parse_manual_key(key)
        if not employee_name or not store:
            continue

        amount = parse_money(amounts[index] if index < len(amounts) else 0)
        comment = normalize_text(comments[index] if index < len(comments) else "")

        payload[(employee_name, store)] = {
            "amount": amount,
            "comment": comment or None,
        }

    return payload


def active_manual_adjustment(session, employee_name, store, date_from, date_to):
    return session.query(ManualPayrollAdjustment).filter(
        ManualPayrollAdjustment.employee_name == normalize_text(employee_name),
        ManualPayrollAdjustment.store == normalize_text(store),
        ManualPayrollAdjustment.date_from == date_from,
        ManualPayrollAdjustment.date_to == date_to,
        ManualPayrollAdjustment.status == "active",
        ManualPayrollAdjustment.applied_run_id == None,
    ).first()


def get_manual_adjustments_map(session, date_from, date_to):
    adjustments = session.query(ManualPayrollAdjustment).filter(
        ManualPayrollAdjustment.date_from == date_from,
        ManualPayrollAdjustment.date_to == date_to,
        ManualPayrollAdjustment.status == "active",
        ManualPayrollAdjustment.applied_run_id == None,
    ).all()

    return {
        (normalize_text(item.employee_name), normalize_text(item.store)): item
        for item in adjustments
    }


def apply_manual_adjustments_to_rows(session, rows, date_from, date_to):
    manual_map = get_manual_adjustments_map(session, date_from, date_to)
    target_indexes = {}

    for index, row in enumerate(rows):
        key = (normalize_text(row["employee_name"]), normalize_text(row["store"]))
        current_index = target_indexes.get(key)
        if current_index is None:
            target_indexes[key] = index
        elif row.get("has_no_plan") and not rows[current_index].get("has_no_plan"):
            target_indexes[key] = index

    for row in rows:
        row["manual_adjustments"] = 0
        row["manual_comment"] = ""
        row["manual_editable"] = False
        row["manual_key"] = ""
        row["total_amount"] = (
            (row.get("amount") or 0)
            + (row.get("auto_adjustments") or 0)
            - (row.get("lmk_amount") or 0)
        )

    for key, index in target_indexes.items():
        row = rows[index]
        adjustment = manual_map.get(key)
        manual_amount = adjustment.amount if adjustment else 0

        row["manual_adjustments"] = manual_amount
        row["manual_comment"] = adjustment.comment if adjustment else ""
        row["manual_editable"] = True
        row["manual_key"] = f"{row['employee_name']}|||{row['store']}"
        row["total_amount"] = (
            (row.get("amount") or 0)
            + (row.get("auto_adjustments") or 0)
            + manual_amount
            - (row.get("lmk_amount") or 0)
        )


def can_save_manual_adjustment(session, employee_name, store, date_from, date_to, allowed_cities=None):
    if allowed_cities is None:
        return True

    return session.query(Shift.id).filter(
        Shift.employee == employee_name,
        Shift.store == store,
        Shift.shift_date >= date_from,
        Shift.shift_date <= date_to,
        Shift.city.in_(allowed_cities),
    ).first() is not None


def save_manual_adjustments(
    session,
    *,
    user_id,
    date_from,
    date_to,
    manual_keys,
    manual_amounts,
    manual_comments=None,
    allowed_cities=None,
    request=None,
    user=None,
):
    payload = build_manual_payload(manual_keys, manual_amounts, manual_comments)
    saved = 0
    deleted = 0
    skipped = 0

    for (employee_name, store), data in payload.items():
        if not can_save_manual_adjustment(
            session,
            employee_name,
            store,
            date_from,
            date_to,
            allowed_cities=allowed_cities,
        ):
            skipped += 1
            continue

        adjustment = active_manual_adjustment(
            session,
            employee_name,
            store,
            date_from,
            date_to,
        )

        amount = data["amount"]
        if amount == 0:
            if adjustment:
                old_value = {
                    "amount": adjustment.amount,
                    "comment": adjustment.comment,
                    "status": adjustment.status,
                }
                adjustment.status = "deleted"
                adjustment.deleted_by = user_id
                adjustment.deleted_at = now_utc()
                create_audit_log(
                    session,
                    request,
                    user,
                    "manual_adjustment_deleted",
                    "manual_payroll_adjustment",
                    adjustment.id,
                    f"{employee_name} / {store}",
                    old_value=old_value,
                    new_value={"status": "deleted"},
                )
                deleted += 1
            continue

        if adjustment:
            old_value = {
                "amount": adjustment.amount,
                "comment": adjustment.comment,
                "status": adjustment.status,
            }
            adjustment.amount = amount
            adjustment.comment = data["comment"]
            create_audit_log(
                session,
                request,
                user,
                "manual_adjustment_updated",
                "manual_payroll_adjustment",
                adjustment.id,
                f"{employee_name} / {store}",
                old_value=old_value,
                new_value={
                    "amount": amount,
                    "comment": data["comment"],
                    "status": adjustment.status,
                },
            )
        else:
            adjustment = ManualPayrollAdjustment(
                employee_name=employee_name,
                store=store,
                date_from=date_from,
                date_to=date_to,
                amount=amount,
                comment=data["comment"],
                status="active",
                created_by=user_id,
                created_at=now_utc(),
            )
            session.add(adjustment)
            session.flush()
            create_audit_log(
                session,
                request,
                user,
                "manual_adjustment_created",
                "manual_payroll_adjustment",
                adjustment.id,
                f"{employee_name} / {store}",
                new_value={
                    "employee_name": employee_name,
                    "store": store,
                    "date_from": date_from,
                    "date_to": date_to,
                    "amount": amount,
                    "comment": data["comment"],
                    "status": "active",
                },
            )

        saved += 1

    session.commit()
    return {"saved": saved, "deleted": deleted, "skipped": skipped}


def mark_manual_adjustments_applied(session, date_from, date_to, run_id, keys):
    for employee_name, store in keys:
        adjustment = active_manual_adjustment(
            session,
            employee_name,
            store,
            date_from,
            date_to,
        )
        if adjustment:
            adjustment.status = "applied"
            adjustment.applied_run_id = run_id

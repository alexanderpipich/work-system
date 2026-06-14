from audit_helpers import create_audit_log
from models import UserAccessScope
from time_helpers import now_utc
from utils import normalize_text


def parse_scope_values(raw_value):
    if isinstance(raw_value, (list, tuple, set)):
        values = raw_value
    else:
        values = str(raw_value or "").split(",")
    return sorted({normalize_text(value) for value in values if normalize_text(value)})


def active_scope_values(session, user_id, scope_type):
    return [
        row.scope_value
        for row in session.query(UserAccessScope).filter(
            UserAccessScope.user_id == user_id,
            UserAccessScope.scope_type == scope_type,
            UserAccessScope.is_active == True,
        ).order_by(UserAccessScope.scope_value).all()
    ]


def sync_access_scopes(session, request, actor, user, scope_type, raw_values):
    desired = set(parse_scope_values(raw_values))
    rows = session.query(UserAccessScope).filter(
        UserAccessScope.user_id == user.id,
        UserAccessScope.scope_type == scope_type,
    ).all()
    existing = {normalize_text(row.scope_value): row for row in rows}
    before = sorted(value for value, row in existing.items() if row.is_active)

    for value, row in existing.items():
        row.is_active = value in desired

    for value in desired - set(existing):
        session.add(UserAccessScope(
            user_id=user.id,
            scope_type=scope_type,
            scope_value=value,
            created_by=actor.id,
            created_at=now_utc(),
            is_active=True,
        ))

    after = sorted(desired)
    if before != after:
        create_audit_log(
            session, request, actor, "user_access_scope_changed", "user",
            user.id, user.employee_name,
            old_value={scope_type: before}, new_value={scope_type: after},
        )
    return after

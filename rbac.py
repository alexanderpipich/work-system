from fastapi import Depends, Request

from audit_helpers import create_audit_log
from dependencies import RedirectException, current_user, get_db
from models import UserAccessScope
from utils import normalize_text


ROLE_SUPERADMIN = "superadmin"
ROLE_HR_LEAD = "hr_lead"
ROLE_HR_MANAGER = "hr_manager"
ROLE_ECONOMIST = "economist"
ROLE_BRIGADIER = "brigadier"
ROLE_EMPLOYEE = "employee"

ROLES = {
    ROLE_SUPERADMIN,
    ROLE_HR_LEAD,
    ROLE_HR_MANAGER,
    ROLE_ECONOMIST,
    ROLE_BRIGADIER,
    ROLE_EMPLOYEE,
}

# Permissions exclusive to superadmin (not listed per-role since superadmin bypasses the check):
#   email.manage

PERMISSIONS = {
    ROLE_HR_LEAD: {
        "employees.view", "employees.manage", "documents.view", "documents.manage",
        "requisites.view", "requisites.manage", "reports.view",
        "payroll.view", "payroll.export", "payroll.summary_view",
        "rates.view", "lmk.view", "password.reset_limited",
        "audit.hr_view", "hr_team.manage", "schedules.view",
    },
    ROLE_HR_MANAGER: {
        "employees.view", "employees.manage", "documents.view", "documents.manage",
        "requisites.view", "requisites.manage", "reports.view", "payroll.view", "payroll.export",
        "rates.view", "lmk.view", "password.reset_limited", "schedules.view",
    },
    ROLE_ECONOMIST: {
        "employees.view", "employees.manage", "documents.view", "documents.verify",
        "schedules.view", "payroll.view", "payroll.manage", "payroll.send",
        "adjustments.manage", "rates.view", "rates.manage", "requisites.view", "lmk.manage", "reports.view",
        "legal_entities.manage", "economist.dashboard",
    },
    ROLE_BRIGADIER: {"schedules.view"},
    ROLE_EMPLOYEE: {"profile.own", "documents.own", "schedules.own"},
}


def canonical_role(user) -> str:
    role = normalize_text(getattr(user, "role", "")).lower()
    if getattr(user, "is_admin", False) or role in {"admin", ROLE_SUPERADMIN}:
        return ROLE_SUPERADMIN
    return role if role in ROLES else ROLE_EMPLOYEE


def is_superadmin(user) -> bool:
    return canonical_role(user) == ROLE_SUPERADMIN


def has_permission(user, permission: str) -> bool:
    role = canonical_role(user)
    return role == ROLE_SUPERADMIN or permission in PERMISSIONS.get(role, set())


def record_denied_action(session, request, user, permission: str):
    create_audit_log(
        session,
        request,
        user,
        "permission_denied",
        "permission",
        entity_name=permission,
        comment=getattr(getattr(request, "url", None), "path", None),
    )
    session.commit()


def require_permission(permission: str, audit_denied: bool = False):
    def dependency(
        request: Request,
        session=Depends(get_db),
        user=Depends(current_user),
    ):
        if not has_permission(user, permission):
            if audit_denied:
                record_denied_action(session, request, user, permission)
            raise RedirectException("/")
        return user
    return dependency


def get_scope_values(session, user, scope_type: str):
    if canonical_role(user) in {ROLE_SUPERADMIN, ROLE_HR_LEAD}:
        return None
    rows = session.query(UserAccessScope.scope_value).filter(
        UserAccessScope.user_id == user.id,
        UserAccessScope.scope_type == scope_type,
        UserAccessScope.is_active == True,
    ).all()
    return {normalize_text(row[0]) for row in rows if normalize_text(row[0])}


def can_access_city(session, user, city) -> bool:
    allowed = get_scope_values(session, user, "city")
    return allowed is None or normalize_text(city) in allowed


def can_access_store(session, user, store) -> bool:
    allowed = get_scope_values(session, user, "store")
    return allowed is None or normalize_text(store) in allowed


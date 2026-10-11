import os

from fastapi import Depends, Request

from audit_helpers import create_audit_log
from dependencies import RedirectException, current_user, get_db
from models import UserAccessScope
from utils import normalize_text


ROLE_SUPERADMIN = "superadmin"
ROLE_HR_LEAD = "hr_lead"
ROLE_TM = "tm"  # территориальный менеджер; до П1 — hr_manager
ROLE_HR_CLERK = "hr_clerk"  # кадровик
ROLE_ECONOMIST = "economist"
ROLE_BRIGADIER = "brigadier"
ROLE_HEADHUNTER = "headhunter"
ROLE_EMPLOYEE = "employee"

ROLES = {
    ROLE_SUPERADMIN,
    ROLE_HR_LEAD,
    ROLE_TM,
    ROLE_HR_CLERK,
    ROLE_ECONOMIST,
    ROLE_BRIGADIER,
    ROLE_HEADHUNTER,
    ROLE_EMPLOYEE,
}

# Старые значения users.role → каноническая роль (как admin → superadmin).
# hr_manager остаётся в базах до scripts/migrate_role_tm.py.
LEGACY_ROLE_ALIASES = {"hr_manager": ROLE_TM}

# Значения users.role, означающие ТМ (для выборок по колонке, где canonical_role не применить).
TM_ROLE_VALUES = (ROLE_TM, "hr_manager")

# Роли, работающие в кабинете /hr. Доступ к разделам внутри него всё равно
# решают права (payroll.view и т.п.): кадровик в выплаты не попадает.
HR_CABINET_ROLES = frozenset({ROLE_HR_LEAD, ROLE_TM, ROLE_HR_CLERK})

# Подписи ролей в интерфейсе. Ключи — канонические роли.
ROLE_LABELS = {
    ROLE_SUPERADMIN: "Суперадмин",
    ROLE_HR_LEAD: "Руководитель ТМ",
    ROLE_TM: "ТМ (территориальный менеджер)",
    ROLE_HR_CLERK: "Кадровик",
    ROLE_ECONOMIST: "Экономист",
    ROLE_BRIGADIER: "Бригадир",
    ROLE_HEADHUNTER: "Рекрутер",
    ROLE_EMPLOYEE: "Сотрудник",
}

# Permissions exclusive to superadmin (not listed per-role since superadmin bypasses the check):
#   email.manage
#   upload.auto — настройка автозагрузки смен из timebook (П2, вкладка на /admin/upload)

PERMISSIONS = {
    ROLE_HR_LEAD: {
        "employees.view", "employees.manage", "documents.view", "documents.manage",
        "requisites.view", "requisites.manage", "reports.view",
        "payroll.view", "payroll.export", "payroll.summary_view",
        "rates.view", "lmk.view", "password.reset_limited",
        "audit.hr_view", "hr_team.manage", "schedules.view",
        "stores.directory.view", "stores.contacts.view", "contracts.view", "users.view",
        "payouts.advances.select_any", "payouts.advances.fix", "payouts.export",
        "regions.manage", "contracts.manage",
    },
    ROLE_TM: {
        "employees.view", "employees.manage", "documents.view", "documents.manage",
        "requisites.view", "requisites.manage", "reports.view", "payroll.view", "payroll.export",
        "rates.view", "lmk.view", "password.reset_limited", "schedules.view",
        "stores.directory.view", "stores.contacts.view", "users.view",
        "payouts.advances.select_own", "contracts.view",
    },
    # Кадровик: документы, гражданства, типы документов, мониторинг сотрудников,
    # справочники. Без выплат, ставок, реквизитов и рассылок.
    ROLE_HR_CLERK: {
        "employees.view", "documents.view", "documents.manage",
        "citizenship.manage", "services.view", "contracts.view", "users.view", "regions.manage",
        "contracts.manage",
        "stores.directory.view", "stores.contacts.view",
    },
    ROLE_ECONOMIST: {
        "employees.view", "employees.manage", "documents.view", "documents.verify",
        "schedules.view", "payroll.view", "payroll.manage", "payroll.send",
        "adjustments.manage", "rates.view", "rates.manage", "requisites.view", "lmk.manage", "reports.view",
        "legal_entities.manage", "economist.dashboard",
        "stores.directory.view", "stores.contacts.view", "services.view", "users.view",
        "payouts.advances.select_any", "payouts.advances.fix", "payouts.export",
    },
    ROLE_BRIGADIER: {"schedules.view", "stores.directory.view", "stores.contacts.view"},
    # Минимальный набор под кабинет-заглушку: доступ к своему дашборду + справочник магазинов.
    # Права под реальные функции (мессенджер/вакансии) добавятся, когда появятся функции.
    ROLE_HEADHUNTER: {"headhunter.dashboard", "stores.directory.view", "stores.contacts.view"},
    # Рядовой сотрудник видит справочник магазинов, но НЕ контакты (stores.contacts.view).
    ROLE_EMPLOYEE: {"profile.own", "documents.own", "schedules.own", "stores.directory.view"},
}


def canonical_role(user) -> str:
    role = normalize_text(getattr(user, "role", "")).lower()
    if getattr(user, "is_admin", False) or role in {"admin", ROLE_SUPERADMIN}:
        return ROLE_SUPERADMIN
    role = LEGACY_ROLE_ALIASES.get(role, role)
    return role if role in ROLES else ROLE_EMPLOYEE


# Порядок ролей в выпадающих списках форм пользователей: (код, подпись).
ROLE_CHOICES = [(role, ROLE_LABELS[role]) for role in (
    ROLE_EMPLOYEE, ROLE_BRIGADIER, ROLE_ECONOMIST, ROLE_TM, ROLE_HR_CLERK,
    ROLE_HR_LEAD, ROLE_HEADHUNTER, ROLE_SUPERADMIN,
)]


def role_label(role) -> str:
    """Подпись роли для интерфейса; принимает и старые значения (hr_manager)."""
    role = normalize_text(role).lower()
    if role == "admin":
        role = ROLE_SUPERADMIN
    role = LEGACY_ROLE_ALIASES.get(role, role)
    return ROLE_LABELS.get(role, role or ROLE_LABELS[ROLE_EMPLOYEE])


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


def scopes_enabled() -> bool:
    """Скоупы городов/магазинов. П1: выключены — все видят всё. Инфраструктура
    (UserAccessScope, access.py, scripts/migrate_scopes.py) сохранена: SCOPES_ENABLED=true
    возвращает прежнюю логику."""
    return os.getenv("SCOPES_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}


def get_scope_values(session, user, scope_type: str):
    if not scopes_enabled():
        return None
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


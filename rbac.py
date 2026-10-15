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

# Линейный персонал: у них в карточке /admin/users есть должность, закреплённый ТМ, дата
# рождения и пол (бригадир — из линейного состава). Офисным ролям эти поля не показываются,
# а при сохранении не трогаются — старые значения из импорта остаются в базе.
LINE_STAFF_ROLES = (ROLE_EMPLOYEE, ROLE_BRIGADIER)

# Подписи ролей в интерфейсе. Ключи — канонические роли.
ROLE_LABELS = {
    ROLE_SUPERADMIN: "Суперадмин",
    ROLE_HR_LEAD: "Руководитель",  # П5: была «HR-руководитель» (П4.8)
    ROLE_TM: "ТМ (территориальный менеджер)",
    ROLE_HR_CLERK: "Кадровик",
    ROLE_ECONOMIST: "Экономист",
    ROLE_BRIGADIER: "Бригадир",
    ROLE_HEADHUNTER: "Рекрутер",
    ROLE_EMPLOYEE: "Сотрудник",
}

# Permissions exclusive to superadmin (not listed per-role since superadmin bypasses the check):
#   shifts.upload — загрузка timebook (POST /admin/upload); страницу открывает upload.view
#   upload.auto — настройка автозагрузки смен из timebook (П2, вкладка на /admin/upload)
#   admin.settings, system.* — настройки и служебные инструменты
#   tour.manage — настройки демо-тура (/admin/tour-settings, П5)
#   schedules.admin_view, payroll.delete,
#   rates.hard_delete, legal_entities.hard_delete, documents.hard_delete (карточка документа)
#   payroll.close, payroll.any_period (табель не за полмесяца) — суперадмин и HR-руководитель
# Роли superadmin и hr_lead создаёт, назначает, удаляет и сбрасывает им пароль только
# суперадмин — can_manage_role (П4.8).

PERMISSIONS = {
    ROLE_TM: {
        "employees.view", "employees.manage", "documents.view", "documents.manage",
        "requisites.view", "requisites.manage", "reports.view", "payroll.view", "payroll.export",
        "rates.view", "lmk.view", "password.reset_limited", "schedules.view",
        "stores.directory.view", "stores.contacts.view", "users.view",
        "payouts.advances.select_own", "contracts.view", "planning.manage",
        "weekly.view", "weekly.edit_own",
    },
    # Кадровик: документы, гражданства, типы документов, мониторинг сотрудников,
    # справочники. Без выплат, ставок, реквизитов и рассылок.
    # users.edit_personal (П5.2) — личные поля карточки сотрудника (роль employee) на /admin/users:
    # дата рождения, пол, гражданство, должность, ИНН, «студент» (routers/users.PERSONAL_FIELDS).
    ROLE_HR_CLERK: {
        "employees.view", "documents.view", "documents.manage", "users.edit_personal",
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
        "weekly.view", "weekly.manage",
    },
    ROLE_BRIGADIER: {"schedules.view", "stores.directory.view", "stores.contacts.view"},
    # Минимальный набор под кабинет-заглушку: доступ к своему дашборду + справочник магазинов.
    # Права под реальные функции (мессенджер/вакансии) добавятся, когда появятся функции.
    ROLE_HEADHUNTER: {"headhunter.dashboard", "stores.directory.view", "stores.contacts.view"},
    # Рядовой сотрудник видит справочник магазинов, но НЕ контакты (stores.contacts.view).
    ROLE_EMPLOYEE: {"profile.own", "documents.own", "schedules.own", "stores.directory.view"},
}

# П4.8: HR-руководитель — фактически руководитель компании: всё, что есть у ТМ, кадровика
# и экономиста, плюс управление пользователями (кроме ролей superadmin/hr_lead) и финансы.
# Технические права суперадмина (список выше) сюда не входят.
HR_LEAD_OWN_PERMISSIONS = {
    "hr_team.manage", "audit.hr_view", "users.view", "payroll.summary_view",
    "users.manage", "users.hard_delete", "rates.manage", "payroll.manage", "payroll.send",
    "adjustments.manage", "lmk.manage", "legal_entities.manage", "email.manage",
    "weekly.manage", "upload.view",
    # Владелец 13.10.2026: на дашборде HR-руководителя открыты Audit Log и Классификатор магазинов.
    "audit.view", "stores.view", "stores.manage",
    # Владелец 13.10.2026: закрытие периода и табель за произвольный период; удаления — суперадмину.
    "payroll.close", "payroll.any_period",
}
# Права «свой участок» ТМ: у HR-руководителя вместо них *_any / *.manage, иначе экран
# недельного отчёта и авансов считал бы его рядовым ТМ со своими сотрудниками.
HR_LEAD_EXCLUDED = {"weekly.edit_own", "payouts.advances.select_own"}
PERMISSIONS[ROLE_HR_LEAD] = (
    PERMISSIONS[ROLE_TM] | PERMISSIONS[ROLE_HR_CLERK] | PERMISSIONS[ROLE_ECONOMIST] | HR_LEAD_OWN_PERMISSIONS
) - HR_LEAD_EXCLUDED

# Роли, которыми управляет только суперадмин (П4.8).
PROTECTED_ROLES = frozenset({ROLE_SUPERADMIN, ROLE_HR_LEAD})


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


def role_value(role) -> str:
    """Каноническая роль по значению колонки/формы (admin → superadmin, hr_manager → tm)."""
    role = normalize_text(role).lower()
    if role == "admin":
        role = ROLE_SUPERADMIN
    return LEGACY_ROLE_ALIASES.get(role, role)


def role_label(role) -> str:
    """Подпись роли для интерфейса; принимает и старые значения (hr_manager)."""
    role = role_value(role)
    return ROLE_LABELS.get(role, role or ROLE_LABELS[ROLE_EMPLOYEE])


def is_superadmin(user) -> bool:
    return canonical_role(user) == ROLE_SUPERADMIN


def can_manage_role(actor, target_role) -> bool:
    """Может ли actor создать/назначить/удалить пользователя с ролью target_role (или
    сбросить ему пароль): роли superadmin и hr_lead — только суперадмину (П4.8)."""
    return is_superadmin(actor) or role_value(target_role) not in PROTECTED_ROLES


def can_manage_user(actor, target) -> bool:
    """can_manage_role по существующему пользователю (учитывает is_admin)."""
    return is_superadmin(actor) or canonical_role(target) not in PROTECTED_ROLES


def role_choices_for(actor):
    """ROLE_CHOICES без ролей, которые actor назначать не может."""
    return [(role, label) for role, label in ROLE_CHOICES if can_manage_role(actor, role)]


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


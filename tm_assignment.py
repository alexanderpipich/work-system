"""Закрепление сотрудника за ТМ (User.tm_id) — один helper для карточки /admin/users
и еженедельного отчёта (П4.6), плюс заведение сотрудника из выгрузки без кабинета."""

from audit_helpers import create_audit_log
from models import User
from rbac import ROLE_EMPLOYEE, TM_ROLE_VALUES
from utils import find_user_by_name, normalize_text


def tm_users(session):
    """Пользователи, которых можно закрепить ТМ за сотрудником (П1-Б)."""
    users = session.query(User).filter(User.role.in_(TM_ROLE_VALUES)).all()
    return sorted(users, key=lambda u: normalize_text(u.employee_name).lower())


def set_employee_tm(session, request, actor, employee, tm_id, comment=None):
    """Закрепить сотрудника за ТМ (None/0 — открепить). ТМ — только пользователь с ролью ТМ
    и не сам сотрудник; иначе — снять. Аудит user.tm.assign при изменении. Возвращает прежний tm_id."""
    valid = {tm.id for tm in tm_users(session)}
    new_tm = tm_id if tm_id in valid and tm_id != employee.id else None
    old_tm = employee.tm_id
    employee.tm_id = new_tm
    if old_tm != new_tm:
        create_audit_log(session, request, actor, "user.tm.assign", "user", employee.id, employee.employee_name,
                         old_value={"tm_id": old_tm}, new_value={"tm_id": new_tm}, comment=comment)
    return old_tm


def ensure_employee_user(session, request, actor, employee_name, comment=None):
    """Сотрудник из выгрузки: найти User по ФИО или завести без кабинета (как
    import_employees_cards: role=employee, телефон и пароль пустые). (User, создан ли)."""
    user = find_user_by_name(session, employee_name)
    if user is not None:
        return user, False
    user = User(employee_name=normalize_text(employee_name), role=ROLE_EMPLOYEE, is_admin=False)
    session.add(user)
    session.flush()
    create_audit_log(session, request, actor, "user_created", "user", user.id, user.employee_name,
                     new_value={"role": user.role}, comment=comment)
    return user, True

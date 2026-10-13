from collections import defaultdict
from datetime import timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from access import accessible_employee_names
from access_scope_helpers import active_scope_values, sync_access_scopes
from audit_helpers import create_audit_log
from dependencies import get_db
from models import Shift, User
from rbac import ROLE_HR_LEAD, ROLE_TM, TM_ROLE_VALUES, canonical_role, require_permission, role_label, scopes_enabled
from time_helpers import business_today
from utils import get_password_hash, normalize_person_name

TEAM_STORE_DAYS = 28  # «магазинов за 4 недели»


router = APIRouter()
templates = Jinja2Templates(directory="templates")
templates.env.globals["role_label"] = role_label
require_hr_team_management = require_permission("hr_team.manage", audit_denied=True)
require_limited_password_reset = require_permission("password.reset_limited", audit_denied=True)


def team_counters(session, managers, today):
    """{id ТМ: (сотрудников по tm_id, магазинов по сменам его сотрудников за TEAM_STORE_DAYS дней)}."""
    ids = {manager.id for manager in managers}
    tm_of = {u.employee_name_norm: u.tm_id for u in session.query(User).filter(User.tm_id.in_(ids or [-1]))}
    employees, stores = defaultdict(int), defaultdict(set)
    for tm_id in tm_of.values():
        employees[tm_id] += 1
    rows = session.query(Shift.employee, Shift.store).filter(
        Shift.shift_date >= today - timedelta(days=TEAM_STORE_DAYS), Shift.store != None).distinct()  # noqa: E711
    for employee, store in rows:
        tm_id = tm_of.get(normalize_person_name(employee))
        if tm_id:
            stores[tm_id].add(store)
    return {manager.id: (employees[manager.id], len(stores[manager.id])) for manager in managers}


def _team_redirect(message, open_id=None):
    """Назад на /hr/team с тем же раскрытым блоком ТМ (П4.8)."""
    params = {"message": message, **({"open": open_id} if open_id else {})}
    return RedirectResponse("/hr/team?" + urlencode(params), status_code=302)


@router.get("/hr/team", response_class=HTMLResponse)
def hr_team(request: Request, message: str = "", open: str = "", session: Session = Depends(get_db),
            user=Depends(require_hr_team_management)):
    """П4.8: компактные блоки ТМ; область доступа раскрывается стрелкой под блоком."""
    managers = session.query(User).filter(User.role.in_(TM_ROLE_VALUES)).order_by(User.employee_name).all()
    available_cities = [
        row[0]
        for row in session.query(Shift.city).filter(Shift.city != None).distinct().order_by(Shift.city).all()
        if row[0]
    ]
    stores_by_city = defaultdict(list)
    for city, store in session.query(Shift.city, Shift.store).filter(
            Shift.city.in_(available_cities or ["__none__"]), Shift.store != None).distinct().order_by(Shift.store):  # noqa: E711
        stores_by_city[city].append(store)
    try:
        open_id = int(open)
    except ValueError:
        open_id = None
    return templates.TemplateResponse(request, "hr_team.html", {
        "user": user,
        "managers": managers,
        "available_cities": available_cities,
        "stores_by_city": stores_by_city,
        "counters": team_counters(session, managers, business_today()),
        "open_id": open_id,
        "scopes_enabled": scopes_enabled(),
        "team_store_days": TEAM_STORE_DAYS,
        "store_scopes": {manager.id: active_scope_values(session, manager.id, "store") for manager in managers},
        "city_scopes": {manager.id: active_scope_values(session, manager.id, "city") for manager in managers},
        "message": message or None,
    })


@router.post("/hr/team/scopes")
def update_hr_manager_scopes(
    request: Request,
    user_id: int = Form(...),
    scope_cities: list[str] = Form(default=[]),
    scope_stores: list[str] = Form(default=[]),
    session: Session = Depends(get_db),
    user=Depends(require_hr_team_management),
):
    manager = session.query(User).filter(User.id == user_id, User.role.in_(TM_ROLE_VALUES)).first()
    if not manager:
        return _team_redirect("ТМ не найден")
    cities = sync_access_scopes(session, request, user, manager, "city", scope_cities)
    valid_stores = [row[0] for row in session.query(Shift.store).filter(Shift.city.in_(cities or ["__none__"]), Shift.store.in_(scope_stores or ["__none__"])).distinct().all()]
    sync_access_scopes(session, request, user, manager, "store", valid_stores)
    manager.economist_stores = ", ".join(cities) or None
    session.commit()
    return _team_redirect("Область ТМ обновлена", manager.id)

@router.get("/hr/access", response_class=HTMLResponse)
def hr_access(request: Request, message: str = "", error: str = "", session: Session = Depends(get_db), user=Depends(require_limited_password_reset)):
    role = canonical_role(user)
    if role not in {ROLE_HR_LEAD, ROLE_TM}:
        return RedirectResponse("/", status_code=302)
    allowed_names = None if role == "hr_lead" or not scopes_enabled() else set(accessible_employee_names(session, user))
    query = session.query(User).filter(User.role.in_(["employee", "brigadier"]))
    if allowed_names is not None:
        query = query.filter(User.employee_name.in_(allowed_names or ["__none__"]))
    users = query.order_by(User.employee_name).all()
    return templates.TemplateResponse(request, "hr_access.html", {"users": users, "message": message or None, "error": error or None})


@router.post("/hr/access/reset-password")
def hr_reset_password(request: Request, user_id: int = Form(...), new_password: str = Form(...), session: Session = Depends(get_db), user=Depends(require_limited_password_reset)):
    role = canonical_role(user)
    target = session.query(User).filter(User.id == user_id, User.role.in_(["employee", "brigadier"])).first()
    allowed_names = None if role == "hr_lead" or not scopes_enabled() else set(accessible_employee_names(session, user))
    if not target or (allowed_names is not None and target.employee_name not in allowed_names):
        return RedirectResponse("/hr/access?error=Пользователь недоступен", status_code=302)
    password = str(new_password or "").strip()
    if len(password) < 6:
        return RedirectResponse("/hr/access?error=Пароль должен содержать минимум 6 символов", status_code=302)
    if not target.phone:
        return RedirectResponse("/hr/access?error=У сотрудника нет телефона (логина) — пароль не задан", status_code=302)
    target.password_hash = get_password_hash(password)
    target.password_is_temporary = True  # HR задал пароль → сотруднику предложить сменить
    create_audit_log(session, request, user, "user_password_reset", "user", target.id, target.employee_name, comment="limited HR reset")
    session.commit()
    return RedirectResponse("/hr/access?message=Пароль изменён", status_code=302)
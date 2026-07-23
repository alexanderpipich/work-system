from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from access import accessible_employee_names
from access_scope_helpers import active_scope_values, sync_access_scopes
from audit_helpers import create_audit_log
from dependencies import get_db
from models import Shift, User
from rbac import canonical_role, require_permission
from utils import get_password_hash


router = APIRouter()
templates = Jinja2Templates(directory="templates")
require_hr_team_management = require_permission("hr_team.manage", audit_denied=True)
require_limited_password_reset = require_permission("password.reset_limited", audit_denied=True)


@router.get("/hr/team", response_class=HTMLResponse)
def hr_team(request: Request, message: str = "", session: Session = Depends(get_db), user=Depends(require_hr_team_management)):
    managers = session.query(User).filter(User.role == "hr_manager").order_by(User.employee_name).all()
    available_cities = [
        row[0]
        for row in session.query(Shift.city).filter(Shift.city != None).distinct().order_by(Shift.city).all()
        if row[0]
    ]
    return templates.TemplateResponse(request, "hr_team.html", {
        "user": user,
        "managers": managers,
        "available_cities": available_cities,
        "stores_by_city": {city: [row[0] for row in session.query(Shift.store).filter(Shift.city == city, Shift.store != None).distinct().order_by(Shift.store).all()] for city in available_cities},
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
    manager = session.query(User).filter(User.id == user_id, User.role == "hr_manager").first()
    if not manager:
        return RedirectResponse("/hr/team?message=HR-менеджер не найден", status_code=302)
    cities = sync_access_scopes(session, request, user, manager, "city", scope_cities)
    valid_stores = [row[0] for row in session.query(Shift.store).filter(Shift.city.in_(cities or ["__none__"]), Shift.store.in_(scope_stores or ["__none__"])).distinct().all()]
    sync_access_scopes(session, request, user, manager, "store", valid_stores)
    manager.economist_stores = ", ".join(cities) or None
    session.commit()
    return RedirectResponse("/hr/team?message=Область HR-менеджера обновлена", status_code=302)

@router.get("/hr/access", response_class=HTMLResponse)
def hr_access(request: Request, message: str = "", error: str = "", session: Session = Depends(get_db), user=Depends(require_limited_password_reset)):
    role = canonical_role(user)
    if role not in {"hr_lead", "hr_manager"}:
        return RedirectResponse("/", status_code=302)
    allowed_names = None if role == "hr_lead" else set(accessible_employee_names(session, user))
    query = session.query(User).filter(User.role.in_(["employee", "brigadier"]))
    if allowed_names is not None:
        query = query.filter(User.employee_name.in_(allowed_names or ["__none__"]))
    users = query.order_by(User.employee_name).all()
    return templates.TemplateResponse(request, "hr_access.html", {"users": users, "message": message or None, "error": error or None})


@router.post("/hr/access/reset-password")
def hr_reset_password(request: Request, user_id: int = Form(...), new_password: str = Form(...), session: Session = Depends(get_db), user=Depends(require_limited_password_reset)):
    role = canonical_role(user)
    target = session.query(User).filter(User.id == user_id, User.role.in_(["employee", "brigadier"])).first()
    allowed_names = None if role == "hr_lead" else set(accessible_employee_names(session, user))
    if not target or (allowed_names is not None and target.employee_name not in allowed_names):
        return RedirectResponse("/hr/access?error=Пользователь недоступен", status_code=302)
    password = str(new_password or "").strip()
    if len(password) < 6:
        return RedirectResponse("/hr/access?error=Пароль должен содержать минимум 6 символов", status_code=302)
    target.password_hash = get_password_hash(password)
    target.password_is_temporary = True  # HR задал пароль → сотруднику предложить сменить
    create_audit_log(session, request, user, "user_password_reset", "user", target.id, target.employee_name, comment="limited HR reset")
    session.commit()
    return RedirectResponse("/hr/access?message=Пароль изменён", status_code=302)
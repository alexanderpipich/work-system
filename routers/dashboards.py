from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from access import get_economist_cities
from dependencies import get_db, require_admin_user, require_economist_user
from rbac import canonical_role, get_scope_values, require_permission


router = APIRouter()
templates = Jinja2Templates(directory="templates")
require_hr_dashboard = require_permission("employees.view", audit_denied=True)


@router.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request, admin=Depends(require_admin_user)):
    return templates.TemplateResponse(request, "admin_dashboard.html", {"admin": admin})


@router.get("/economist", response_class=HTMLResponse)
def economist_dashboard(request: Request, user=Depends(require_economist_user)):
    return templates.TemplateResponse(
        request, "economist_dashboard.html",
        {"user": user, "allowed_cities": get_economist_cities(user)},
    )


@router.get("/hr", response_class=HTMLResponse)
def hr_dashboard(request: Request, session=Depends(get_db), user=Depends(require_hr_dashboard)):
    role = canonical_role(user)
    if role not in {"hr_lead", "hr_manager"}:
        return templates.TemplateResponse(request, "hr_dashboard.html", {"user": user, "role": role, "allowed_cities": [], "access_error": True}, status_code=403)
    allowed_cities = get_scope_values(session, user, "city")
    return templates.TemplateResponse(
        request, "hr_dashboard.html",
        {"user": user, "role": role, "allowed_cities": sorted(allowed_cities) if allowed_cities is not None else None, "access_error": False},
    )


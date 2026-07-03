from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from access import get_economist_cities
from dependencies import get_db
from rbac import canonical_role, get_scope_values, require_permission


router = APIRouter()
templates = Jinja2Templates(directory="templates")
require_hr_dashboard = require_permission("employees.view", audit_denied=True)
_admin_dashboard = require_permission("admin.dashboard")
_economist_dashboard = require_permission("economist.dashboard")
_headhunter_dashboard = require_permission("headhunter.dashboard")


@router.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request, user=Depends(_admin_dashboard)):
    return templates.TemplateResponse(request, "admin_dashboard.html", {"admin": user})


@router.get("/economist", response_class=HTMLResponse)
def economist_dashboard(request: Request, user=Depends(_economist_dashboard)):
    return templates.TemplateResponse(
        request, "economist_dashboard.html",
        {"user": user, "allowed_cities": get_economist_cities(user)},
    )


@router.get("/headhunter", response_class=HTMLResponse)
def headhunter_dashboard(request: Request, user=Depends(_headhunter_dashboard)):
    return templates.TemplateResponse(request, "headhunter.html", {"user": user})


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


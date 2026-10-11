from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from dependencies import current_user
from navigation import all_cards, build_navigation
from rbac import canonical_role, require_permission, role_label


router = APIRouter()
templates = Jinja2Templates(directory="templates")
require_hr_dashboard = require_permission("employees.view", audit_denied=True)
_economist_dashboard = require_permission("economist.dashboard")
_headhunter_dashboard = require_permission("headhunter.dashboard")


def render_dashboard(request, user):
    """Единый дашборд (П2): все группы и карточки, недоступные — приглушены."""
    role = canonical_role(user)
    return templates.TemplateResponse(
        request,
        "admin_dashboard.html",
        {
            "user": user,
            "role": role,
            "role_label": role_label(role),
            "groups": build_navigation(user),
            "cards_total": sum(1 for _ in all_cards()),
        },
    )


# /admin открыт любому вошедшему: это только меню, права проверяет каждый раздел.
@router.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request, user=Depends(current_user)):
    return render_dashboard(request, user)


# /economist и /hr — прежние «домашние» адреса ролей (на них ведёт вход), теперь тот же дашборд.
@router.get("/economist", response_class=HTMLResponse)
def economist_dashboard(request: Request, user=Depends(_economist_dashboard)):
    return render_dashboard(request, user)


@router.get("/hr", response_class=HTMLResponse)
def hr_dashboard(request: Request, user=Depends(require_hr_dashboard)):
    return render_dashboard(request, user)


@router.get("/headhunter", response_class=HTMLResponse)
def headhunter_dashboard(request: Request, user=Depends(_headhunter_dashboard)):
    return templates.TemplateResponse(request, "headhunter.html", {"user": user})

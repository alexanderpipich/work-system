from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from dependencies import current_user, get_db
from navigation import PAYOUTS_GROUPS, build_menu, build_navigation
from rbac import ROLE_EMPLOYEE, canonical_role, has_permission, require_permission, role_label


router = APIRouter()
templates = Jinja2Templates(directory="templates")
require_hr_dashboard = require_permission("employees.view", audit_denied=True)
_economist_dashboard = require_permission("economist.dashboard")
_headhunter_dashboard = require_permission("headhunter.dashboard")
_payroll_view = require_permission("payroll.view")


def dashboard_notices(session, user):
    """Плашки над разделами (П4.6): запросы на смену ТМ — тем, кто их решает; ТМ — сколько
    сотрудников прошлой недели без ТМ."""
    from time_helpers import business_today
    from weekly_report import employees_without_tm, last_complete_week, pending_tm_requests

    notices = []
    if has_permission(user, "weekly.manage"):
        count = len(pending_tm_requests(session))
        if count:
            notices.append({"text": f"Запросы на смену ТМ: {count}", "url": "/admin/payouts/weekly"})
    if canonical_role(user) == "tm" and has_permission(user, "weekly.edit_own"):
        week = last_complete_week(business_today())
        count = employees_without_tm(session, week)
        if count:
            notices.append({"text": f"Без ТМ в прошлой неделе: {count}",
                            "url": f"/admin/payouts/weekly?week={week.isoformat()}&tm=0&no_tm=1"})
    return notices


def render_dashboard(request, user, session=None):
    """Единый дашборд (П2): все группы и карточки, недоступные — приглушены."""
    role = canonical_role(user)
    groups = build_navigation(user)
    return templates.TemplateResponse(
        request,
        "admin_dashboard.html",
        {
            "user": user,
            "role": role,
            "role_label": role_label(role),
            "groups": groups,
            "cards_total": sum(len(group["cards"]) for group in groups),
            # П4.9: боковое меню из того же реестра; сотруднику не показывается.
            "menu": build_menu(groups) if role != ROLE_EMPLOYEE else [],
            "notices": dashboard_notices(session, user) if session is not None else [],
        },
    )


# /admin открыт любому вошедшему: это только меню, права проверяет каждый раздел.
@router.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request, session: Session = Depends(get_db), user=Depends(current_user)):
    return render_dashboard(request, user, session)


# /economist и /hr — прежние «домашние» адреса ролей (на них ведёт вход), теперь тот же дашборд.
@router.get("/economist", response_class=HTMLResponse)
def economist_dashboard(request: Request, session: Session = Depends(get_db), user=Depends(_economist_dashboard)):
    return render_dashboard(request, user, session)


@router.get("/hr", response_class=HTMLResponse)
def hr_dashboard(request: Request, session: Session = Depends(get_db), user=Depends(require_hr_dashboard)):
    return render_dashboard(request, user, session)


@router.get("/admin/payouts", response_class=HTMLResponse)
def payouts_dashboard(request: Request, user=Depends(_payroll_view)):
    """Поддашборд «Выплаты» (П2): табель, история, еженедельные авансы."""
    return templates.TemplateResponse(request, "nav_section.html", {
        "title": "Выплаты",
        "subtitle": "Выплатной табель, история выплат и еженедельные авансы",
        "groups": build_navigation(user, PAYOUTS_GROUPS),
        "back_url": "/admin",
    })


@router.get("/headhunter", response_class=HTMLResponse)
def headhunter_dashboard(request: Request, user=Depends(_headhunter_dashboard)):
    return templates.TemplateResponse(request, "headhunter.html", {"user": user})

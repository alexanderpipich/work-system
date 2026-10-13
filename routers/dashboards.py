import time
from datetime import timedelta

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
            notices.append({"text": f"Запросы на смену ТМ: {count}", "short": f"Запросы ТМ: {count}",
                            "url": "/admin/payouts/weekly"})
    if canonical_role(user) == "tm" and has_permission(user, "weekly.edit_own"):
        week = last_complete_week(business_today())
        count = employees_without_tm(session, week)
        if count:
            notices.append({"text": f"Без ТМ в прошлой неделе: {count}", "short": f"Без ТМ: {count}",
                            "url": f"/admin/payouts/weekly?week={week.isoformat()}&tm=0&no_tm=1"})
    return notices


# П4.9: сводка недели на рабочем столе. Кэш в памяти процесса: понедельник → (момент расчёта, данные).
SUMMARY_TTL = 600
SUMMARY_CITY_ROWS = 4
SUMMARY_STORE_ROWS = 5
_summary_cache = {}


def summary_visible(user):
    return has_permission(user, "reports.view") or has_permission(user, "weekly.view")


def _week_hours(session, week_start):
    from sqlalchemy import func

    from models import Shift

    total = session.query(func.coalesce(func.sum(Shift.hours), 0)).filter(
        Shift.shift_date >= week_start, Shift.shift_date <= week_start + timedelta(days=6)).scalar()
    return float(total or 0)


def _bars(rows, label_attr="city"):
    peak = max((value for _label, value in rows), default=0)
    return [{"label": label, "value": value, "text": format_hours(value),
             "pct": round(value / peak * 100, 1) if peak else 0}
            for label, value in rows]


def format_hours(value):
    """Часы для виджета: целые — без дроби, иначе одна цифра; разряды — узкий пробел."""
    text = f"{value:,.0f}" if float(value).is_integer() else f"{value:,.1f}"
    return text.replace(",", "\u202f").replace(".", ",")


def format_dynamics(current, previous):
    """«+3,2 % часов» / «−1,4 % часов»; None — если за прошлую неделю часов нет."""
    if not previous:
        return None
    change = (current - previous) / previous * 100
    sign = "+" if change >= 0 else "\u2212"
    return f"{sign}{abs(change):.1f}".replace(".", ",") + "\u00a0% часов"


def compute_dashboard_summary(session, week_start):
    """Сводка последней полной недели: часы по тарифным регионам (4 + «Другие»), топ-5 ТК,
    часы и активные сотрудники недели, динамика к предыдущей. Смены без плана считаются —
    это факт времени, не оплата."""
    from models import Shift
    from routers.analytics import hours_by_city, top_stores
    from service_catalog import build_rate_region_resolver
    from store_helpers import extract_tk_number
    from utils import normalize_person_name

    week_end = week_start + timedelta(days=6)
    regions = hours_by_city(session, week_start, week_end, limit=None,
                            region_of=build_rate_region_resolver(session))
    city_rows = [(row.city, row.hours) for row in regions[:SUMMARY_CITY_ROWS]]
    rest = sum(row.hours for row in regions[SUMMARY_CITY_ROWS:])
    if rest:
        city_rows.append(("Другие", rest))

    by_tk = {}
    for row in top_stores(session, week_start, week_end, limit=None):
        tk = extract_tk_number(row.store)
        label = f"Лента-{tk}" if tk is not None else (row.store or "—")
        by_tk[label] = by_tk.get(label, 0) + float(row.hours or 0)
    store_rows = sorted(by_tk.items(), key=lambda item: (-item[1], item[0]))[:SUMMARY_STORE_ROWS]

    names = session.query(Shift.employee).filter(
        Shift.shift_date >= week_start, Shift.shift_date <= week_end).distinct()
    employees = {normalize_person_name(name) for (name,) in names if normalize_person_name(name)}

    previous_start = week_start - timedelta(days=7)
    hours = _week_hours(session, week_start)
    previous = _week_hours(session, previous_start)
    return {
        "week_start": week_start,
        "week_end": week_end,
        "previous_start": previous_start,
        "previous_end": previous_start + timedelta(days=6),
        "cities": _bars(city_rows),
        "stores": _bars(store_rows),
        "hours": hours,
        "hours_text": format_hours(hours),
        "previous_hours": previous,
        "employees": len(employees),
        "dynamics": format_dynamics(hours, previous),
        "dynamics_up": hours >= previous,
    }


def dashboard_summary(session, user, today=None):
    """Сводка для рабочего стола или None, если пользователю она не положена (нет
    reports.view / weekly.view). Расчёт кэшируется на SUMMARY_TTL секунд по понедельнику."""
    if session is None or not summary_visible(user):
        return None
    from time_helpers import business_today
    from weekly_report import last_complete_week

    week_start = last_complete_week(today or business_today())
    cached = _summary_cache.get(week_start)
    now = time.monotonic()
    if cached and now - cached[0] < SUMMARY_TTL:
        return cached[1]
    data = compute_dashboard_summary(session, week_start)
    _summary_cache.clear()
    _summary_cache[week_start] = (now, data)
    return data


def _card_urls(groups, *keys):
    """Адреса доступных этому пользователю карточек по ключу (ссылки виджетов сводки)."""
    urls = {card["key"]: card["url"] for group in groups for card in group["cards"] if card["available"]}
    return {key: urls.get(key) for key in keys}


def mobile_quick_links(user, groups, notices):
    """Быстрые кнопки мобильной шапки (П4.9) — ТМ, HR-руководителю, экономисту:
    «Еженедельный отчёт» и короткие плашки из dashboard_notices («Без ТМ: N»)."""
    if canonical_role(user) not in {"tm", "hr_lead", "economist"}:
        return []
    links = []
    weekly = _card_urls(groups, "weekly_report")["weekly_report"]
    if weekly:
        links.append({"text": "Еженедельный отчёт", "url": weekly})
    links += [{"text": notice.get("short") or notice["text"], "url": notice["url"]} for notice in notices]
    return links


def render_dashboard(request, user, session=None):
    """Единый дашборд (П2): все группы и карточки, недоступные — приглушены."""
    role = canonical_role(user)
    groups = build_navigation(user)
    notices = dashboard_notices(session, user) if session is not None else []
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
            "notices": notices,
            "summary": dashboard_summary(session, user),
            "summary_links": _card_urls(groups, "analytics", "weekly_report"),
            "quick_links": mobile_quick_links(user, groups, notices),
            # Мобильное меню: «Выплаты» раскрыта тем, у кого есть недельный отчёт.
            "menu_open": "payouts" if has_permission(user, "weekly.view") else None,
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

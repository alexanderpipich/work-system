from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from access import get_economist_cities
from dependencies import get_db
from models import Shift
from rbac import require_permission
from shift_helpers import is_no_plan_shift
from time_helpers import business_today


router = APIRouter()
templates = Jinja2Templates(directory="templates")


def _default_week_range() -> tuple[str, str]:
    today = business_today()
    current_week_monday = today - timedelta(days=today.weekday())
    default_date_to = current_week_monday - timedelta(days=1)
    default_date_from = default_date_to - timedelta(days=6)

    return (
        default_date_from.strftime("%Y-%m-%d"),
        default_date_to.strftime("%Y-%m-%d"),
    )


def _days_between(start_date, end_date):
    days = []
    current_day = start_date

    while current_day <= end_date:
        days.append(current_day)
        current_day += timedelta(days=1)

    return days


def _build_schedule_rows(shifts, days, include_city: bool = False):
    table = {}

    for shift in shifts:
        is_no_plan = is_no_plan_shift(shift)
        if include_city:
            key = (shift.employee, shift.city, shift.store, shift.service, is_no_plan)
        else:
            key = (shift.employee, shift.store, shift.service, is_no_plan)

        if key not in table:
            row = {
                "employee": shift.employee,
                "store": shift.store,
                "service": shift.service,
                "is_no_plan": is_no_plan,
                "request_type": shift.request_type,
                "days": {day: 0 for day in days},
                "no_plan_days": {day: False for day in days},
                "total": 0,
            }
            if include_city:
                row["city"] = shift.city
            table[key] = row

        table[key]["days"][shift.shift_date] += shift.hours
        if is_no_plan:
            table[key]["no_plan_days"][shift.shift_date] = True
        table[key]["total"] += shift.hours

    rows = list(table.values())
    if include_city:
        rows.sort(key=lambda x: (x["city"], x["store"], x["employee"], x["service"]))
    else:
        rows.sort(key=lambda x: (x["store"], x["employee"], x["service"]))

    return rows


@router.get("/economist/schedules", response_class=HTMLResponse)
def economist_schedules(
    request: Request,
    date_from: str = "",
    date_to: str = "",
    stores: list[str] | None = Query(default=None),
    session: Session = Depends(get_db),
    user=Depends(require_permission("schedules.view")),
):
    allowed_cities = get_economist_cities(user)

    if not allowed_cities and not user.is_admin:
        return templates.TemplateResponse(
            request,
            "economist_schedules.html",
            {
                "user": user,
                "allowed_cities": allowed_cities,
                "rows": [],
                "days": [],
                "date_from": date_from,
                "date_to": date_to,
                "stores": [],
                "selected_stores": stores or [],
                "show_table": False,
                "error": "Для экономиста не назначены города",
            },
        )

    if not date_from and not date_to:
        date_from, date_to = _default_week_range()

    store_query = session.query(Shift.store).distinct()

    if not user.is_admin:
        store_query = store_query.filter(Shift.city.in_(allowed_cities))

    all_stores = store_query.order_by(Shift.store.asc()).all()
    store_list = [s[0] for s in all_stores]

    rows = []
    days = []
    show_table = bool(stores)

    if show_table:
        start_date = datetime.strptime(date_from, "%Y-%m-%d").date()
        end_date = datetime.strptime(date_to, "%Y-%m-%d").date()
        days = _days_between(start_date, end_date)

        shifts_query = session.query(Shift).filter(
            Shift.shift_date >= start_date,
            Shift.shift_date <= end_date,
            Shift.store.in_(stores),
        )

        if not user.is_admin:
            shifts_query = shifts_query.filter(Shift.city.in_(allowed_cities))

        shifts = shifts_query.order_by(
            Shift.city.asc(),
            Shift.store.asc(),
            Shift.employee.asc(),
            Shift.service.asc(),
            Shift.shift_date.asc(),
        ).all()

        rows = _build_schedule_rows(shifts, days, include_city=True)

    return templates.TemplateResponse(
        request,
        "economist_schedules.html",
        {
            "user": user,
            "allowed_cities": allowed_cities,
            "rows": rows,
            "days": days,
            "date_from": date_from,
            "date_to": date_to,
            "stores": store_list,
            "selected_stores": stores or [],
            "show_table": show_table,
            "error": None,
        },
    )


@router.get("/admin/schedules", response_class=HTMLResponse)
def admin_schedules(
    request: Request,
    date_from: str = "",
    date_to: str = "",
    stores: list[str] | None = Query(default=None),
    session: Session = Depends(get_db),
    user=Depends(require_permission("schedules.admin_view")),
):
    if not date_from and not date_to:
        date_from, date_to = _default_week_range()

    all_stores = session.query(Shift.store).distinct().order_by(Shift.store.asc()).all()
    store_list = [s[0] for s in all_stores]

    rows = []
    days = []
    show_table = bool(stores)

    if show_table:
        try:
            start_date = datetime.strptime(date_from, "%Y-%m-%d").date()
            end_date = datetime.strptime(date_to, "%Y-%m-%d").date()
        except ValueError:
            return templates.TemplateResponse(
                request,
                "schedules.html",
                {
                    "rows": [],
                    "days": [],
                    "date_from": date_from,
                    "date_to": date_to,
                    "stores": store_list,
                    "selected_stores": stores or [],
                    "show_table": False,
                    "error": "Некорректный формат даты",
                },
            )

        days = _days_between(start_date, end_date)

        shifts = session.query(Shift).filter(
            Shift.shift_date >= start_date,
            Shift.shift_date <= end_date,
            Shift.store.in_(stores),
        ).order_by(
            Shift.store.asc(),
            Shift.employee.asc(),
            Shift.service.asc(),
            Shift.shift_date.asc(),
        ).all()

        rows = _build_schedule_rows(shifts, days)

    return templates.TemplateResponse(
        request,
        "schedules.html",
        {
            "rows": rows,
            "days": days,
            "date_from": date_from,
            "date_to": date_to,
            "stores": store_list,
            "selected_stores": stores or [],
            "show_table": show_table,
            "error": None,
        },
    )

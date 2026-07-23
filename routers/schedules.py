from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from access import get_economist_cities, get_user_cities
from dependencies import get_db
from models import Shift
from rbac import canonical_role, require_permission
from schedule_grid import build_schedule_rows as _build_schedule_rows
from schedule_grid import days_between as _days_between
from store_helpers import extract_tk_number
from time_helpers import business_today


def _sort_stores_by_tk(stores):
    """Числовая сортировка магазинов по номеру ТК (по возрастанию).

    Строковая сортировка ставит «Лента-10» раньше «Лента-2» — неверно. Здесь
    сортируем по извлечённому номеру ТК; магазины без распознанного номера —
    в конец, стабильно по названию.
    """
    return sorted(
        stores,
        key=lambda s: (extract_tk_number(s) is None, extract_tk_number(s) or 0, s or ""),
    )


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

    all_stores = store_query.all()
    store_list = _sort_stores_by_tk([s[0] for s in all_stores])

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


@router.get("/hr/schedules", response_class=HTMLResponse)
def hr_schedules(
    request: Request,
    date_from: str = "",
    date_to: str = "",
    stores: list[str] | None = Query(default=None),
    session: Session = Depends(get_db),
    user=Depends(require_permission("schedules.view")),
):
    if canonical_role(user) not in {"hr_lead", "hr_manager"}:
        from fastapi.responses import RedirectResponse
        return RedirectResponse("/", status_code=302)

    allowed_cities = get_user_cities(session, user)  # None = hr_lead (unrestricted), list = hr_manager

    if allowed_cities is not None and not allowed_cities:
        return templates.TemplateResponse(
            request,
            "economist_schedules.html",
            {
                "user": user,
                "allowed_cities": [],
                "rows": [], "days": [],
                "date_from": date_from, "date_to": date_to,
                "stores": [], "selected_stores": stores or [],
                "show_table": False,
                "form_action": "/hr/schedules",
                "back_url": "/hr", "back_label": "HR кабинет",
                "error": "Для пользователя не назначены города",
            },
        )

    if not date_from and not date_to:
        date_from, date_to = _default_week_range()

    store_query = session.query(Shift.store).distinct()
    if allowed_cities is not None:
        store_query = store_query.filter(Shift.city.in_(allowed_cities))
    store_list = _sort_stores_by_tk([s[0] for s in store_query.all()])

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
        if allowed_cities is not None:
            shifts_query = shifts_query.filter(Shift.city.in_(allowed_cities))

        shifts = shifts_query.order_by(
            Shift.city.asc(), Shift.store.asc(),
            Shift.employee.asc(), Shift.service.asc(),
            Shift.shift_date.asc(),
        ).all()
        rows = _build_schedule_rows(shifts, days, include_city=True)

    return templates.TemplateResponse(
        request,
        "economist_schedules.html",
        {
            "user": user,
            "allowed_cities": allowed_cities if allowed_cities is not None else [],
            "rows": rows, "days": days,
            "date_from": date_from, "date_to": date_to,
            "stores": store_list, "selected_stores": stores or [],
            "show_table": show_table,
            "form_action": "/hr/schedules",
            "back_url": "/hr", "back_label": "HR кабинет",
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

    all_stores = session.query(Shift.store).distinct().all()
    store_list = _sort_stores_by_tk([s[0] for s in all_stores])

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

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from dependencies import current_user, get_db
from document_helpers import employee_document_rows, user_citizenship
from models import Shift
from shift_helpers import is_no_plan_shift
from time_helpers import business_today


router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/cabinet", response_class=HTMLResponse)
def cabinet(
    request: Request,
    date_from: str = "",
    date_to: str = "",
    session: Session = Depends(get_db),
    user=Depends(current_user),
):
    today = business_today()

    if not date_from and not date_to:
        default_date_to = today
        default_date_from = today - timedelta(days=13)

        date_from = default_date_from.strftime("%Y-%m-%d")
        date_to = default_date_to.strftime("%Y-%m-%d")

    query = session.query(Shift).filter(Shift.employee == user.employee_name)

    try:
        if date_from:
            query = query.filter(
                Shift.shift_date >= datetime.strptime(date_from, "%Y-%m-%d").date()
            )
        if date_to:
            query = query.filter(
                Shift.shift_date <= datetime.strptime(date_to, "%Y-%m-%d").date()
            )
    except ValueError:
        return templates.TemplateResponse(
            request,
            "cabinet.html",
            {
                "user": user,
                "shifts": [],
                "total_hours": 0,
                "date_from": date_from,
                "date_to": date_to,
                "documents_attention_count": 0,
                "error": "Некорректный формат даты"
            }
        )

    shifts = query.order_by(Shift.shift_date).all()
    for shift in shifts:
        shift.is_no_plan = is_no_plan_shift(shift)
        shift.is_attention = shift.is_no_plan or (shift.hours or 0) == 0

    total = sum(s.hours for s in shifts)
    document_rows = employee_document_rows(session, user)
    documents_attention_count = len([
        row for row in document_rows
        if row["status"] in {"missing", "rejected", "expired"}
    ])

    return templates.TemplateResponse(
        request,
        "cabinet.html",
        {
            "user": user,
            "shifts": shifts,
            "total_hours": total,
            "date_from": date_from,
            "date_to": date_to,
            "documents_attention_count": documents_attention_count,
            "error": None
        }
    )


@router.get("/brigadier", response_class=HTMLResponse)
def brigadier_cabinet(
    request: Request,
    year: str = "",
    month: str = "",
    session: Session = Depends(get_db),
    user=Depends(current_user),
):
    if user.role != "brigadier":
        return RedirectResponse(url="/cabinet", status_code=302)

    if not user.brigadier_store:
        return templates.TemplateResponse(
            request,
            "brigadier.html",
            {
                "user": user,
                "store": None,
                "year": year,
                "month": month,
                "days": [],
                "rows": [],
                "total_hours": 0,
                "employees_count": 0,
                "error": "Для бригадира не указан магазин"
            }
        )

    today = business_today()

    try:
        selected_year = int(year) if year else today.year
        selected_month = int(month) if month else today.month

        if selected_month < 1 or selected_month > 12:
            raise ValueError
    except ValueError:
        selected_year = today.year
        selected_month = today.month

    if selected_month == 12:
        next_month = datetime(selected_year + 1, 1, 1).date()
    else:
        next_month = datetime(selected_year, selected_month + 1, 1).date()

    month_start = datetime(selected_year, selected_month, 1).date()
    month_end = next_month - timedelta(days=1)

    days = list(range(1, month_end.day + 1))

    shifts = session.query(Shift).filter(
        Shift.store == user.brigadier_store,
        Shift.shift_date >= month_start,
        Shift.shift_date <= month_end
    ).order_by(
        Shift.employee.asc(),
        Shift.service.asc(),
        Shift.shift_date.asc()
    ).all()

    table = {}

    for shift in shifts:
        key = (shift.employee, shift.store, shift.service)

        if key not in table:
            table[key] = {
                "employee": shift.employee,
                "store": shift.store,
                "service": shift.service,
                "days": {day: 0 for day in days},
                "total": 0
            }

        day_number = shift.shift_date.day
        table[key]["days"][day_number] += shift.hours
        table[key]["total"] += shift.hours

    rows = list(table.values())
    rows.sort(key=lambda x: (x["employee"], x["service"]))
    total_hours = sum(row["total"] for row in rows)
    employees_count = len({row["employee"] for row in rows})

    return templates.TemplateResponse(
        request,
        "brigadier.html",
        {
            "user": user,
            "store": user.brigadier_store,
            "year": selected_year,
            "month": selected_month,
            "days": days,
            "rows": rows,
            "total_hours": total_hours,
            "employees_count": employees_count,
            "error": None
        }
    )


@router.get("/employee_docs", response_class=HTMLResponse)
def employee_docs(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(current_user),
):
    citizenship = user_citizenship(session, user) or "Не указано"

    return templates.TemplateResponse(
        request,
        "employee_docs.html",
        {
            "user": user,
            "citizenship": citizenship,
            "document_rows": employee_document_rows(session, user),
            "message": request.query_params.get("message"),
            "error": request.query_params.get("error"),
        }
    )


@router.get("/vacancies", response_class=HTMLResponse)
def vacancies(request: Request, user=Depends(current_user)):
    return employee_placeholder(request, user, "Вакансии")


@router.get("/support", response_class=HTMLResponse)
def support(request: Request, user=Depends(current_user)):
    return employee_placeholder(request, user, "Поддержка и FAQ")


def employee_placeholder(request: Request, user, title: str):
    return templates.TemplateResponse(
        request,
        "employee_placeholder.html",
        {
            "user": user,
            "title": title
        }
    )

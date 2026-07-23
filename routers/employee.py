from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import or_
from sqlalchemy.orm import Session

from audit_helpers import create_audit_log
from dependencies import current_user, get_db
from document_helpers import (
    employee_completeness,
    employee_document_rows,
    latest_employee_document,
    user_citizenship,
)
from models import Requisite, Shift
from shift_helpers import is_no_plan_shift
from time_helpers import business_today
from utils import get_password_hash, normalize_text, verify_password


router = APIRouter()
templates = Jinja2Templates(directory="templates")

_STATUS_STYLES = {
    "ok":            {"border": "#16a34a", "bg": "#f0fdf4", "glyph": "✓", "label": "Проверен, годен"},
    "expiring_soon": {"border": "#f97316", "bg": "#fff7ed", "glyph": "⚠", "label": "Истекает скоро"},
    "pending":       {"border": "#eab308", "bg": "#fefce8", "glyph": "⏳", "label": "Ждёт проверки"},
    "expired":       {"border": "#dc2626", "bg": "#fef2f2", "glyph": "✗", "label": "Просрочен"},
    "missing":       {"border": "#94a3b8", "bg": "#f8fafc", "glyph": "–", "label": "Не загружен"},
}


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
                "completeness": [],
                "all_ok": True,
                "attention_count": 0,
                "status_styles": _STATUS_STYLES,
                "error": "Некорректный формат даты",
            },
        )

    shifts = query.order_by(Shift.shift_date).all()
    for shift in shifts:
        shift.is_no_plan = is_no_plan_shift(shift)
        shift.is_attention = shift.is_no_plan or (shift.hours or 0) == 0

    total = sum(s.hours for s in shifts)

    completeness = employee_completeness(session, user)
    name_clean = normalize_text(user.employee_name)
    requisite = session.query(Requisite).filter(
        Requisite.is_active == True,
        or_(Requisite.user_id == user.id, Requisite.employee_name == name_clean),
    ).first()
    for item in completeness:
        if item["source"] == "document" and item["document_type"]:
            doc = latest_employee_document(session, user.employee_name, item["document_type"].id)
            item["document"] = doc
            item["file_ext"] = doc.file_path.rsplit(".", 1)[-1].lower() if doc and doc.file_path else ""
            item["requisite"] = None
        else:
            item["document"] = None
            item["file_ext"] = ""
            item["requisite"] = requisite
    all_ok = all(r["status"] == "ok" for r in completeness)
    attention_count = sum(1 for r in completeness if r["status"] != "ok")

    return templates.TemplateResponse(
        request,
        "cabinet.html",
        {
            "user": user,
            "shifts": shifts,
            "total_hours": total,
            "date_from": date_from,
            "date_to": date_to,
            "completeness": completeness,
            "all_ok": all_ok,
            "attention_count": attention_count,
            "status_styles": _STATUS_STYLES,
            "error": None,
        },
    )


def validate_password_change(user, current_password, new_password, new_password_repeat):
    """Проверка смены пароля сотрудником. Возвращает текст ошибки или None.

    Текущий пароль требуем всегда (в т.ч. для временного — он известен сотруднику).
    Значения паролей нигде не логируются.
    """
    current_clean = str(current_password).strip()
    new_clean = str(new_password).strip()
    repeat_clean = str(new_password_repeat).strip()

    if not verify_password(current_clean, user.password_hash):
        return "Текущий пароль неверный"
    if len(new_clean) < 6:
        return "Новый пароль должен содержать минимум 6 символов"
    if new_clean != repeat_clean:
        return "Новый пароль и повтор не совпадают"
    if verify_password(new_clean, user.password_hash):
        return "Новый пароль совпадает с текущим — придумайте другой"
    return None


@router.get("/cabinet/password", response_class=HTMLResponse)
def cabinet_password_page(
    request: Request,
    user=Depends(current_user),
):
    return templates.TemplateResponse(
        request,
        "cabinet_password.html",
        {"user": user, "error": None, "message": None},
    )


@router.post("/cabinet/password", response_class=HTMLResponse)
def cabinet_password_submit(
    request: Request,
    current_password: str = Form(""),
    new_password: str = Form(""),
    new_password_repeat: str = Form(""),
    session: Session = Depends(get_db),
    user=Depends(current_user),
):
    def render(error=None, message=None):
        return templates.TemplateResponse(
            request,
            "cabinet_password.html",
            {"user": user, "error": error, "message": message},
        )

    error = validate_password_change(user, current_password, new_password, new_password_repeat)
    if error:
        return render(error=error)

    user.password_hash = get_password_hash(str(new_password).strip())
    user.password_is_temporary = False
    create_audit_log(
        session, request, user,
        "password_changed_by_user", "user", user.id, user.employee_name,
        comment="employee changed own password",  # значения паролей не логируем
    )
    session.commit()
    return render(message="Пароль изменён")


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

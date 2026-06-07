from datetime import datetime
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from access import get_economist_cities
from audit_helpers import create_audit_log
from dependencies import get_db, require_admin_user, require_economist_user
from lmk_charges import month_start
from models import MedicalBookCharge, Shift
from time_helpers import now_utc
from utils import normalize_text


router = APIRouter()
templates = Jinja2Templates(directory="templates")


def _employee_names_for_cities(session, allowed_cities):
    if allowed_cities is None:
        rows = session.query(Shift.employee).distinct().all()
    elif not allowed_cities:
        return []
    else:
        rows = session.query(Shift.employee).filter(
            Shift.city.in_(allowed_cities)
        ).distinct().all()

    return sorted({normalize_text(row[0]) for row in rows if row[0]})


def _employee_list(session, allowed_cities=None):
    return _employee_names_for_cities(session, allowed_cities)


def _scope_charges(query, employee_names):
    if employee_names is None:
        return query
    if not employee_names:
        return query.filter(MedicalBookCharge.id == -1)
    return query.filter(MedicalBookCharge.employee_name.in_(employee_names))


def _render_lmk_page(
    request,
    session,
    user,
    *,
    base_path,
    back_url,
    back_label,
    payroll_url,
    employee_names=None,
    message="",
    error="",
):
    active_query = session.query(MedicalBookCharge).filter(
        MedicalBookCharge.status == "active"
    )
    archived_query = session.query(MedicalBookCharge).filter(
        MedicalBookCharge.status.in_(["completed", "cancelled"])
    )

    active_charges = _scope_charges(active_query, employee_names).order_by(
        MedicalBookCharge.start_month.asc(),
        MedicalBookCharge.employee_name.asc(),
    ).all()

    archived_charges = _scope_charges(archived_query, employee_names).order_by(
        MedicalBookCharge.id.desc()
    ).limit(100).all()

    return templates.TemplateResponse(
        request,
        "lmk.html",
        {
            "admin": user,
            "base_path": base_path,
            "back_url": back_url,
            "back_label": back_label,
            "payroll_url": payroll_url,
            "employees": _employee_list(session) if employee_names is None else employee_names,
            "active_charges": active_charges,
            "archived_charges": archived_charges,
            "message": message or None,
            "error": error or None,
        },
    )


def _economist_allowed_employee_names(session, user):
    if user.is_admin:
        return None
    return _employee_names_for_cities(session, get_economist_cities(user))


def _is_employee_allowed(employee_name, employee_names):
    if employee_names is None:
        return True
    return normalize_text(employee_name) in set(employee_names)


def _is_charge_allowed(charge, employee_names):
    return bool(charge) and _is_employee_allowed(charge.employee_name, employee_names)


def _parse_date(value):
    return datetime.strptime(value, "%Y-%m-%d").date()


def _parse_month(value):
    return month_start(_parse_date(f"{value}-01" if len(value) == 7 else value))


def _parse_money(value):
    try:
        return float(str(value or "0").replace(",", "."))
    except ValueError:
        return 0


def _redirect(base_path, **params):
    query = {key: value for key, value in params.items() if value}
    url = base_path
    if query:
        url = f"{base_path}?{urlencode(query)}"
    return RedirectResponse(url=url, status_code=302)


def _add_lmk_charge(
    session,
    request,
    user,
    base_path,
    employee_names,
    employee_name,
    exam_date,
    total_amount,
    months_count,
    monthly_amount,
    start_month,
    comment,
):
    employee_name_clean = normalize_text(employee_name)
    if not _is_employee_allowed(employee_name_clean, employee_names):
        return _redirect(base_path, error="Нет доступа к сотруднику")

    total = _parse_money(total_amount)
    months = max(months_count or 1, 1)
    monthly = _parse_money(monthly_amount) or round(total / months, 2)

    charge = MedicalBookCharge(
        employee_name=employee_name_clean,
        exam_date=_parse_date(exam_date),
        total_amount=total,
        months_count=months,
        monthly_amount=monthly,
        start_month=_parse_month(start_month),
        remaining_amount=total,
        status="active",
        comment=normalize_text(comment) or None,
        created_by=user.id,
        created_at=now_utc(),
    )
    session.add(charge)
    session.flush()
    create_audit_log(
        session,
        request,
        user,
        "lmk_created",
        "medical_book_charge",
        charge.id,
        charge.employee_name,
        new_value={
            "total_amount": charge.total_amount,
            "monthly_amount": charge.monthly_amount,
            "remaining_amount": charge.remaining_amount,
            "start_month": charge.start_month,
            "status": charge.status,
        },
        comment=charge.comment,
    )
    session.commit()

    return _redirect(base_path, message="ЛМК удержание добавлено")


def _update_lmk_charge(
    session,
    request,
    user,
    base_path,
    employee_names,
    charge_id,
    total_amount,
    months_count,
    monthly_amount,
    start_month,
    remaining_amount,
    comment,
):
    charge = session.query(MedicalBookCharge).filter(
        MedicalBookCharge.id == charge_id
    ).first()
    if not charge:
        return _redirect(base_path, error="ЛМК удержание не найдено")
    if not _is_charge_allowed(charge, employee_names):
        return _redirect(base_path, error="Нет доступа к удержанию")

    old_value = {
        "total_amount": charge.total_amount,
        "months_count": charge.months_count,
        "monthly_amount": charge.monthly_amount,
        "start_month": charge.start_month,
        "remaining_amount": charge.remaining_amount,
        "status": charge.status,
        "comment": charge.comment,
    }
    charge.total_amount = _parse_money(total_amount)
    charge.months_count = max(months_count or 1, 1)
    charge.monthly_amount = _parse_money(monthly_amount)
    charge.start_month = _parse_month(start_month)
    charge.remaining_amount = _parse_money(remaining_amount)
    charge.comment = normalize_text(comment) or None
    if charge.status == "completed" and charge.remaining_amount > 0:
        charge.status = "active"
    if charge.status == "active" and charge.remaining_amount <= 0:
        charge.status = "completed"

    create_audit_log(
        session,
        request,
        user,
        "lmk_updated",
        "medical_book_charge",
        charge.id,
        charge.employee_name,
        old_value=old_value,
        new_value={
            "total_amount": charge.total_amount,
            "months_count": charge.months_count,
            "monthly_amount": charge.monthly_amount,
            "start_month": charge.start_month,
            "remaining_amount": charge.remaining_amount,
            "status": charge.status,
            "comment": charge.comment,
        },
    )
    session.commit()
    return _redirect(base_path, message="ЛМК удержание обновлено")


def _cancel_lmk_charge(session, request, user, base_path, employee_names, charge_id):
    charge = session.query(MedicalBookCharge).filter(
        MedicalBookCharge.id == charge_id
    ).first()
    if not charge:
        return _redirect(base_path, error="ЛМК удержание не найдено")
    if not _is_charge_allowed(charge, employee_names):
        return _redirect(base_path, error="Нет доступа к удержанию")

    old_value = {"status": charge.status, "remaining_amount": charge.remaining_amount}
    charge.status = "cancelled"
    charge.cancelled_by = user.id
    charge.cancelled_at = now_utc()
    create_audit_log(
        session,
        request,
        user,
        "lmk_updated",
        "medical_book_charge",
        charge.id,
        charge.employee_name,
        old_value=old_value,
        new_value={"status": "cancelled", "cancelled_at": charge.cancelled_at},
    )
    session.commit()

    return _redirect(base_path, message="ЛМК удержание отменено")


@router.get("/admin/lmk", response_class=HTMLResponse)
def lmk_page(
    request: Request,
    message: str = "",
    error: str = "",
    session: Session = Depends(get_db),
    admin=Depends(require_admin_user),
):
    return _render_lmk_page(
        request,
        session,
        admin,
        base_path="/admin/lmk",
        back_url="/admin",
        back_label="Назад в админку",
        payroll_url="/admin/payroll",
        message=message,
        error=error,
    )


@router.get("/economist/lmk", response_class=HTMLResponse)
def economist_lmk_page(
    request: Request,
    message: str = "",
    error: str = "",
    session: Session = Depends(get_db),
    user=Depends(require_economist_user),
):
    return _render_lmk_page(
        request,
        session,
        user,
        base_path="/economist/lmk",
        back_url="/economist",
        back_label="Кабинет экономиста",
        payroll_url="/economist/payroll",
        employee_names=_economist_allowed_employee_names(session, user),
        message=message,
        error=error,
    )


@router.post("/economist/lmk/add")
def economist_add_lmk_charge(
    request: Request,
    employee_name: str = Form(...),
    exam_date: str = Form(...),
    total_amount: str = Form(...),
    months_count: int = Form(...),
    monthly_amount: str = Form(default=""),
    start_month: str = Form(...),
    comment: str = Form(default=""),
    session: Session = Depends(get_db),
    user=Depends(require_economist_user),
):
    try:
        return _add_lmk_charge(
            session,
            request,
            user,
            "/economist/lmk",
            _economist_allowed_employee_names(session, user),
            employee_name,
            exam_date,
            total_amount,
            months_count,
            monthly_amount,
            start_month,
            comment,
        )

    except Exception as exc:
        session.rollback()
        return _redirect("/economist/lmk", error=str(exc))


@router.post("/economist/lmk/update")
def economist_update_lmk_charge(
    request: Request,
    charge_id: int = Form(...),
    total_amount: str = Form(...),
    months_count: int = Form(...),
    monthly_amount: str = Form(...),
    start_month: str = Form(...),
    remaining_amount: str = Form(...),
    comment: str = Form(default=""),
    session: Session = Depends(get_db),
    user=Depends(require_economist_user),
):
    try:
        return _update_lmk_charge(
            session,
            request,
            user,
            "/economist/lmk",
            _economist_allowed_employee_names(session, user),
            charge_id,
            total_amount,
            months_count,
            monthly_amount,
            start_month,
            remaining_amount,
            comment,
        )

    except Exception as exc:
        session.rollback()
        return _redirect("/economist/lmk", error=str(exc))


@router.post("/economist/lmk/cancel")
def economist_cancel_lmk_charge(
    request: Request,
    charge_id: int = Form(...),
    session: Session = Depends(get_db),
    user=Depends(require_economist_user),
):
    try:
        return _cancel_lmk_charge(
            session,
            request,
            user,
            "/economist/lmk",
            _economist_allowed_employee_names(session, user),
            charge_id,
        )

    except Exception as exc:
        session.rollback()
        return _redirect("/economist/lmk", error=str(exc))


@router.post("/admin/lmk/add")
def add_lmk_charge(
    request: Request,
    employee_name: str = Form(...),
    exam_date: str = Form(...),
    total_amount: str = Form(...),
    months_count: int = Form(...),
    monthly_amount: str = Form(default=""),
    start_month: str = Form(...),
    comment: str = Form(default=""),
    session: Session = Depends(get_db),
    admin=Depends(require_admin_user),
):
    try:
        return _add_lmk_charge(
            session,
            request,
            admin,
            "/admin/lmk",
            None,
            employee_name,
            exam_date,
            total_amount,
            months_count,
            monthly_amount,
            start_month,
            comment,
        )

    except Exception as exc:
        session.rollback()
        return _redirect("/admin/lmk", error=str(exc))


@router.post("/admin/lmk/update")
def update_lmk_charge(
    request: Request,
    charge_id: int = Form(...),
    total_amount: str = Form(...),
    months_count: int = Form(...),
    monthly_amount: str = Form(...),
    start_month: str = Form(...),
    remaining_amount: str = Form(...),
    comment: str = Form(default=""),
    session: Session = Depends(get_db),
    admin=Depends(require_admin_user),
):
    try:
        return _update_lmk_charge(
            session,
            request,
            admin,
            "/admin/lmk",
            None,
            charge_id,
            total_amount,
            months_count,
            monthly_amount,
            start_month,
            remaining_amount,
            comment,
        )

    except Exception as exc:
        session.rollback()
        return _redirect("/admin/lmk", error=str(exc))


@router.post("/admin/lmk/cancel")
def cancel_lmk_charge(
    request: Request,
    charge_id: int = Form(...),
    session: Session = Depends(get_db),
    admin=Depends(require_admin_user),
):
    return _cancel_lmk_charge(session, request, admin, "/admin/lmk", None, charge_id)

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from access import get_economist_cities
from audit_helpers import create_audit_log
from dependencies import get_db
from models import PayrollAdjustment, Shift
from rbac import require_permission
from time_helpers import now_utc
from utils import normalize_text

_adjustments_manage = require_permission("adjustments.manage")


router = APIRouter()
templates = Jinja2Templates(directory="templates")


def _adjustment_name(adjustment):
    return f"{adjustment.employee_name} / {adjustment.store} / {adjustment.shift_date}"


def _log_adjustment(session, request, user, action, adjustment, old_status=None):
    create_audit_log(
        session,
        request,
        user,
        action,
        "payroll_adjustment",
        adjustment.id,
        _adjustment_name(adjustment),
        old_value={"status": old_status} if old_status is not None else None,
        new_value={
            "status": adjustment.status,
            "target_run_id": adjustment.target_run_id,
            "diff_hours": adjustment.diff_hours,
            "diff_amount": adjustment.diff_amount,
        },
    )


def _payroll_redirect_url(base_path, date_from="", date_to="", employee_name="", stores=None):
    params = []
    if date_from:
        params.append(urlencode({"date_from": date_from}))
    if date_to:
        params.append(urlencode({"date_to": date_to}))
    if employee_name:
        params.append(urlencode({"employee_name": employee_name}))
    for store in stores or []:
        params.append(urlencode({"stores": store}))
    if params:
        return f"{base_path}?{'&'.join(params)}"
    return base_path


def _adjustments_redirect_url(
    base_path,
    status="pending",
    message="",
    error="",
    employee_name="",
):
    params = {}
    if status:
        params["status"] = status
    if employee_name:
        params["employee_name"] = employee_name
    if message:
        params["message"] = message
    if error:
        params["error"] = error
    query = urlencode(params)
    return f"{base_path}?{query}" if query else base_path


def _status_urls(base_path, employee_name=""):
    return {
        status: _adjustments_redirect_url(
            base_path,
            status=status,
            employee_name=employee_name,
        )
        for status in ("applied", "pending", "approved", "rejected", "all")
    }


def _admin_adjustment_employees(session):
    rows = session.query(PayrollAdjustment.employee_name).filter(
        PayrollAdjustment.employee_name != None,
        PayrollAdjustment.employee_name != "",
    ).distinct().order_by(PayrollAdjustment.employee_name.asc()).all()
    return [row[0] for row in rows]


def _economist_adjustment_employees(session, user):
    query = session.query(PayrollAdjustment)
    adjustments = _filter_economist_adjustments(session, query.all(), user)
    return sorted({
        normalize_text(adjustment.employee_name)
        for adjustment in adjustments
        if normalize_text(adjustment.employee_name)
    })


def _payroll_adjustments_query(
    session,
    *,
    adjustment_ids=None,
    employee_name="",
    store="",
):
    query = session.query(PayrollAdjustment).filter(
        PayrollAdjustment.target_run_id == None,
        PayrollAdjustment.status.in_(["pending", "approved"]),
    )

    if adjustment_ids:
        return query.filter(PayrollAdjustment.id.in_(adjustment_ids))

    employee_name_clean = normalize_text(employee_name)
    store_clean = normalize_text(store)

    if not employee_name_clean and not store_clean:
        return query.filter(PayrollAdjustment.id == -1)

    if employee_name_clean:
        query = query.filter(PayrollAdjustment.employee_name == employee_name_clean)
    if store_clean:
        query = query.filter(PayrollAdjustment.store == store_clean)

    return query


def _shift_key(employee, store, service, shift_date):
    return (
        normalize_text(employee),
        normalize_text(store),
        normalize_text(service),
        shift_date,
    )


def _allowed_adjustment_keys(session, allowed_cities):
    if not allowed_cities:
        return set()

    rows = session.query(
        Shift.employee,
        Shift.store,
        Shift.service,
        Shift.shift_date,
    ).filter(Shift.city.in_(allowed_cities)).distinct().all()

    return {
        _shift_key(row[0], row[1], row[2], row[3])
        for row in rows
    }


def _filter_economist_adjustments(session, adjustments, user):
    if user.is_admin:
        return adjustments

    allowed_cities = get_economist_cities(user)
    allowed_keys = _allowed_adjustment_keys(session, allowed_cities)

    return [
        adjustment
        for adjustment in adjustments
        if _shift_key(
            adjustment.employee_name,
            adjustment.store,
            adjustment.service,
            adjustment.shift_date,
        ) in allowed_keys
    ]


def _economist_can_manage_adjustment(session, adjustment, user):
    if not adjustment:
        return False
    if user.is_admin:
        return True

    allowed_cities = get_economist_cities(user)
    if not allowed_cities:
        return False

    return session.query(Shift.id).filter(
        Shift.city.in_(allowed_cities),
        Shift.employee == normalize_text(adjustment.employee_name),
        Shift.store == normalize_text(adjustment.store),
        Shift.service == normalize_text(adjustment.service),
        Shift.shift_date == adjustment.shift_date,
    ).first() is not None


@router.get("/admin/adjustments", response_class=HTMLResponse)
def admin_adjustments(
    request: Request,
    status: str = "pending",
    employee_name: str = "",
    message: str = "",
    error: str = "",
    session: Session = Depends(get_db),
    admin=Depends(_adjustments_manage),
):
    query = session.query(PayrollAdjustment)

    if status and status != "all":
        query = query.filter(PayrollAdjustment.status == status)

    employee_name_clean = normalize_text(employee_name)
    if employee_name_clean:
        query = query.filter(PayrollAdjustment.employee_name == employee_name_clean)

    adjustments = query.order_by(
        PayrollAdjustment.created_at.desc(),
        PayrollAdjustment.id.desc()
    ).all()

    return templates.TemplateResponse(
        request,
        "adjustments.html",
        {
            "adjustments": adjustments,
            "status": status,
            "employee_name": employee_name_clean,
            "employee_options": _admin_adjustment_employees(session),
            "status_urls": _status_urls("/admin/adjustments", employee_name_clean),
            "base_path": "/admin/adjustments",
            "back_url": "/admin",
            "back_label": "Назад в админку",
            "show_actions": True,
            "show_upload_link": True,
            "message": message or None,
            "error": error or None
        }
    )



@router.post("/admin/adjustments/approve")
def approve_adjustment(
    request: Request,
    adjustment_id: int = Form(...),
    status: str = Form(default="pending"),
    employee_name: str = Form(default=""),
    session: Session = Depends(get_db),
    admin=Depends(_adjustments_manage),
):
    adjustment = session.query(PayrollAdjustment).filter(
        PayrollAdjustment.id == adjustment_id
    ).first()

    if adjustment and adjustment.status == "pending":
        old_status = adjustment.status
        adjustment.status = "approved"
        adjustment.approved_at = now_utc()
        adjustment.approved_by = admin.id
        _log_adjustment(session, request, admin, "adjustment_approved", adjustment, old_status)
        session.commit()

    return RedirectResponse(
        url=_adjustments_redirect_url(
            "/admin/adjustments",
            status,
            employee_name=employee_name,
        ),
        status_code=302,
    )



@router.post("/admin/adjustments/reject")
def reject_adjustment(
    request: Request,
    adjustment_id: int = Form(...),
    status: str = Form(default="pending"),
    employee_name: str = Form(default=""),
    session: Session = Depends(get_db),
    admin=Depends(_adjustments_manage),
):
    adjustment = session.query(PayrollAdjustment).filter(
        PayrollAdjustment.id == adjustment_id
    ).first()

    if adjustment and adjustment.status == "pending":
        old_status = adjustment.status
        adjustment.status = "rejected"
        adjustment.rejected_at = now_utc()
        adjustment.rejected_by = admin.id
        _log_adjustment(session, request, admin, "adjustment_rejected", adjustment, old_status)
        session.commit()

    return RedirectResponse(
        url=_adjustments_redirect_url(
            "/admin/adjustments",
            status,
            employee_name=employee_name,
        ),
        status_code=302,
    )



@router.post("/admin/payroll/adjustments/delete")
def delete_payroll_adjustments(
    request: Request,
    adjustment_ids: list[int] | None = Form(default=None),
    employee_name: str = Form(default=""),
    store: str = Form(default=""),
    date_from: str = Form(default=""),
    date_to: str = Form(default=""),
    redirect_employee_name: str = Form(default=""),
    stores: list[str] | None = Form(default=None),
    session: Session = Depends(get_db),
    admin=Depends(_adjustments_manage),
):
    adjustments = _payroll_adjustments_query(
        session,
        adjustment_ids=adjustment_ids,
        employee_name=employee_name,
        store=store,
    ).all()

    for adjustment in adjustments:
        old_status = adjustment.status
        adjustment.status = "deleted"
        adjustment.rejected_by = admin.id
        adjustment.rejected_at = now_utc()
        _log_adjustment(session, request, admin, "adjustment_deleted", adjustment, old_status)

    session.commit()

    return RedirectResponse(
        url=_payroll_redirect_url("/admin/payroll", date_from, date_to, redirect_employee_name, stores),
        status_code=302,
    )



@router.post("/admin/payroll/adjustments/approve")
def approve_payroll_adjustments(
    request: Request,
    adjustment_ids: list[int] | None = Form(default=None),
    employee_name: str = Form(default=""),
    store: str = Form(default=""),
    date_from: str = Form(default=""),
    date_to: str = Form(default=""),
    redirect_employee_name: str = Form(default=""),
    stores: list[str] | None = Form(default=None),
    session: Session = Depends(get_db),
    admin=Depends(_adjustments_manage),
):
    adjustments = _payroll_adjustments_query(
        session,
        adjustment_ids=adjustment_ids,
        employee_name=employee_name,
        store=store,
    ).filter(PayrollAdjustment.status == "pending").all()

    for adjustment in adjustments:
        old_status = adjustment.status
        adjustment.status = "approved"
        adjustment.approved_at = now_utc()
        adjustment.approved_by = admin.id
        _log_adjustment(session, request, admin, "adjustment_approved", adjustment, old_status)

    session.commit()

    return RedirectResponse(
        url=_payroll_redirect_url("/admin/payroll", date_from, date_to, redirect_employee_name, stores),
        status_code=302,
    )



@router.post("/economist/payroll/adjustments/delete")
def economist_delete_payroll_adjustments(
    request: Request,
    adjustment_ids: list[int] | None = Form(default=None),
    employee_name: str = Form(default=""),
    store: str = Form(default=""),
    date_from: str = Form(default=""),
    date_to: str = Form(default=""),
    redirect_employee_name: str = Form(default=""),
    stores: list[str] | None = Form(default=None),
    session: Session = Depends(get_db),
    user=Depends(_adjustments_manage),
):
    adjustments = _payroll_adjustments_query(
        session,
        adjustment_ids=adjustment_ids,
        employee_name=employee_name,
        store=store,
    ).all()
    adjustments = _filter_economist_adjustments(session, adjustments, user)

    for adjustment in adjustments:
        old_status = adjustment.status
        adjustment.status = "deleted"
        adjustment.rejected_by = user.id
        adjustment.rejected_at = now_utc()
        _log_adjustment(session, request, user, "adjustment_deleted", adjustment, old_status)

    session.commit()

    return RedirectResponse(
        url=_payroll_redirect_url("/economist/payroll", date_from, date_to, redirect_employee_name, stores),
        status_code=302,
    )



@router.post("/economist/payroll/adjustments/approve")
def economist_approve_payroll_adjustments(
    request: Request,
    adjustment_ids: list[int] | None = Form(default=None),
    employee_name: str = Form(default=""),
    store: str = Form(default=""),
    date_from: str = Form(default=""),
    date_to: str = Form(default=""),
    redirect_employee_name: str = Form(default=""),
    stores: list[str] | None = Form(default=None),
    session: Session = Depends(get_db),
    user=Depends(_adjustments_manage),
):
    adjustments = _payroll_adjustments_query(
        session,
        adjustment_ids=adjustment_ids,
        employee_name=employee_name,
        store=store,
    ).filter(PayrollAdjustment.status == "pending").all()
    adjustments = _filter_economist_adjustments(session, adjustments, user)

    for adjustment in adjustments:
        old_status = adjustment.status
        adjustment.status = "approved"
        adjustment.approved_at = now_utc()
        adjustment.approved_by = user.id
        _log_adjustment(session, request, user, "adjustment_approved", adjustment, old_status)

    session.commit()

    return RedirectResponse(
        url=_payroll_redirect_url("/economist/payroll", date_from, date_to, redirect_employee_name, stores),
        status_code=302,
    )



@router.get("/economist/adjustments", response_class=HTMLResponse)
def economist_adjustments(
    request: Request,
    status: str = "pending",
    employee_name: str = "",
    message: str = "",
    error: str = "",
    session: Session = Depends(get_db),
    user=Depends(_adjustments_manage),
):
    query = session.query(PayrollAdjustment)

    if status and status != "all":
        query = query.filter(PayrollAdjustment.status == status)

    adjustments = query.order_by(
        PayrollAdjustment.created_at.desc(),
        PayrollAdjustment.id.desc()
    ).all()
    adjustments = _filter_economist_adjustments(session, adjustments, user)

    employee_name_clean = normalize_text(employee_name)
    if employee_name_clean:
        adjustments = [
            adjustment
            for adjustment in adjustments
            if normalize_text(adjustment.employee_name) == employee_name_clean
        ]

    return templates.TemplateResponse(
        request,
        "economist_adjustments.html",
        {
            "adjustments": adjustments,
            "status": status,
            "employee_name": employee_name_clean,
            "employee_options": _economist_adjustment_employees(session, user),
            "status_urls": _status_urls("/economist/adjustments", employee_name_clean),
            "base_path": "/economist/adjustments",
            "back_url": "/economist",
            "back_label": "Кабинет экономиста",
            "show_actions": True,
            "show_upload_link": False,
            "message": message or None,
            "error": error or None
        }
    )



@router.post("/economist/adjustments/approve")
def economist_approve_adjustment(
    request: Request,
    adjustment_id: int = Form(...),
    status: str = Form(default="pending"),
    session: Session = Depends(get_db),
    user=Depends(_adjustments_manage),
):
    adjustment = session.query(PayrollAdjustment).filter(
        PayrollAdjustment.id == adjustment_id
    ).first()

    if not _economist_can_manage_adjustment(session, adjustment, user):
        return RedirectResponse(
            url=_adjustments_redirect_url(
                "/economist/adjustments",
                status,
                error="Нет доступа к корректировке",
            ),
            status_code=302,
        )

    if adjustment.status == "pending":
        old_status = adjustment.status
        adjustment.status = "approved"
        adjustment.approved_at = now_utc()
        adjustment.approved_by = user.id
        _log_adjustment(session, request, user, "adjustment_approved", adjustment, old_status)
        session.commit()

    return RedirectResponse(
        url=_adjustments_redirect_url(
            "/economist/adjustments",
            status,
            message="Корректировка подтверждена",
        ),
        status_code=302,
    )



@router.post("/economist/adjustments/reject")
def economist_reject_adjustment(
    request: Request,
    adjustment_id: int = Form(...),
    status: str = Form(default="pending"),
    session: Session = Depends(get_db),
    user=Depends(_adjustments_manage),
):
    adjustment = session.query(PayrollAdjustment).filter(
        PayrollAdjustment.id == adjustment_id
    ).first()

    if not _economist_can_manage_adjustment(session, adjustment, user):
        return RedirectResponse(
            url=_adjustments_redirect_url(
                "/economist/adjustments",
                status,
                error="Нет доступа к корректировке",
            ),
            status_code=302,
        )

    if adjustment.status == "pending":
        old_status = adjustment.status
        adjustment.status = "rejected"
        adjustment.rejected_at = now_utc()
        adjustment.rejected_by = user.id
        _log_adjustment(session, request, user, "adjustment_rejected", adjustment, old_status)
        session.commit()

    return RedirectResponse(
        url=_adjustments_redirect_url(
            "/economist/adjustments",
            status,
            message="Корректировка отклонена",
        ),
        status_code=302,
    )



@router.post("/economist/adjustments/delete")
def economist_delete_adjustment(
    request: Request,
    adjustment_id: int = Form(...),
    status: str = Form(default="pending"),
    session: Session = Depends(get_db),
    user=Depends(_adjustments_manage),
):
    adjustment = session.query(PayrollAdjustment).filter(
        PayrollAdjustment.id == adjustment_id
    ).first()

    if not _economist_can_manage_adjustment(session, adjustment, user):
        return RedirectResponse(
            url=_adjustments_redirect_url(
                "/economist/adjustments",
                status,
                error="Нет доступа к корректировке",
            ),
            status_code=302,
        )

    if adjustment.status != "applied" and adjustment.target_run_id is None:
        old_status = adjustment.status
        adjustment.status = "deleted"
        adjustment.rejected_at = now_utc()
        adjustment.rejected_by = user.id
        _log_adjustment(session, request, user, "adjustment_deleted", adjustment, old_status)
        session.commit()

    return RedirectResponse(
        url=_adjustments_redirect_url(
            "/economist/adjustments",
            status,
            message="Корректировка удалена",
        ),
        status_code=302,
    )


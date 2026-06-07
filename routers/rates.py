from datetime import datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from audit_helpers import create_audit_log
from dependencies import get_db, require_admin_user, require_economist_user
from models import Rate
from utils import normalize_format, normalize_text


router = APIRouter()
templates = Jinja2Templates(directory="templates")


def _rate_payload(rate):
    return {
        "service": rate.service,
        "format": rate.format,
        "store": rate.store,
        "employee_name": rate.employee_name,
        "hourly_rate": rate.hourly_rate,
        "active_from": rate.active_from,
        "active_to": rate.active_to,
        "comment": rate.comment,
    }


def rates_query(session):
    return session.query(Rate).order_by(
        Rate.employee_name.desc().nullslast(),
        Rate.store.desc().nullslast(),
        Rate.format.desc().nullslast(),
        Rate.service.asc()
    )


@router.get("/economist/rates", response_class=HTMLResponse)
def economist_rates(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(require_economist_user),
):
    rates = rates_query(session).all()

    return templates.TemplateResponse(
        request,
        "economist_rates.html",
        {
            "rates": rates,
            "message": None,
            "error": None
        }
    )


@router.post("/economist/rates", response_class=HTMLResponse)
def economist_create_rate(
    request: Request,
    service: str = Form(...),
    format: str = Form(default=""),
    store: str = Form(default=""),
    employee_name: str = Form(default=""),
    hourly_rate: float = Form(...),
    active_from: str = Form(default=""),
    active_to: str = Form(default=""),
    comment: str = Form(default=""),
    session: Session = Depends(get_db),
    user=Depends(require_economist_user),
):
    active_from_date = None
    active_to_date = None

    if active_from:
        active_from_date = datetime.strptime(active_from, "%Y-%m-%d").date()

    if active_to:
        active_to_date = datetime.strptime(active_to, "%Y-%m-%d").date()

    rate = Rate(
        service=normalize_text(service),
        format=normalize_format(format) or None,
        store=normalize_text(store) or None,
        employee_name=normalize_text(employee_name) or None,
        hourly_rate=hourly_rate,
        active_from=active_from_date,
        active_to=active_to_date,
        comment=normalize_text(comment) or None
    )

    session.add(rate)
    session.flush()
    create_audit_log(
        session,
        request,
        user,
        "rate_created",
        "rate",
        rate.id,
        f"{rate.service} / {rate.format or ''} / {rate.store or ''} / {rate.employee_name or ''}",
        new_value=_rate_payload(rate),
    )
    session.commit()

    return RedirectResponse(url="/economist/rates", status_code=302)


@router.post("/economist/rates/update", response_class=HTMLResponse)
def economist_update_rate(
    request: Request,
    rate_id: int = Form(...),
    service: str = Form(...),
    format: str = Form(default=""),
    store: str = Form(default=""),
    employee_name: str = Form(default=""),
    hourly_rate: float = Form(...),
    active_from: str = Form(default=""),
    active_to: str = Form(default=""),
    comment: str = Form(default=""),
    session: Session = Depends(get_db),
    user=Depends(require_economist_user),
):
    rate = session.query(Rate).filter(Rate.id == rate_id).first()

    if not rate:
        return RedirectResponse(url="/economist/rates", status_code=302)

    old_value = _rate_payload(rate)
    active_from_date = None
    active_to_date = None

    if active_from:
        active_from_date = datetime.strptime(active_from, "%Y-%m-%d").date()

    if active_to:
        active_to_date = datetime.strptime(active_to, "%Y-%m-%d").date()

    rate.service = normalize_text(service)
    rate.format = normalize_format(format) or None
    rate.store = normalize_text(store) or None
    rate.employee_name = normalize_text(employee_name) or None
    rate.hourly_rate = hourly_rate
    rate.active_from = active_from_date
    rate.active_to = active_to_date
    rate.comment = normalize_text(comment) or None

    create_audit_log(
        session,
        request,
        user,
        "rate_updated",
        "rate",
        rate.id,
        f"{rate.service} / {rate.format or ''} / {rate.store or ''} / {rate.employee_name or ''}",
        old_value=old_value,
        new_value=_rate_payload(rate),
    )
    session.commit()

    return RedirectResponse(url="/economist/rates", status_code=302)


@router.post("/economist/rates/delete", response_class=HTMLResponse)
def economist_delete_rate(
    request: Request,
    rate_id: int = Form(...),
    session: Session = Depends(get_db),
    user=Depends(require_economist_user),
):
    rate = session.query(Rate).filter(Rate.id == rate_id).first()

    if rate:
        create_audit_log(
            session,
            request,
            user,
            "rate_deleted",
            "rate",
            rate.id,
            f"{rate.service} / {rate.format or ''} / {rate.store or ''} / {rate.employee_name or ''}",
            old_value=_rate_payload(rate),
        )
        session.delete(rate)
        session.commit()

    return RedirectResponse(url="/economist/rates", status_code=302)


@router.get("/admin/rates", response_class=HTMLResponse)
def admin_rates(
    request: Request,
    session: Session = Depends(get_db),
    admin=Depends(require_admin_user),
):
    rates = rates_query(session).all()

    return templates.TemplateResponse(
        request,
        "rates.html",
        {
            "rates": rates,
            "message": None,
            "error": None
        }
    )


@router.post("/admin/rates", response_class=HTMLResponse)
def create_rate(
    request: Request,
    service: str = Form(...),
    format: str = Form(default=""),
    store: str = Form(default=""),
    employee_name: str = Form(default=""),
    hourly_rate: float = Form(...),
    active_from: str = Form(default=""),
    active_to: str = Form(default=""),
    comment: str = Form(default=""),
    session: Session = Depends(get_db),
    admin=Depends(require_admin_user),
):
    service_clean = normalize_text(service)
    format_clean = normalize_format(format) or None
    store_clean = normalize_text(store) or None
    employee_name_clean = normalize_text(employee_name) or None
    comment_clean = normalize_text(comment) or None

    active_from_date = None
    active_to_date = None

    try:
        if active_from:
            active_from_date = datetime.strptime(active_from, "%Y-%m-%d").date()
        if active_to:
            active_to_date = datetime.strptime(active_to, "%Y-%m-%d").date()
    except ValueError:
        rates = session.query(Rate).order_by(Rate.service.asc()).all()
        return templates.TemplateResponse(
            request,
            "rates.html",
            {
                "rates": rates,
                "message": None,
                "error": "Некорректный формат даты"
            }
        )

    if hourly_rate <= 0:
        rates = session.query(Rate).order_by(Rate.service.asc()).all()
        return templates.TemplateResponse(
            request,
            "rates.html",
            {
                "rates": rates,
                "message": None,
                "error": "ЧТС должна быть больше нуля"
            }
        )

    rate = Rate(
        service=service_clean,
        format=format_clean,
        store=store_clean,
        employee_name=employee_name_clean,
        hourly_rate=hourly_rate,
        active_from=active_from_date,
        active_to=active_to_date,
        comment=comment_clean
    )

    session.add(rate)
    session.flush()
    create_audit_log(
        session,
        request,
        admin,
        "rate_created",
        "rate",
        rate.id,
        f"{rate.service} / {rate.format or ''} / {rate.store or ''} / {rate.employee_name or ''}",
        new_value=_rate_payload(rate),
    )
    session.commit()

    return RedirectResponse(url="/admin/rates", status_code=302)


@router.post("/admin/rates/update", response_class=HTMLResponse)
def update_rate(
    request: Request,
    rate_id: int = Form(...),
    service: str = Form(...),
    format: str = Form(default=""),
    store: str = Form(default=""),
    employee_name: str = Form(default=""),
    hourly_rate: float = Form(...),
    active_from: str = Form(default=""),
    active_to: str = Form(default=""),
    comment: str = Form(default=""),
    session: Session = Depends(get_db),
    admin=Depends(require_admin_user),
):
    rate = session.query(Rate).filter(Rate.id == rate_id).first()
    if not rate:
        return RedirectResponse(url="/admin/rates", status_code=302)

    old_value = _rate_payload(rate)
    active_from_date = None
    active_to_date = None

    if active_from:
        active_from_date = datetime.strptime(active_from, "%Y-%m-%d").date()
    if active_to:
        active_to_date = datetime.strptime(active_to, "%Y-%m-%d").date()

    rate.service = normalize_text(service)
    rate.format = normalize_format(format) or None
    rate.store = normalize_text(store) or None
    rate.employee_name = normalize_text(employee_name) or None
    rate.hourly_rate = hourly_rate
    rate.active_from = active_from_date
    rate.active_to = active_to_date
    rate.comment = normalize_text(comment) or None

    create_audit_log(
        session,
        request,
        admin,
        "rate_updated",
        "rate",
        rate.id,
        f"{rate.service} / {rate.format or ''} / {rate.store or ''} / {rate.employee_name or ''}",
        old_value=old_value,
        new_value=_rate_payload(rate),
    )
    session.commit()

    return RedirectResponse(url="/admin/rates", status_code=302)


@router.post("/admin/rates/delete", response_class=HTMLResponse)
def delete_rate(
    request: Request,
    rate_id: int = Form(...),
    session: Session = Depends(get_db),
    admin=Depends(require_admin_user),
):
    rate = session.query(Rate).filter(Rate.id == rate_id).first()
    if rate:
        create_audit_log(
            session,
            request,
            admin,
            "rate_deleted",
            "rate",
            rate.id,
            f"{rate.service} / {rate.format or ''} / {rate.store or ''} / {rate.employee_name or ''}",
            old_value=_rate_payload(rate),
        )
        session.delete(rate)
        session.commit()

    return RedirectResponse(url="/admin/rates", status_code=302)

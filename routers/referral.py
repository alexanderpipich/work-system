"""АПД «Приведи друга» — управление акциями (по образцу ЛМК): список, создание с
проверкой уникальности приведённого, глобальные настройки, отмена, подтверждение/
отмена pending-премий. Финансовый доступ (payroll.manage: economist/superadmin)."""

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from audit_helpers import create_audit_log
from dependencies import get_db
from models import ReferralPayout, ReferralPromo, User
from rbac import require_permission
from referral_helpers import (
    cancel_payout,
    confirm_payout,
    get_referral_settings,
    pending_payouts,
    referred_hours,
)
from time_helpers import now_utc
from utils import normalize_text

router = APIRouter()
templates = Jinja2Templates(directory="templates")
_manage = require_permission("payroll.manage")


def _base(request):
    return "/economist" if request.url.path.startswith("/economist") else "/admin"


def _redirect(base, message="", error=""):
    params = {}
    if message:
        params["message"] = message
    if error:
        params["error"] = error
    suffix = f"?{urlencode(params)}" if params else ""
    return RedirectResponse(f"{base}/referral{suffix}", status_code=302)


def _page(request, session, user, message="", error=""):
    settings = get_referral_settings(session)
    promos = session.query(ReferralPromo).order_by(ReferralPromo.id.desc()).all()
    rows = [{
        "promo": p,
        "hours": referred_hours(session, p.referred_employee_name),
        "beneficiary": p.beneficiary_name or "—",
    } for p in promos]
    users = session.query(User).order_by(User.employee_name.asc()).all()
    return templates.TemplateResponse(request, "referral.html", {
        "base_path": _base(request),
        "user": user,
        "settings": settings,
        "rows": rows,
        "users": users,
        "pending": pending_payouts(session),
        "message": message or None,
        "error": error or None,
    })


@router.get("/admin/referral", response_class=HTMLResponse)
@router.get("/economist/referral", response_class=HTMLResponse)
def referral_page(request: Request, message: str = "", error: str = "",
                  session: Session = Depends(get_db), user=Depends(_manage)):
    return _page(request, session, user, message=message, error=error)


@router.post("/admin/referral/create")
@router.post("/economist/referral/create")
def referral_create(request: Request, referred_employee_name: str = Form(...),
                    beneficiary_user_id: int = Form(...), comment: str = Form(default=""),
                    session: Session = Depends(get_db), user=Depends(_manage)):
    base = _base(request)
    referred = normalize_text(referred_employee_name)
    if not referred:
        return _redirect(base, error="Укажите ФИО приведённого")
    # Уникальность: 1 ФИО может быть приведённым только один раз за всю историю.
    exists = session.query(ReferralPromo).filter(
        ReferralPromo.referred_employee_name == referred
    ).first()
    if exists:
        return _redirect(base, error=f"«{referred}» уже был приведён ранее — повторная акция запрещена")
    beneficiary = session.query(User).filter(User.id == beneficiary_user_id).first()
    if not beneficiary:
        return _redirect(base, error="Выберите выгодоприобретателя из пользователей")
    promo = ReferralPromo(
        referred_employee_name=referred,
        beneficiary_user_id=beneficiary.id,
        beneficiary_name=beneficiary.employee_name,
        status="active", created_by=user.id, created_at=now_utc(),
        comment=normalize_text(comment) or None,
    )
    session.add(promo)
    session.flush()
    create_audit_log(session, request, user, "referral_promo_created", "referral_promo",
                     promo.id, referred, new_value={"beneficiary": beneficiary.employee_name})
    session.commit()
    return _redirect(base, message=f"Акция создана: {referred} → {beneficiary.employee_name}")


@router.post("/admin/referral/settings")
@router.post("/economist/referral/settings")
def referral_settings(request: Request, hours_threshold: float = Form(...),
                      bonus_amount: float = Form(...), session: Session = Depends(get_db), user=Depends(_manage)):
    settings = get_referral_settings(session)
    settings.hours_threshold = max(hours_threshold, 1)
    settings.bonus_amount = max(bonus_amount, 0)
    settings.updated_by = user.id
    settings.updated_at = now_utc()
    create_audit_log(session, request, user, "referral_settings_updated", "referral_settings",
                     settings.id, None, new_value={"threshold": settings.hours_threshold, "bonus": settings.bonus_amount})
    session.commit()
    return _redirect(_base(request), message="Настройки сохранены")


@router.post("/admin/referral/cancel")
@router.post("/economist/referral/cancel")
def referral_cancel(request: Request, promo_id: int = Form(...),
                    session: Session = Depends(get_db), user=Depends(_manage)):
    promo = session.query(ReferralPromo).filter(ReferralPromo.id == promo_id).first()
    if promo and promo.status in {"active", "threshold_reached"}:
        promo.status = "cancelled"
        promo.cancelled_by = user.id
        promo.cancelled_at = now_utc()
        # Незакрытые pending-премии по этой акции — отменить, чтобы не блокировали табель.
        for payout in session.query(ReferralPayout).filter(
            ReferralPayout.promo_id == promo.id, ReferralPayout.status == "pending"
        ).all():
            payout.status = "cancelled"
            payout.cancelled_by = user.id
            payout.cancelled_at = now_utc()
        create_audit_log(session, request, user, "referral_promo_cancelled", "referral_promo",
                         promo.id, promo.referred_employee_name)
        session.commit()
    return _redirect(_base(request), message="Акция отменена")


@router.post("/admin/referral/payout/confirm")
@router.post("/economist/referral/payout/confirm")
def referral_payout_confirm(request: Request, payout_id: int = Form(...), back: str = Form(default=""),
                            session: Session = Depends(get_db), user=Depends(_manage)):
    confirm_payout(session, request, user, payout_id)
    target = back if back.startswith(("/admin", "/economist")) else f"{_base(request)}/referral"
    sep = "&" if "?" in target else "?"
    return RedirectResponse(f"{target}{sep}message=Премия+подтверждена", status_code=302)


@router.post("/admin/referral/payout/cancel")
@router.post("/economist/referral/payout/cancel")
def referral_payout_cancel(request: Request, payout_id: int = Form(...), back: str = Form(default=""),
                           session: Session = Depends(get_db), user=Depends(_manage)):
    cancel_payout(session, request, user, payout_id)
    target = back if back.startswith(("/admin", "/economist")) else f"{_base(request)}/referral"
    sep = "&" if "?" in target else "?"
    return RedirectResponse(f"{target}{sep}message=Премия+отменена", status_code=302)

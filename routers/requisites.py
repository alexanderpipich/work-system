import pandas as pd
from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from access import accessible_employee_names, get_user_cities
from audit_helpers import create_audit_log
from dependencies import get_db, require_admin_user, require_economist_user
from models import Requisite, Shift, User
from rbac import canonical_role, require_permission
from time_helpers import now_utc
from utils import normalize_text


router = APIRouter()
templates = Jinja2Templates(directory="templates")
require_requisites_view = require_permission("requisites.view", audit_denied=True)


def _requisite_payload(req):
    return {
        "employee_name": req.employee_name,
        "inn": req.inn,
        "account_number": req.account_number,
        "bik": req.bik,
        "bank_name": req.bank_name,
        "citizenship": req.citizenship,
        "is_third_party": req.is_third_party,
        "recipient_name": req.recipient_name,
        "is_active": req.is_active,
        "is_verified": req.is_verified,
        "comment": req.comment,
    }


@router.get("/economist/requisites", response_class=HTMLResponse)
@router.get("/hr/requisites", response_class=HTMLResponse)
def economist_requisites(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(require_requisites_view),
):
    allowed_cities = get_user_cities(session, user)
    allowed_names = None if allowed_cities is None else accessible_employee_names(session, user)

    if not allowed_cities and canonical_role(user) not in {"superadmin", "hr_lead"}:
        return templates.TemplateResponse(
            request,
            "economist_requisites.html",
            {
                "user": user,
                "allowed_cities": allowed_cities,
                "requisites": [],
                "message": None,
                "error": "Для пользователя не назначены города"
            }
        )

    employee_names = (
        [normalize_text(row[0]) for row in session.query(Shift.employee).distinct().all() if row[0]]
        if allowed_names is None
        else allowed_names
    )

    requisites = session.query(Requisite).filter(
        Requisite.employee_name.in_(employee_names)
    ).order_by(
        Requisite.employee_name.asc()
    ).all()

    return templates.TemplateResponse(
        request,
        "economist_requisites.html",
        {
            "user": user,
            "allowed_cities": allowed_cities,
            "requisites": requisites,
            "message": None,
            "error": None
        }
    )


@router.get("/admin/requisites", response_class=HTMLResponse)
def admin_requisites(
    request: Request,
    session: Session = Depends(get_db),
    admin=Depends(require_admin_user),
):
    requisites = session.query(Requisite).order_by(Requisite.employee_name).all()

    return templates.TemplateResponse(
        request,
        "requisites.html",
        {
            "requisites": requisites,
            "message": None,
            "error": None
        }
    )


@router.post("/admin/requisites/add")
def add_requisite(
    request: Request,
    employee_name: str = Form(...),
    inn: str = Form(""),
    account_number: str = Form(""),
    bik: str = Form(""),
    bank_name: str = Form(""),
    citizenship: str = Form(""),
    is_third_party: str = Form(default=""),
    recipient_name: str = Form(default=""),
    is_active: str = Form(default="on"),
    is_verified: str = Form(default=""),
    comment: str = Form(default=""),
    session: Session = Depends(get_db),
    admin=Depends(require_admin_user),
):
    employee_name_clean = normalize_text(employee_name)

    user = session.query(User).filter(
        User.employee_name == employee_name_clean
    ).first()

    req = Requisite(
        user_id=user.id if user else None,
        employee_name=employee_name_clean,
        inn=normalize_text(inn),
        account_number=normalize_text(account_number),
        bik=normalize_text(bik),
        bank_name=normalize_text(bank_name),
        citizenship=normalize_text(citizenship),
        is_third_party=(is_third_party == "on" or is_third_party == "true"),
        recipient_name=normalize_text(recipient_name) or None,
        is_active=(is_active == "on" or is_active == "true"),
        is_verified=(is_verified == "on" or is_verified == "true"),
        created_at=now_utc(),
        updated_at=now_utc(),
        verified_at=now_utc() if (is_verified == "on" or is_verified == "true") else None,
        comment=normalize_text(comment) or None
    )

    session.add(req)
    session.flush()
    create_audit_log(
        session,
        request,
        admin,
        "requisite_updated",
        "requisite",
        req.id,
        req.employee_name,
        new_value=_requisite_payload(req),
    )
    if req.is_verified:
        create_audit_log(
            session,
            request,
            admin,
            "requisite_verified",
            "requisite",
            req.id,
            req.employee_name,
            new_value={"is_verified": True, "verified_at": req.verified_at},
        )
    session.commit()

    return RedirectResponse("/admin/requisites", status_code=302)


@router.post("/admin/requisites/update")
def update_requisite(
    request: Request,
    requisite_id: int = Form(...),
    employee_name: str = Form(...),
    inn: str = Form(""),
    account_number: str = Form(""),
    bik: str = Form(""),
    bank_name: str = Form(""),
    citizenship: str = Form(""),
    is_third_party: str = Form(default=""),
    recipient_name: str = Form(default=""),
    is_active: str = Form(default=""),
    is_verified: str = Form(default=""),
    comment: str = Form(default=""),
    session: Session = Depends(get_db),
    admin=Depends(require_admin_user),
):
    req = session.query(Requisite).filter(Requisite.id == requisite_id).first()

    if not req:
        return RedirectResponse("/admin/requisites", status_code=302)

    employee_name_clean = normalize_text(employee_name)
    user = session.query(User).filter(User.employee_name == employee_name_clean).first()

    was_verified = req.is_verified
    old_value = _requisite_payload(req)

    req.user_id = user.id if user else None
    req.employee_name = employee_name_clean
    req.inn = normalize_text(inn)
    req.account_number = normalize_text(account_number)
    req.bik = normalize_text(bik)
    req.bank_name = normalize_text(bank_name)
    req.citizenship = normalize_text(citizenship)
    req.is_third_party = (is_third_party == "on" or is_third_party == "true")
    req.recipient_name = normalize_text(recipient_name) or None

    req.is_active = (is_active == "on" or is_active == "true")
    req.is_verified = (is_verified == "on" or is_verified == "true")
    req.updated_at = now_utc()

    if req.is_verified and not was_verified:
        req.verified_at = now_utc()

    if not req.is_verified:
        req.verified_at = None

    req.comment = normalize_text(comment) or None

    create_audit_log(
        session,
        request,
        admin,
        "requisite_updated",
        "requisite",
        req.id,
        req.employee_name,
        old_value=old_value,
        new_value=_requisite_payload(req),
    )
    if req.is_verified and not was_verified:
        create_audit_log(
            session,
            request,
            admin,
            "requisite_verified",
            "requisite",
            req.id,
            req.employee_name,
            old_value={"is_verified": was_verified},
            new_value={"is_verified": True, "verified_at": req.verified_at},
        )
    session.commit()

    return RedirectResponse("/admin/requisites", status_code=302)


@router.post("/admin/requisites/delete")
def delete_requisite(
    request: Request,
    requisite_id: int = Form(...),
    session: Session = Depends(get_db),
    admin=Depends(require_admin_user),
):
    req = session.query(Requisite).filter(Requisite.id == requisite_id).first()

    if req:
        create_audit_log(
            session,
            request,
            admin,
            "requisite_updated",
            "requisite",
            req.id,
            req.employee_name,
            old_value=_requisite_payload(req),
            new_value={"deleted": True},
            comment="deleted",
        )
        session.delete(req)
        session.commit()

    return RedirectResponse("/admin/requisites", status_code=302)


@router.post("/admin/requisites/upload")
def upload_requisites(
    request: Request,
    file: UploadFile = File(...),
    session: Session = Depends(get_db),
    admin=Depends(require_admin_user),
):
    try:
        df = pd.read_excel(file.file)
        df.columns = [str(c).strip() for c in df.columns]

        created = 0
        bad = 0

        column_aliases = {
            "employee_name": ["employee_name", "ФИО", "фио"],
            "inn": ["inn", "ИНН", "инн"],
            "account_number": ["account_number", "НОМЕР СЧЕТА", "номер счета", "Счет", "счет"],
            "bik": ["bik", "БИК", "бик"],
            "bank_name": ["bank_name", "НАИМЕНОВАНИЕ БАНКА", "банк", "Банк"],
            "citizenship": ["citizenship", "ГРАЖДАНСТВО", "гражданство"],
            "is_third_party": ["is_third_party", "третье лицо", "3 лицо", "третье_лицо"],
            "recipient_name": ["recipient_name", "получатель", "ФИО получателя", "фио получателя"],
            "is_active": ["is_active", "активно", "активный"],
            "is_verified": ["is_verified", "проверено", "проверен"],
            "comment": ["comment", "комментарий", "примечание"],
        }

        def get_value(row, key):
            for column in column_aliases[key]:
                if column in row:
                    value = row.get(column, "")
                    if pd.isna(value):
                        return ""
                    return normalize_text(value)
            return ""

        for _, row in df.iterrows():
            name = get_value(row, "employee_name")
            if not name:
                bad += 1
                continue

            user = session.query(User).filter(User.employee_name == name).first()

            third_party_value = get_value(row, "is_third_party").lower()
            is_third_party = third_party_value in ["да", "yes", "true", "1", "on"]

            active_value = get_value(row, "is_active").lower()
            verified_value = get_value(row, "is_verified").lower()

            is_active = True
            if active_value in ["нет", "no", "false", "0", "off"]:
                is_active = False

            is_verified = verified_value in ["да", "yes", "true", "1", "on"]

            req = Requisite(
                user_id=user.id if user else None,
                employee_name=name,
                inn=get_value(row, "inn"),
                account_number=get_value(row, "account_number"),
                bik=get_value(row, "bik"),
                bank_name=get_value(row, "bank_name"),
                citizenship=get_value(row, "citizenship"),
                is_third_party=is_third_party,
                recipient_name=get_value(row, "recipient_name") or None,
                is_active=is_active,
                is_verified=is_verified,
                created_at=now_utc(),
                updated_at=now_utc(),
                verified_at=now_utc() if is_verified else None,
                comment=get_value(row, "comment") or None
            )

            session.add(req)
            session.flush()
            create_audit_log(
                session,
                request,
                admin,
                "requisite_updated",
                "requisite",
                req.id,
                req.employee_name,
                new_value=_requisite_payload(req),
                comment="uploaded from Excel",
            )
            if req.is_verified:
                create_audit_log(
                    session,
                    request,
                    admin,
                    "requisite_verified",
                    "requisite",
                    req.id,
                    req.employee_name,
                    new_value={"is_verified": True, "verified_at": req.verified_at},
                    comment="uploaded from Excel",
                )
            created += 1

        session.commit()

        requisites = session.query(Requisite).order_by(Requisite.employee_name).all()

        return templates.TemplateResponse(
            request,
            "requisites.html",
            {
                "requisites": requisites,
                "message": f"Импорт завершён. Создано: {created}. Некорректных строк: {bad}.",
                "error": None
            }
        )

    except Exception:
        session.rollback()

        requisites = session.query(Requisite).order_by(Requisite.employee_name).all()

        return templates.TemplateResponse(
            request,
            "requisites.html",
            {
                "requisites": requisites,
                "message": None,
                "error": "Import failed"
            }
        )




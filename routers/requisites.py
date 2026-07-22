import pandas as pd
from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from access import accessible_employee_names, get_user_cities
from audit_helpers import create_audit_log
from dependencies import get_db
from inn_sync import set_employee_inn
from models import Requisite, Shift, User
from rbac import canonical_role, require_permission
from time_helpers import now_utc
from utils import is_scientific_notation, normalize_digits, normalize_text


router = APIRouter()
templates = Jinja2Templates(directory="templates")
require_requisites_view = require_permission("requisites.view", audit_denied=True)
_req_manage = require_permission("requisites.manage")


def _requisite_payload(req):
    return {
        "employee_name": req.employee_name,
        "inn": req.inn,
        "account_number": req.account_number,
        "bik": req.bik,
        "bank_name": req.bank_name,
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
    user=Depends(_req_manage),
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
    current=Depends(_req_manage),
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
        # Гражданство больше НЕ хранится в реквизитах (Блок 1 нормализации) —
        # источник истины: User.citizenship_country_id.
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
        current,
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
            current,
            "requisite_verified",
            "requisite",
            req.id,
            req.employee_name,
            new_value={"is_verified": True, "verified_at": req.verified_at},
        )
    if user is not None and req.inn:
        set_employee_inn(session, user, req.inn, source="requisite", actor=current, request=request)
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
    current=Depends(_req_manage),
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
    # Гражданство больше НЕ пишется в реквизиты (Блок 1 нормализации).
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
        current,
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
            current,
            "requisite_verified",
            "requisite",
            req.id,
            req.employee_name,
            old_value={"is_verified": was_verified},
            new_value={"is_verified": True, "verified_at": req.verified_at},
        )
    if user is not None and req.inn:
        set_employee_inn(session, user, req.inn, source="requisite", actor=current, request=request)
    session.commit()

    return RedirectResponse("/admin/requisites", status_code=302)


@router.post("/admin/requisites/delete")
def delete_requisite(
    request: Request,
    requisite_id: int = Form(...),
    session: Session = Depends(get_db),
    user=Depends(_req_manage),
):
    req = session.query(Requisite).filter(Requisite.id == requisite_id).first()

    if req:
        create_audit_log(
            session,
            request,
            user,
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
    current=Depends(_req_manage),
):
    try:
        # dtype=str — читать все колонки строками, иначе pandas превращает
        # ИНН/БИК в float (хвост .0), а 20-значный номер счёта — в научную
        # нотацию с БЕЗВОЗВРАТНОЙ потерей младших цифр.
        df = pd.read_excel(file.file, dtype=str)
        df.columns = [str(c).strip() for c in df.columns]

        created = 0
        updated = 0
        bad = 0
        unmatched_users = []
        changes_report = []
        scientific_report = []

        truthy = ["да", "yes", "true", "1", "on"]
        falsy = ["нет", "no", "false", "0", "off"]

        column_aliases = {
            "employee_name": ["employee_name", "ФИО", "фио"],
            "inn": ["inn", "ИНН", "инн"],
            "account_number": ["account_number", "НОМЕР СЧЕТА", "номер счета", "Счет", "счет"],
            "bik": ["bik", "БИК", "бик"],
            "bank_name": ["bank_name", "НАИМЕНОВАНИЕ БАНКА", "банк", "Банк"],
            "citizenship": ["citizenship", "ГРАЖДАНСТВО", "гражданство"],
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
            if not user:
                unmatched_users.append(name)

            raw_inn = get_value(row, "inn")
            raw_account = get_value(row, "account_number")
            raw_bik = get_value(row, "bik")

            # Научная нотация = уже утерянные данные (счёт схлопнулся во float).
            # Не восстанавливаем — помечаем строку в отчёте.
            sci_fields = [
                label
                for label, value in (
                    ("ИНН", raw_inn),
                    ("счёт", raw_account),
                    ("БИК", raw_bik),
                )
                if is_scientific_notation(value)
            ]
            if sci_fields:
                scientific_report.append({"name": name, "fields": ", ".join(sci_fields)})

            inn = normalize_digits(raw_inn)
            account_number = normalize_digits(raw_account)
            bik = normalize_digits(raw_bik)
            bank_name = get_value(row, "bank_name")
            # Гражданство больше НЕ пишется в реквизиты (Блок 1 нормализации) —
            # источник истины: User.citizenship_country_id.
            recipient_name = get_value(row, "recipient_name")
            comment = get_value(row, "comment")

            active_raw = get_value(row, "is_active").lower()
            verified_raw = get_value(row, "is_verified").lower()

            # Поиск существующего активного реквизита: по user_id, иначе по ФИО.
            existing = None
            if user:
                existing = session.query(Requisite).filter(
                    Requisite.user_id == user.id,
                    Requisite.is_active == True,
                ).first()
            if existing is None:
                existing = session.query(Requisite).filter(
                    Requisite.employee_name == name,
                    Requisite.is_active == True,
                ).first()

            if existing is not None:
                # Обновление: непустые ячейки обновляют, пустые не затирают.
                old_value = _requisite_payload(existing)
                was_verified = existing.is_verified
                row_changes = []

                if user and existing.user_id != user.id:
                    existing.user_id = user.id
                    row_changes.append("привязка к пользователю")

                for field, value in (
                    ("inn", inn),
                    ("account_number", account_number),
                    ("bik", bik),
                    ("bank_name", bank_name),
                    ("recipient_name", recipient_name or None),
                    ("comment", comment or None),
                ):
                    if value and getattr(existing, field) != value:
                        row_changes.append(field)
                        setattr(existing, field, value)

                # «Третье лицо» выводится из получателя: заполнен → True.
                # Считаем по ЭФФЕКТИВНОМУ значению (пустая ячейка не затирала
                # существующего получателя выше).
                new_tp = bool((existing.recipient_name or "").strip())
                if existing.is_third_party != new_tp:
                    existing.is_third_party = new_tp
                    row_changes.append("3-е лицо")

                if active_raw:
                    new_active = active_raw not in falsy
                    if existing.is_active != new_active:
                        existing.is_active = new_active
                        row_changes.append("активность")

                if verified_raw:
                    new_verified = verified_raw in truthy
                    if existing.is_verified != new_verified:
                        existing.is_verified = new_verified
                        row_changes.append("проверено")

                if existing.is_verified and not was_verified:
                    existing.verified_at = now_utc()
                if not existing.is_verified:
                    existing.verified_at = None

                if row_changes:
                    existing.updated_at = now_utc()
                    create_audit_log(
                        session,
                        request,
                        current,
                        "requisite_updated",
                        "requisite",
                        existing.id,
                        existing.employee_name,
                        old_value=old_value,
                        new_value=_requisite_payload(existing),
                        comment="updated from Excel",
                    )
                    if existing.is_verified and not was_verified:
                        create_audit_log(
                            session,
                            request,
                            current,
                            "requisite_verified",
                            "requisite",
                            existing.id,
                            existing.employee_name,
                            old_value={"is_verified": was_verified},
                            new_value={"is_verified": True, "verified_at": existing.verified_at},
                            comment="updated from Excel",
                        )
                    updated += 1
                    changes_report.append({"name": name, "changes": "; ".join(row_changes)})
                if user and inn:
                    set_employee_inn(session, user, inn, source="requisite", actor=current, request=request)
                continue

            # Создание нового реквизита.
            # «Третье лицо» выводится из получателя: заполнен → True.
            is_third_party = bool(recipient_name.strip())
            is_active = active_raw not in falsy
            is_verified = verified_raw in truthy

            req = Requisite(
                user_id=user.id if user else None,
                employee_name=name,
                inn=inn,
                account_number=account_number,
                bik=bik,
                bank_name=bank_name,
                is_third_party=is_third_party,
                recipient_name=recipient_name or None,
                is_active=is_active,
                is_verified=is_verified,
                created_at=now_utc(),
                updated_at=now_utc(),
                verified_at=now_utc() if is_verified else None,
                comment=comment or None
            )

            session.add(req)
            session.flush()
            create_audit_log(
                session,
                request,
                current,
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
                    current,
                    "requisite_verified",
                    "requisite",
                    req.id,
                    req.employee_name,
                    new_value={"is_verified": True, "verified_at": req.verified_at},
                    comment="uploaded from Excel",
                )
            if user and inn:
                set_employee_inn(session, user, inn, source="requisite", actor=current, request=request)
            created += 1

        session.commit()

        requisites = session.query(Requisite).order_by(Requisite.employee_name).all()

        return templates.TemplateResponse(
            request,
            "requisites.html",
            {
                "requisites": requisites,
                "message": f"Импорт завершён. Создано: {created}, обновлено: {updated}. Некорректных строк: {bad}.",
                "changes_report": changes_report,
                "unmatched_users": unmatched_users,
                "scientific_report": scientific_report,
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




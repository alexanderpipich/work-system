import pandas as pd
from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from audit_helpers import create_audit_log
from access_scope_helpers import active_scope_values, sync_access_scopes
from dependencies import get_db
from rbac import require_permission
from legal_entity_helpers import active_legal_entities
from models import Shift, User
from utils import (
    get_password_hash,
    normalize_phone,
    normalize_role,
    normalize_text,
)


router = APIRouter()
templates = Jinja2Templates(directory="templates")
require_user_management = require_permission("users.manage", audit_denied=True)
require_user_hard_delete = require_permission("users.hard_delete", audit_denied=True)


def _user_payload(user):
    return {
        "phone": user.phone,
        "employee_name": user.employee_name,
        "is_admin": user.is_admin,
        "role": user.role,
        "brigadier_store": user.brigadier_store,
        "economist_stores": user.economist_stores,
        "citizenship_country": user.citizenship_country,
        "legal_entity": user.legal_entity,
    }



def _default_city_scope(session, role, raw_scope):
    raw = normalize_text(raw_scope)
    if raw or role != "economist":
        return raw
    cities = [row[0] for row in session.query(Shift.city).filter(Shift.city != None).distinct().order_by(Shift.city).all() if row[0]]
    return ", ".join(cities)
def render_users(request: Request, session, message=None, error=None, filters=None):
    users = session.query(User).order_by(User.employee_name.asc()).all()
    legal_entities = active_legal_entities(session)
    return templates.TemplateResponse(
        request,
        "admin_users.html",
        {
            "users": users,
            "legal_entities": legal_entities,
            "message": message,
            "error": error,
            "filters": filters or {},
            "city_scopes": {user.id: active_scope_values(session, user.id, "city") for user in users}
        }
    )


@router.get("/admin/create-user", response_class=HTMLResponse)
def create_user_page(
    request: Request,
    session: Session = Depends(get_db),
    admin=Depends(require_user_management),
):
    return templates.TemplateResponse(
        request,
        "create_user.html",
        {
            "message": None,
            "error": None,
            "legal_entities": active_legal_entities(session),
        }
    )


@router.post("/admin/create-user", response_class=HTMLResponse)
def create_user_submit(
    request: Request,
    phone: str = Form(...),
    password: str = Form(...),
    employee_name: str = Form(...),
    role: str = Form(default="employee"),
    brigadier_store: str = Form(default=""),
    economist_stores: str = Form(default=""),
    scope_cities: str = Form(default=""),
    citizenship_country: str = Form(...),
    legal_entity: str = Form(default=""),
    session: Session = Depends(get_db),
    admin=Depends(require_user_management),
):
    phone_clean = normalize_phone(phone)
    password_clean = str(password).strip()
    employee_name_clean = normalize_text(employee_name)
    role_clean = normalize_role(role)
    scope_value = _default_city_scope(session, role_clean, scope_cities or economist_stores)
    citizenship_country_clean = normalize_text(citizenship_country)

    if not citizenship_country_clean:
        return templates.TemplateResponse(
            request,
            "create_user.html",
            {
                "error": "Гражданство обязательно",
                "message": None,
                "legal_entities": active_legal_entities(session),
            },
            status_code=400,
        )

    if session.query(User).filter(User.phone == phone_clean).first():
        return templates.TemplateResponse(
            request,
            "create_user.html",
            {
                "error": "Пользователь уже существует",
                "message": None,
                "legal_entities": active_legal_entities(session),
            }
        )

    user = User(
        phone=phone_clean,
        password_hash=get_password_hash(password_clean),
        employee_name=employee_name_clean,
        is_admin=(role_clean in {"admin", "superadmin"}),
        role=role_clean,
        brigadier_store=normalize_text(brigadier_store) or None,
        economist_stores=scope_value or None,
        citizenship_country=citizenship_country_clean,
        legal_entity=normalize_text(legal_entity) or None,
    )

    session.add(user)
    session.flush()
    sync_access_scopes(session, request, admin, user, "city", scope_value)
    create_audit_log(
        session,
        request,
        admin,
        "user_created",
        "user",
        user.id,
        user.employee_name,
        new_value=_user_payload(user),
    )
    session.commit()

    return templates.TemplateResponse(
        request,
        "create_user.html",
        {
            "message": "Пользователь создан",
            "error": None,
            "legal_entities": active_legal_entities(session),
        }
    )


@router.get("/admin/upload-users", response_class=HTMLResponse)
def upload_users_page(
    request: Request,
    admin=Depends(require_user_management),
):
    return templates.TemplateResponse(
        request,
        "upload_users.html",
        {
            "message": None,
            "error": None,
            "created": None,
            "skipped": None,
            "bad_rows": None
        }
    )


@router.post("/admin/upload-users", response_class=HTMLResponse)
async def upload_users_submit(
    request: Request,
    file: UploadFile = File(...),
    session: Session = Depends(get_db),
    admin=Depends(require_user_management),
):
    df = pd.read_excel(file.file)
    df.columns = [str(c).strip() for c in df.columns]
    citizenship_aliases = {
        "citizenship": "citizenship_country",
        "гражданство": "citizenship_country",
    }
    df = df.rename(columns={
        column: citizenship_aliases.get(column.casefold(), column)
        for column in df.columns
    })

    required = ["phone", "employee_name", "password", "citizenship_country"]
    missing = [c for c in required if c not in df.columns]

    if missing:
        return templates.TemplateResponse(
            request,
            "upload_users.html",
            {
                "error": f"В файле нет обязательных колонок: {', '.join(missing)}",
                "message": None,
                "created": None,
                "skipped": None,
                "bad_rows": None
            }
        )

    created = 0
    skipped = 0
    bad = 0

    for _, row in df.iterrows():
        try:
            phone_raw = row["phone"]
            name_raw = row["employee_name"]
            password_raw = row["password"]
            citizenship_raw = row["citizenship_country"]

            if pd.isna(phone_raw) or pd.isna(name_raw) or pd.isna(password_raw) or pd.isna(citizenship_raw):
                bad += 1
                continue

            phone_clean = normalize_phone(phone_raw)
            name_clean = normalize_text(name_raw)
            citizenship_clean = normalize_text(citizenship_raw)

            if isinstance(password_raw, float) and password_raw.is_integer():
                password_clean = str(int(password_raw))
            else:
                password_clean = str(password_raw).strip()

            if not phone_clean or not name_clean or not password_clean or not citizenship_clean:
                bad += 1
                continue

            if session.query(User).filter(User.phone == phone_clean).first():
                skipped += 1
                continue

            role_raw = row.get("role", "employee")
            role_clean = normalize_role(role_raw)
            uploaded_scope = _default_city_scope(session, role_clean, row.get("economist_stores", ""))

            user = User(
                phone=phone_clean,
                password_hash=get_password_hash(password_clean),
                employee_name=name_clean,
                is_admin=(role_clean in {"admin", "superadmin"}),
                role=role_clean,
                brigadier_store=normalize_text(row.get("brigadier_store", "")) or None,
                economist_stores=uploaded_scope or None,
                citizenship_country=citizenship_clean,
                legal_entity=normalize_text(row.get("legal_entity", "")) or None,
            )

            session.add(user)

            try:
                session.flush()
                sync_access_scopes(session, request, admin, user, "city", uploaded_scope)
                create_audit_log(
                    session,
                    request,
                    admin,
                    "user_created",
                    "user",
                    user.id,
                    user.employee_name,
                    new_value=_user_payload(user),
                    comment="uploaded from Excel",
                )
                session.commit()
                created += 1
            except IntegrityError:
                session.rollback()
                skipped += 1

        except Exception:
            session.rollback()
            bad += 1

    return templates.TemplateResponse(
        request,
        "upload_users.html",
        {
            "message": "Готово",
            "created": created,
            "skipped": skipped,
            "bad_rows": bad,
            "error": None
        }
    )



@router.get("/admin/users", response_class=HTMLResponse)
def admin_users(
    request: Request,
    user_id: str = "",
    phone: str = "",
    employee_name: str = "",
    role: str = "",
    session: Session = Depends(get_db),
    admin=Depends(require_user_management),
):
    query = session.query(User)

    if user_id.strip():
        try:
            query = query.filter(User.id == int(user_id.strip()))
        except ValueError:
            query = query.filter(User.id == -1)

    if phone.strip():
        query = query.filter(User.phone.ilike(f"%{normalize_phone(phone)}%"))

    if employee_name.strip():
        query = query.filter(User.employee_name.ilike(f"%{employee_name.strip()}%"))

    if role.strip():
        query = query.filter(User.role == normalize_role(role))

    users = query.order_by(User.employee_name.asc()).all()

    return templates.TemplateResponse(
        request,
        "admin_users.html",
        {
            "users": users,
            "legal_entities": active_legal_entities(session),
            "message": None,
            "error": None,
            "city_scopes": {user.id: active_scope_values(session, user.id, "city") for user in users},
            "filters": {
                "user_id": user_id,
                "phone": phone,
                "employee_name": employee_name,
                "role": role,
            }
        }
    )


@router.post("/admin/update-user", response_class=HTMLResponse)
def update_user(
    request: Request,
    user_id: int = Form(...),
    role: str = Form(default="employee"),
    brigadier_store: str = Form(default=""),
    economist_stores: str = Form(default=""),
    scope_cities: str = Form(default=""),
    citizenship_country: str = Form(default=""),
    legal_entity: str = Form(default=""),
    session: Session = Depends(get_db),
    admin=Depends(require_user_management),
):
    user = session.query(User).filter(User.id == user_id).first()

    if not user:
        return RedirectResponse(url="/admin/users", status_code=302)

    role_clean = normalize_role(role)
    scope_value = _default_city_scope(session, role_clean, scope_cities or economist_stores)

    old_value = _user_payload(user)
    old_role = user.role
    user.role = role_clean
    user.is_admin = role_clean in {"admin", "superadmin"}
    user.brigadier_store = normalize_text(brigadier_store) or None
    city_values = sync_access_scopes(session, request, admin, user, "city", scope_value)
    user.economist_stores = ", ".join(city_values) or None
    user.citizenship_country = normalize_text(citizenship_country) or None
    user.legal_entity = normalize_text(legal_entity) or None

    create_audit_log(
        session,
        request,
        admin,
        "user_updated",
        "user",
        user.id,
        user.employee_name,
        old_value=old_value,
        new_value=_user_payload(user),
    )
    if old_role != user.role:
        create_audit_log(
            session,
            request,
            admin,
            "user_role_changed",
            "user",
            user.id,
            user.employee_name,
            old_value={"role": old_role},
            new_value={"role": user.role},
        )
    session.commit()

    return RedirectResponse(url="/admin/users", status_code=302)


@router.post("/admin/delete-user", response_class=HTMLResponse)
def delete_user(
    request: Request,
    user_id: int = Form(...),
    session: Session = Depends(get_db),
    admin=Depends(require_user_hard_delete),
):
    user = session.query(User).filter(User.id == user_id).first()

    if not user:
        return render_users(
            request,
            session,
            error="Пользователь не найден"
        )

    create_audit_log(
        session,
        request,
        admin,
        "user_deleted",
        "user",
        user.id,
        user.employee_name,
        old_value=_user_payload(user),
    )
    session.delete(user)
    session.commit()

    return render_users(
        request,
        session,
        message="Пользователь удалён"
    )


@router.post("/admin/change-password", response_class=HTMLResponse)
def change_password(
    request: Request,
    user_id: int = Form(...),
    new_password: str = Form(...),
    session: Session = Depends(get_db),
    admin=Depends(require_user_management),
):
    user = session.query(User).filter(User.id == user_id).first()

    if not user:
        return render_users(
            request,
            session,
            error="Пользователь не найден"
        )

    new_password_clean = str(new_password).strip()
    if not new_password_clean:
        return render_users(
            request,
            session,
            error="Новый пароль не может быть пустым"
        )

    user.password_hash = get_password_hash(new_password_clean)
    session.commit()

    return render_users(
        request,
        session,
        message="Пароль изменён"
    )






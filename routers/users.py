import pandas as pd
from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from audit_helpers import create_audit_log
from access_scope_helpers import active_scope_values, sync_access_scopes
from dependencies import get_db
from inn_sync import set_employee_inn
from rbac import require_permission
from legal_entity_helpers import active_legal_entities
from models import Country, Shift, User
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
        "citizenship_country_id": getattr(user, "citizenship_country_id", None),
        "is_student": getattr(user, "is_student", False),
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
    countries = session.query(Country).filter(Country.is_active == True).order_by(Country.name).all()
    return templates.TemplateResponse(
        request,
        "admin_users.html",
        {
            "users": users,
            "legal_entities": legal_entities,
            "countries": countries,
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
            "countries": session.query(Country).filter(Country.is_active == True).order_by(Country.name).all(),
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
    citizenship_country_id: int = Form(0),
    is_student: str = Form(""),
    legal_entity: str = Form(default=""),
    session: Session = Depends(get_db),
    admin=Depends(require_user_management),
):
    phone_clean = normalize_phone(phone)
    password_clean = str(password).strip()
    employee_name_clean = normalize_text(employee_name)
    role_clean = normalize_role(role)
    scope_value = _default_city_scope(session, role_clean, scope_cities or economist_stores)

    if not citizenship_country_id:
        return templates.TemplateResponse(
            request,
            "create_user.html",
            {
                "error": "Выберите страну гражданства",
                "message": None,
                "legal_entities": active_legal_entities(session),
                "countries": session.query(Country).filter(Country.is_active == True).order_by(Country.name).all(),
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
                "countries": session.query(Country).filter(Country.is_active == True).order_by(Country.name).all(),
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
        citizenship_country_id=citizenship_country_id,
        is_student=bool(is_student),
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
            "countries": session.query(Country).filter(Country.is_active == True).order_by(Country.name).all(),
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
                "updated": None,
                "skipped": None,
                "bad_rows": None,
                "linked": None,
                "unmatched": None,
                "changes_report": None,
            }
        )

    countries = session.query(Country).filter(Country.is_active == True).all()
    country_by_name = {normalize_text(c.name).casefold(): c.id for c in countries}

    def cell_text(value):
        if value is None or pd.isna(value):
            return ""
        return normalize_text(value)

    def cell_password(value):
        if value is None or pd.isna(value):
            return ""
        if isinstance(value, float) and value.is_integer():
            return str(int(value))
        return str(value).strip()

    def cell_role(value):
        text = cell_text(value)
        return normalize_role(text) if text else None

    created = 0
    updated = 0
    skipped = 0
    bad = 0
    linked = 0
    unmatched = []
    changes_report = []

    for _, row in df.iterrows():
        try:
            phone_raw = row.get("phone")
            phone_clean = "" if (phone_raw is None or pd.isna(phone_raw)) else normalize_phone(phone_raw)
            if not phone_clean:
                bad += 1
                continue

            name_clean = cell_text(row.get("employee_name"))
            citizenship_clean = cell_text(row.get("citizenship_country"))
            matched_country_id = (
                country_by_name.get(citizenship_clean.casefold()) if citizenship_clean else None
            )
            password_clean = cell_password(row.get("password"))
            role_clean = cell_role(row.get("role"))
            brigadier_clean = cell_text(row.get("brigadier_store"))
            economist_clean = cell_text(row.get("economist_stores"))
            legal_clean = cell_text(row.get("legal_entity"))

            existing = session.query(User).filter(User.phone == phone_clean).first()

            if existing:
                # Обновление существующего: непустые ячейки обновляют, пустые не затирают.
                old_value = _user_payload(existing)
                row_changes = []

                if name_clean and name_clean != existing.employee_name:
                    row_changes.append(f"ФИО {existing.employee_name}→{name_clean}")
                    existing.employee_name = name_clean

                if role_clean and role_clean != existing.role:
                    row_changes.append(f"роль {existing.role}→{role_clean}")
                    existing.role = role_clean
                    existing.is_admin = role_clean in {"admin", "superadmin"}

                if brigadier_clean and brigadier_clean != (existing.brigadier_store or ""):
                    row_changes.append(f"магазин бригадира →{brigadier_clean}")
                    existing.brigadier_store = brigadier_clean

                if economist_clean:
                    scope_value = _default_city_scope(session, existing.role, economist_clean)
                    city_values = sync_access_scopes(session, request, admin, existing, "city", scope_value)
                    new_scope = ", ".join(city_values) or None
                    if new_scope != existing.economist_stores:
                        row_changes.append("доступ к городам обновлён")
                        existing.economist_stores = new_scope

                if citizenship_clean and citizenship_clean != (existing.citizenship_country or ""):
                    row_changes.append(f"гражданство {existing.citizenship_country or '—'}→{citizenship_clean}")
                    existing.citizenship_country = citizenship_clean

                # До-привязка к справочнику даже если строка уже была.
                if matched_country_id and existing.citizenship_country_id != matched_country_id:
                    row_changes.append("привязано к справочнику гражданств")
                    existing.citizenship_country_id = matched_country_id

                if legal_clean and legal_clean != (existing.legal_entity or ""):
                    row_changes.append(f"юрлицо →{legal_clean}")
                    existing.legal_entity = legal_clean

                # Пароль — только если в таблице явно указан непустой.
                if password_clean:
                    existing.password_hash = get_password_hash(password_clean)
                    row_changes.append("пароль обновлён")

                if row_changes:
                    create_audit_log(
                        session,
                        request,
                        admin,
                        "user_updated",
                        "user",
                        existing.id,
                        existing.employee_name,
                        old_value=old_value,
                        new_value=_user_payload(existing),
                        comment="updated from Excel",
                    )
                    session.commit()
                    updated += 1
                    changes_report.append(
                        {"name": existing.employee_name, "changes": "; ".join(row_changes)}
                    )
                else:
                    session.rollback()
                    skipped += 1
                continue

            # Создание нового — нужны ФИО, пароль и гражданство.
            if not name_clean or not password_clean or not citizenship_clean:
                bad += 1
                continue

            create_role = role_clean or "employee"
            uploaded_scope = _default_city_scope(session, create_role, economist_clean)

            user = User(
                phone=phone_clean,
                password_hash=get_password_hash(password_clean),
                employee_name=name_clean,
                is_admin=(create_role in {"admin", "superadmin"}),
                role=create_role,
                brigadier_store=brigadier_clean or None,
                economist_stores=uploaded_scope or None,
                citizenship_country=citizenship_clean,
                citizenship_country_id=matched_country_id,
                legal_entity=legal_clean or None,
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
                if matched_country_id:
                    linked += 1
                else:
                    unmatched.append({"name": name_clean, "citizenship": citizenship_clean})
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
            "updated": updated,
            "skipped": skipped,
            "bad_rows": bad,
            "linked": linked,
            "unmatched": unmatched,
            "changes_report": changes_report,
            "error": None,
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
            "countries": session.query(Country).filter(Country.is_active == True).order_by(Country.name).all(),
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
    citizenship_country_id: int = Form(0),
    is_student: str = Form(""),
    legal_entity: str = Form(default=""),
    inn: str = Form(default=""),
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
    user.citizenship_country_id = citizenship_country_id or None
    user.is_student = bool(is_student)
    user.legal_entity = normalize_text(legal_entity) or None

    inn_clean = normalize_text(inn)
    if inn_clean:
        # Пустое поле не затирает уже сохранённый ИНН (форма не всегда
        # предзаполнена) — очистка ИНН через этот экран не предусмотрена.
        set_employee_inn(session, user, inn_clean, source="profile", actor=admin, request=request)

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

    return RedirectResponse(url=f"/admin/users#user-{user_id}", status_code=302)


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






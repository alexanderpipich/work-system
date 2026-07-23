from urllib.parse import urlencode

import pandas as pd
from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from audit_helpers import create_audit_log
from access_scope_helpers import active_scope_values, sync_access_scopes
from country_helpers import build_country_matcher
from dependencies import get_db
from inn_sync import set_employee_inn
from rbac import require_permission
from legal_entity_helpers import active_legal_entities
from models import JOB_TITLES, Country, Shift, TimebookEmployee, User
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
        "job_title": getattr(user, "job_title", None),
    }



def _default_city_scope(session, role, raw_scope):
    raw = normalize_text(raw_scope)
    if raw or role != "economist":
        return raw
    cities = [row[0] for row in session.query(Shift.city).filter(Shift.city != None).distinct().order_by(Shift.city).all() if row[0]]
    return ", ".join(cities)


def pending_employees(session):
    """ФИО из смен, у которых НЕТ аккаунта User (нормализованное сравнение).

    Для каждого — подтянутые из timebook телефон/ИНН/табельный (стейджинг
    TimebookEmployee), кол-во смен и последний ТК/город для контекста.
    """
    shift_names = {
        normalize_text(e) for (e,) in session.query(Shift.employee).distinct().all() if normalize_text(e)
    }
    user_names = {
        normalize_text(n) for (n,) in session.query(User.employee_name).distinct().all() if normalize_text(n)
    }
    pending = sorted(shift_names - user_names)
    if not pending:
        return []

    counts = {
        normalize_text(emp): cnt
        for emp, cnt in session.query(Shift.employee, func.count(Shift.id)).group_by(Shift.employee).all()
    }

    last = {}
    for emp, store, city, _d in (
        session.query(Shift.employee, Shift.store, Shift.city, Shift.shift_date)
        .filter(Shift.employee.in_(pending))
        .order_by(Shift.shift_date.asc())
        .all()
    ):
        last[normalize_text(emp)] = {"store": store, "city": city}

    contacts = {
        row.employee_name: row
        for row in session.query(TimebookEmployee).filter(TimebookEmployee.employee_name.in_(pending)).all()
    }

    result = []
    for name in pending:
        c = contacts.get(name)
        result.append({
            "name": name,
            "phone": (c.phone if c else "") or "",
            "inn": (c.inn if c else "") or "",
            "tab": (c.tab_number if c else "") or "",
            "count": counts.get(name, 0),
            "last_store": last.get(name, {}).get("store") or "",
            "last_city": last.get(name, {}).get("city") or "",
            "has_phone": bool(c and c.phone),
        })
    return result
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
            "job_titles": JOB_TITLES,
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
        password_is_temporary=True,  # админ задал пароль — сотруднику предложить сменить
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

    # Матчер имя/алиас → country_id (алиасы сокращений: «РФ»→«Россия»).
    country_by_name = build_country_matcher(session)

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
                    existing.password_is_temporary = True  # задан админом → временный
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
                password_is_temporary=True,  # задан админом при загрузке → временный
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
    message: str = "",
    error: str = "",
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
            "job_titles": JOB_TITLES,
            "pending_count": len(pending_employees(session)),
            "message": message or None,
            "error": error or None,
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
    job_title: str = Form(default=""),
    f_user_id: str = Form(default=""),
    f_phone: str = Form(default=""),
    f_employee_name: str = Form(default=""),
    f_role: str = Form(default=""),
    session: Session = Depends(get_db),
    admin=Depends(require_user_management),
):
    # Опциональные f_* — текущие фильтры списка; пробрасываются в редирект, чтобы после
    # сохранения не слетать в начало несортированного списка (контракт полей данных неизменен).
    filters = {"user_id": f_user_id, "phone": f_phone, "employee_name": f_employee_name, "role": f_role}
    query = {key: value for key, value in filters.items() if value}
    redirect_base = "/admin/users"
    if query:
        redirect_base = f"{redirect_base}?{urlencode(query)}"

    user = session.query(User).filter(User.id == user_id).first()

    if not user:
        return RedirectResponse(url=redirect_base, status_code=302)

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
    # Должность: пустое ИЛИ одно из фиксированного списка; иначе не меняем.
    job_title_clean = normalize_text(job_title)
    if not job_title_clean:
        user.job_title = None
    elif job_title_clean in JOB_TITLES:
        user.job_title = job_title_clean

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

    return RedirectResponse(url=f"{redirect_base}#user-{user_id}", status_code=302)


@router.get("/admin/users/citizenship", response_class=HTMLResponse)
def users_citizenship_page(
    request: Request,
    q: str = "",
    only_missing: str = "",
    session: Session = Depends(get_db),
    admin=Depends(require_user_management),
):
    """Компактный вид массовой правки гражданства: строка на сотрудника, всё видно
    сразу (в аккордеоне /admin/users гражданство скрыто до раскрытия карточки)."""
    query = session.query(User)
    name_filter = normalize_text(q)
    if name_filter:
        query = query.filter(User.employee_name.ilike(f"%{name_filter}%"))
    if only_missing:
        query = query.filter(User.citizenship_country_id == None)

    # Без гражданства — наверх: их и надо заполнить.
    users = sorted(
        query.all(),
        key=lambda u: (u.citizenship_country_id is not None, normalize_text(u.employee_name).lower()),
    )
    countries = session.query(Country).filter(Country.is_active == True).order_by(Country.name).all()
    return templates.TemplateResponse(
        request,
        "users_citizenship.html",
        {
            "users": users,
            "countries": countries,
            "country_names": {c.id: c.name for c in countries},
            "missing_count": session.query(User).filter(User.citizenship_country_id == None).count(),
            "q": name_filter,
            "only_missing": bool(only_missing),
        },
    )


@router.post("/admin/users/{user_id}/citizenship")
def update_user_citizenship(
    request: Request,
    user_id: int,
    citizenship_country_id: int = Form(0),
    session: Session = Depends(get_db),
    admin=Depends(require_user_management),
):
    """Точечное сохранение гражданства одной строки — тем же механизмом, что update_user
    (стр. 565). Всю форму пользователя ради одного поля не гоняем."""
    user = session.query(User).filter(User.id == user_id).first()
    if not user:
        return JSONResponse({"ok": False, "error": "Сотрудник не найден"}, status_code=404)

    country = None
    if citizenship_country_id:
        country = session.query(Country).filter(
            Country.id == citizenship_country_id,
            Country.is_active == True,
        ).first()
        if not country:
            return JSONResponse({"ok": False, "error": "Страна не найдена"}, status_code=400)

    old_country_id = user.citizenship_country_id
    user.citizenship_country_id = citizenship_country_id or None

    create_audit_log(
        session,
        request,
        admin,
        "user_citizenship_updated",
        "user",
        user.id,
        user.employee_name,
        old_value={"citizenship_country_id": old_country_id},
        new_value={"citizenship_country_id": user.citizenship_country_id},
    )
    session.commit()
    return JSONResponse({
        "ok": True,
        "citizenship_country_id": user.citizenship_country_id,
        "citizenship_name": country.name if country else "",
    })


@router.get("/admin/users/pending", response_class=HTMLResponse)
def users_pending_page(
    request: Request,
    session: Session = Depends(get_db),
    admin=Depends(require_user_management),
):
    return templates.TemplateResponse(
        request,
        "users_pending.html",
        {"pending": pending_employees(session), "message": None, "error": None},
    )


@router.post("/admin/users/pending/create", response_class=HTMLResponse)
async def users_pending_create(
    request: Request,
    session: Session = Depends(get_db),
    admin=Depends(require_user_management),
):
    form = await request.form()
    password = str(form.get("new_password") or "").strip()

    if not password:
        return templates.TemplateResponse(
            request,
            "users_pending.html",
            {"pending": pending_employees(session), "message": None,
             "error": "Задайте пароль — он будет установлен всем создаваемым сотрудникам"},
        )

    try:
        row_count = int(form.get("row_count") or 0)
    except ValueError:
        row_count = 0

    created = 0
    no_phone = []
    skipped = []

    for i in range(row_count):
        if not form.get(f"sel_{i}"):
            continue
        name = normalize_text(form.get(f"name_{i}") or "")
        if not name:
            continue

        phone = normalize_phone(form.get(f"phone_{i}") or "")
        if not phone:
            no_phone.append(name)
            continue

        # Идемпотентность: уже есть по телефону ИЛИ по ФИО — пропускаем.
        exists = session.query(User).filter(
            (User.phone == phone) | (User.employee_name == name)
        ).first()
        if exists:
            skipped.append(name)
            continue

        user = User(
            phone=phone,
            password_hash=get_password_hash(password),
            employee_name=name,
            is_admin=False,
            role="employee",
            password_is_temporary=True,  # общий пароль пачки → сотруднику сменить
        )
        session.add(user)
        try:
            session.flush()
            staged = session.query(TimebookEmployee).filter(
                TimebookEmployee.employee_name == name
            ).first()
            if staged and normalize_text(staged.inn):
                set_employee_inn(session, user, staged.inn, source="timebook", actor=admin, request=request)
            create_audit_log(
                session, request, admin,
                "user_created_from_shifts", "user", user.id, user.employee_name,
                new_value=_user_payload(user), comment="created from timebook shifts",
            )
            session.commit()
            created += 1
        except IntegrityError:
            session.rollback()
            skipped.append(name)

    parts = [f"Создано: {created}"]
    if skipped:
        parts.append(f"пропущено (уже есть): {len(skipped)}")
    if no_phone:
        parts.append(f"без телефона (не создано): {len(no_phone)}")

    return templates.TemplateResponse(
        request,
        "users_pending.html",
        {"pending": pending_employees(session), "message": "; ".join(parts),
         "error": None, "no_phone": no_phone},
    )


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
    user.password_is_temporary = True  # админ задал пароль → сотруднику предложить сменить
    session.commit()

    return render_users(
        request,
        session,
        message="Пароль изменён"
    )






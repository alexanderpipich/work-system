from pathlib import Path
from typing import Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from access import accessible_employee_names
from audit_helpers import create_audit_log
from dependencies import (
    RedirectException,
    current_user,
    get_db,
)
from document_helpers import (
    INVALID_DATE_MESSAGE,
    MATRIX_COLUMNS,
    STATUS_LABELS,
    active_document_types,
    batch_employee_completeness,
    build_document_registry_rows,
    classify_document,
    computed_document_status,
    DocumentDateParseError,
    economist_employee_names,
    employee_names,
    false_green_count,
    false_green_documents,
    latest_employee_document,
    normalize_employee_folder,
    parse_bool,
    parse_date,
    MAX_DOCUMENT_PAGES,
    add_document_pages,
    document_pages,
    preview_kind,
    preview_pages,
    remove_document_page,
    save_upload_file,
    save_upload_files,
)
from file_storage import storage_delete, storage_response
from employee_profile import DOC_PATENT, format_patent_number, parse_patent_number
from models import job_title_name
from inn_sync import INN_DOCUMENT_SORT_ORDER, set_employee_inn
from models import CitizenshipRegime, Country, DocumentType, DocumentTypeSample, EmployeeDocument, EmployeeStoreAssignment, RegimeDocumentRule, Store, User
from store_helpers import extract_tk_number
from rbac import (HR_CABINET_ROLES, ROLE_HR_CLERK, ROLE_TM, canonical_role, has_permission, is_superadmin,
                  record_denied_action, scopes_enabled)
from sqlalchemy.orm import Session
from time_helpers import now_utc
from utils import normalize_text, safe_return_to


router = APIRouter()
templates = Jinja2Templates(directory="templates")
templates.env.globals["preview_kind"] = preview_kind  # П4: просмотр документа в модалке
templates.env.globals["preview_pages"] = preview_pages  # многостраничный документ — листание в модалке
templates.env.globals["MAX_DOCUMENT_PAGES"] = MAX_DOCUMENT_PAGES
templates.env.globals["job_title_name"] = job_title_name  # подпись кода должности в карточке сотрудника


SAFE_MEDIA_TYPES = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".pdf": "application/pdf",
    ".heic": "application/octet-stream",
}


def _safe_media_type(path):
    return SAFE_MEDIA_TYPES.get(Path(path).suffix.lower(), "application/octet-stream")


def _redirect(base_path, **params):
    query = {key: value for key, value in params.items() if value not in (None, "")}
    url = base_path
    if query:
        url = f"{url}?{urlencode(query)}"
    return RedirectResponse(url=url, status_code=302)


def require_document_manager(
    request: Request,
    user=Depends(current_user),
):
    if not has_permission(user, "documents.manage") and not has_permission(user, "documents.verify"):
        raise RedirectException("/")
    if request.url.path.startswith("/admin") and not is_superadmin(user):
        raise RedirectException("/")
    if request.url.path.startswith("/hr") and canonical_role(user) not in HR_CABINET_ROLES:
        raise RedirectException("/")
    return user

def _document_type_base(request):
    if request.url.path.startswith("/hr"):
        return "/hr/document-types", "/hr", "HR кабинет"
    if request.url.path.startswith("/economist"):
        return "/economist/document-types", "/economist", "Кабинет экономиста"
    return "/admin/document-types", "/admin", "Назад в админку"


def _documents_base(request):
    if request.url.path.startswith("/hr"):
        return "/hr/documents", "/hr", "HR кабинет"
    if request.url.path.startswith("/economist"):
        return "/economist/documents", "/economist", "Кабинет экономиста"
    return "/admin/documents", "/admin", "Назад в админку"


def _employee_scope(session, user, *, admin=False):
    if admin or canonical_role(user) in {"superadmin", "hr_lead", ROLE_HR_CLERK} or not scopes_enabled():
        return None
    return accessible_employee_names(session, user)


def _is_employee_allowed(employee_name, allowed_names):
    if allowed_names is None:
        return True
    return normalize_text(employee_name) in set(allowed_names)


def _render_document_types(request, session, user, message="", error=""):
    base_path, back_url, back_label = _document_type_base(request)
    document_types = session.query(DocumentType).order_by(
        DocumentType.is_active.desc(),
        DocumentType.sort_order.asc(),
        DocumentType.name.asc(),
    ).all()
    regimes = session.query(CitizenshipRegime).filter(CitizenshipRegime.is_active == True).order_by(CitizenshipRegime.sort_order, CitizenshipRegime.name).all()
    all_rules = session.query(RegimeDocumentRule).filter(RegimeDocumentRule.is_required == True).all()
    doc_regime_map = {}
    for rule in all_rules:
        doc_regime_map.setdefault(rule.document_type_id, set()).add(rule.regime_id)
    all_samples = session.query(DocumentTypeSample).order_by(
        DocumentTypeSample.document_type_id,
        DocumentTypeSample.sort_order,
        DocumentTypeSample.uploaded_at,
    ).all()
    doc_samples_map = {}
    for s in all_samples:
        doc_samples_map.setdefault(s.document_type_id, []).append(s)
    return templates.TemplateResponse(
        request,
        "document_types.html",
        {
            "user": user,
            "is_superadmin_user": is_superadmin(user),
            "document_types": document_types,
            "regimes": regimes,
            "doc_regime_map": doc_regime_map,
            "doc_samples_map": doc_samples_map,
            "base_path": base_path,
            "back_url": back_url,
            "back_label": back_label,
            "message": message or None,
            "error": error or None,
        },
    )


async def _save_sample_files(session, document_type, sample_files):
    for sample_file in sample_files:
        if not sample_file or not sample_file.filename:
            continue
        path, original_filename = await save_upload_file(
            sample_file,
            "document_type_samples",
            f"type_{document_type.id}",
        )
        if path:
            session.add(DocumentTypeSample(
                document_type_id=document_type.id,
                file_path=path,
                original_filename=original_filename,
            ))


def _apply_document_type_fields(
    document_type,
    *,
    name,
    description,
    help_text,
    requires_number,
    requires_issue_date,
    requires_expiry_date,
    allow_permanent,
    extra_field_1_label,
    extra_field_2_label,
    is_required,
    is_active,
    sort_order=0,
    is_student_doc=False,
):
    document_type.name = normalize_text(name)
    document_type.description = normalize_text(description) or None
    document_type.help_text = normalize_text(help_text) or None
    document_type.requires_number = parse_bool(requires_number)
    document_type.requires_issue_date = parse_bool(requires_issue_date)
    document_type.requires_expiry_date = parse_bool(requires_expiry_date)
    document_type.allow_permanent = parse_bool(allow_permanent)
    document_type.extra_field_1_label = normalize_text(extra_field_1_label) or None
    document_type.extra_field_2_label = normalize_text(extra_field_2_label) or None
    document_type.is_required = parse_bool(is_required)
    document_type.is_active = parse_bool(is_active)
    document_type.sort_order = int(sort_order or 0)
    document_type.is_student_doc = parse_bool(is_student_doc)


def _document_type_payload(document_type):
    return {
        "name": document_type.name,
        "description": document_type.description,
        "help_text": document_type.help_text,
        "sample_image_path": document_type.sample_image_path,
        "citizenship_filter": document_type.citizenship_filter,
        "requires_number": document_type.requires_number,
        "requires_issue_date": document_type.requires_issue_date,
        "requires_expiry_date": document_type.requires_expiry_date,
        "allow_permanent": document_type.allow_permanent,
        "extra_field_1_label": document_type.extra_field_1_label,
        "extra_field_2_label": document_type.extra_field_2_label,
        "is_required": document_type.is_required,
        "is_active": document_type.is_active,
    }


def _render_documents(
    request,
    session,
    user,
    *,
    allowed_names=None,
    employee_name="",
    document_type_id=0,
    employee_card=None,
    status="pending_verification",
    message="",
    error="",
):
    base_path, back_url, back_label = _documents_base(request)
    employees = employee_names(session) if allowed_names is None else allowed_names
    document_type_id = int(document_type_id or 0)
    rows = build_document_registry_rows(
        session,
        employees,
        employee_name=employee_name,
        document_type_id=document_type_id,
        status=status,
    )
    document_types = session.query(DocumentType).filter(
        DocumentType.is_active == True
    ).order_by(DocumentType.name.asc()).all()
    return templates.TemplateResponse(
        request,
        "documents.html",
        {
            "user": user,
            "view": "registry",
            "rows": rows,
            "employees": employees,
            "document_types": document_types,
            "status_labels": STATUS_LABELS,
            "employee_name": normalize_text(employee_name),
            "document_type_id": document_type_id,
            "status": status,
            "base_path": base_path,
            # «Добавить» в строке «Не загружен» и подписи полей по типу в «Добавить документ вручную»
            "can_manage_documents": has_permission(user, "documents.manage"),
            "type_fields": {t.id: {"extra1": t.extra_field_1_label or "", "extra2": t.extra_field_2_label or "",
                                   "patent": t.name == DOC_PATENT, "permanent": bool(t.allow_permanent),
                                   "expiry": bool(t.requires_expiry_date)} for t in document_types},
            "back_url": back_url,
            "back_label": back_label,
            "message": message or None,
            "error": error or None,
            **(employee_card or {}),
        },
    )


def _employee_card_context(session, current, user):
    """П4: блок «Данные сотрудника» над реестром его документов."""
    from employee_profile import employee_profile
    from legal_entity_helpers import active_legal_entities
    from models import JOB_TITLES
    from rbac import TM_ROLE_VALUES

    return {
        "card": employee_profile(session, user),
        "countries": session.query(Country).filter(Country.is_active == True).order_by(Country.name).all(),  # noqa: E712
        "tm_users": session.query(User).filter(User.role.in_(TM_ROLE_VALUES)).order_by(User.employee_name).all(),
        "legal_entities": active_legal_entities(session),
        "job_titles": JOB_TITLES,
        "can_edit": has_permission(current, "documents.manage"),
    }


def _render_matrix(request, session, user, *, tk_filter="", name_filter=""):
    from collections import defaultdict
    stores = session.query(Store).filter(Store.is_active == True).order_by(Store.tk_number).all()
    store_by_tk = {s.tk_number: s for s in stores}

    # All role='employee' users — single query; used for resolving assignments and "Без ТК"
    all_employees = (
        session.query(User)
        .filter(User.role == "employee")
        .order_by(User.employee_name)
        .all()
    )
    emp_by_id = {u.id: u for u in all_employees}
    emp_by_name = {normalize_text(u.employee_name): u for u in all_employees}

    assignments = session.query(EmployeeStoreAssignment).filter(EmployeeStoreAssignment.is_active == True).all()
    tk_groups: dict = defaultdict(list)
    assigned_user_ids: set = set()
    for a in assignments:
        tk = extract_tk_number(a.store)
        if not tk:
            continue
        u = (emp_by_id.get(a.user_id) if a.user_id else None) or emp_by_name.get(normalize_text(a.employee_name))
        if u:
            tk_groups[tk].append(u)
            assigned_user_ids.add(u.id)

    if tk_filter:
        try:
            tk_int = int(tk_filter)
            tk_groups = {tk_int: list(tk_groups.get(tk_int, []))}
        except ValueError:
            tk_groups = {}

    groups = []
    for tk in sorted(tk_groups):
        seen_ids: set = set()
        employees = []
        for u in tk_groups[tk]:
            if u.id in seen_ids:
                continue
            if name_filter and name_filter.lower() not in u.employee_name.lower():
                continue
            seen_ids.add(u.id)
            employees.append(u)
        if employees:
            groups.append({"tk_number": tk, "store": store_by_tk.get(tk), "employees": employees})

    # Employees with no active assignment → "Без ТК" group at the end (only when no tk_filter)
    if not tk_filter:
        no_tk = [
            u for u in all_employees
            if u.id not in assigned_user_ids
            and (not name_filter or name_filter.lower() in u.employee_name.lower())
        ]
        if no_tk:
            groups.append({"tk_number": None, "store": None, "employees": no_tk})

    all_users = [u for g in groups for u in g["employees"]]
    completeness_map = batch_employee_completeness(session, all_users)

    return templates.TemplateResponse(
        request,
        "documents.html",
        {
            "user": user,
            "view": "matrix",
            "groups": groups,
            "completeness_map": completeness_map,
            "matrix_columns": MATRIX_COLUMNS,
            "false_green_count": false_green_count(session),
            "stores": stores,
            "tk_filter": tk_filter,
            "name_filter": name_filter,
            "base_path": "/admin/documents",
            "back_url": "/admin",
            "back_label": "Назад в админку",
            "message": None,
            "error": None,
        },
    )


def _matrix_cell_payload(document):
    """Состояние клетки матрицы после отметки/снятия. Статус считает общая
    `classify_document` — своей статус-логики здесь нет."""
    return {
        "ok": True,
        "status": classify_document(document),
        "document_id": document.id if document else None,
        "marked": document is not None,
        "expiry_date": document.expiry_date.isoformat() if document and document.expiry_date else "",
        "permanent": bool(document.is_permanent) if document else False,
    }


@router.post("/admin/documents/matrix/toggle")
def admin_documents_matrix_toggle(
    request: Request,
    user_id: int = Form(...),
    document_type_id: int = Form(...),
    action: str = Form("mark"),
    expiry_date: str = Form(""),
    permanent: str = Form(""),
    session: Session = Depends(get_db),
    user=Depends(require_document_manager),
):
    """Отметка «документ есть» без загрузки файла (и снятие такой отметки).

    Флаги типа развязаны: при обоих включённых (`requires_expiry_date` И
    `allow_permanent`) отметка даёт ВЫБОР — ввести дату ИЛИ отметить «бессрочно»
    (`permanent=1`). «Бессрочно» доступно только если тип его разрешает
    (`allow_permanent`); иначе нужна дата. Записи со сканом (`file_path`) не трогаются.
    """
    employee = session.query(User).filter(User.id == user_id).first()
    if not employee:
        return JSONResponse({"ok": False, "error": "Сотрудник не найден"}, status_code=404)

    document_type = session.query(DocumentType).filter(
        DocumentType.id == document_type_id,
        DocumentType.is_active == True,
    ).first()
    if not document_type:
        return JSONResponse({"ok": False, "error": "Тип документа не найден"}, status_code=404)

    employee_name = normalize_text(employee.employee_name)
    document = latest_employee_document(session, employee_name, document_type.id)
    if document is not None and document.file_path:
        return JSONResponse(
            {"ok": False, "error": "У документа загружен файл — меняйте его в карточке документа: реестр → «Открыть»"},
            status_code=400,
        )

    if action == "unmark":
        if document is None:
            return JSONResponse(_matrix_cell_payload(None))
        document_id = document.id
        old_value = {"status": document.status, "expiry_date": str(document.expiry_date or "")}
        session.delete(document)
        create_audit_log(
            session,
            request,
            user,
            "document_mark_removed",
            "employee_document",
            document_id,
            f"{employee_name} / {document_type.name}",
            old_value=old_value,
        )
        session.commit()
        return JSONResponse(_matrix_cell_payload(None))

    if parse_bool(permanent):
        # «Бессрочно» разрешено только если тип это допускает — иначе обходили бы
        # требование срока (и такую запись потом ловит диагностика ложно-зелёных).
        if not document_type.allow_permanent:
            return JSONResponse(
                {"ok": False, "error": f"Тип «{document_type.name}» требует срок действия — «бессрочно» недоступно"},
                status_code=400,
            )
        parsed_expiry = None
        is_permanent = True
    elif document_type.requires_expiry_date:
        try:
            parsed_expiry = parse_date(expiry_date)
        except DocumentDateParseError:
            return JSONResponse({"ok": False, "error": INVALID_DATE_MESSAGE, "needs_expiry": True}, status_code=400)
        if not parsed_expiry:
            return JSONResponse(
                {"ok": False, "error": f"Для документа «{document_type.name}» нужна дата окончания", "needs_expiry": True},
                status_code=400,
            )
        is_permanent = False
    else:
        parsed_expiry = None
        is_permanent = bool(document_type.allow_permanent)

    if document is None:
        document = EmployeeDocument(
            user_id=employee.id,
            employee_name=employee_name,
            document_type_id=document_type.id,
            uploaded_by=user.id,
            uploaded_at=now_utc(),
        )
        session.add(document)

    document.expiry_date = parsed_expiry
    document.is_permanent = is_permanent
    document.file_path = None
    document.original_filename = None
    document.status = "verified"
    document.verified_by = user.id
    document.verified_at = now_utc()
    document.updated_at = now_utc()
    session.flush()

    create_audit_log(
        session,
        request,
        user,
        "document_marked_manually",
        "employee_document",
        document.id,
        f"{employee_name} / {document_type.name}",
        new_value={
            "employee_name": employee_name,
            "document_type_id": document_type.id,
            "status": document.status,
            "expiry_date": str(parsed_expiry or ""),
            "is_permanent": is_permanent,
        },
    )
    session.commit()
    return JSONResponse(_matrix_cell_payload(document))


async def _create_employee_document(
    session,
    request,
    user,
    *,
    base_path,
    allowed_names,
    employee_name,
    document_type_id,
    document_number,
    issue_date,
    expiry_date,
    is_permanent,
    extra_field_1_value,
    extra_field_2_value,
    file,
    comment,
    status="pending_verification",
):
    employee_name_clean = normalize_text(employee_name)
    if not _is_employee_allowed(employee_name_clean, allowed_names):
        return _redirect(base_path, error="Нет доступа к сотруднику")

    document_type = session.query(DocumentType).filter(
        DocumentType.id == document_type_id,
        DocumentType.is_active == True,
    ).first()
    if not document_type:
        return _redirect(base_path, error="Тип документа не найден")

    try:
        parsed_issue_date = parse_date(issue_date)
        parsed_expiry_date = None if parse_bool(is_permanent) else parse_date(expiry_date)
    except DocumentDateParseError:
        return _redirect(base_path, error=INVALID_DATE_MESSAGE)

    user_row = session.query(User).filter(User.employee_name == employee_name_clean).first()
    folder = f"employee_documents/{user_row.id if user_row else normalize_employee_folder(employee_name_clean)}"
    # Несколько файлов — страницы одного документа (регистрация на 3 листа — 3 фото).
    saved = await save_upload_files(file if isinstance(file, list) else [file], folder, f"type_{document_type.id}")
    file_path, original_filename = saved[0] if saved else (None, None)

    document = EmployeeDocument(
        user_id=user_row.id if user_row else None,
        employee_name=employee_name_clean,
        document_type_id=document_type.id,
        document_number=normalize_text(document_number) or None,
        issue_date=parsed_issue_date,
        expiry_date=parsed_expiry_date,
        is_permanent=parse_bool(is_permanent),
        extra_field_1_value=normalize_text(extra_field_1_value) or None,
        extra_field_2_value=normalize_text(extra_field_2_value) or None,
        file_path=file_path,
        original_filename=original_filename,
        status=status,
        comment=normalize_text(comment) or None,
        uploaded_by=user.id,
        uploaded_at=now_utc(),
    )
    session.add(document)
    add_document_pages(document, saved[1:], user.id)
    session.flush()
    create_audit_log(
        session,
        request,
        user,
        "document_uploaded",
        "employee_document",
        document.id,
        f"{document.employee_name} / {document_type.name}",
        new_value={
            "employee_name": document.employee_name,
            "document_type_id": document.document_type_id,
            "status": document.status,
            "original_filename": document.original_filename,
            "pages": len(saved),
        },
        comment=document.comment,
    )
    # Синхронизация ИНН (Блок 2 нормализации): только для документа типа ИНН,
    # только если найден User и указан номер.
    if user_row is not None and document.document_number and document_type.sort_order == INN_DOCUMENT_SORT_ORDER:
        set_employee_inn(session, user_row, document.document_number, source="document", actor=user, request=request)
    session.commit()
    return _redirect(base_path, message="Документ загружен")


def _document_allowed_for_user(session, document, user):
    if not document:
        return False
    if canonical_role(user) in {"superadmin", "hr_lead", ROLE_HR_CLERK}:
        return True
    if canonical_role(user) in {"economist", ROLE_TM}:
        if not scopes_enabled():
            return True
        allowed = accessible_employee_names(session, user)
        return _is_employee_allowed(document.employee_name, allowed)
    return normalize_text(document.employee_name) == normalize_text(user.employee_name)


# П5.2: из бланка и профессии патента собираются договор и ходатайство — без них патент не проверяется.
PATENT_VERIFY_FIELDS = (("blank_series", "серия бланка"), ("blank_number", "номер бланка"))


def patent_missing_fields(session, document):
    """Пустые поля патента, без которых его нельзя отметить проверенным; [] — можно (или не патент)."""
    document_type = session.get(DocumentType, document.document_type_id) if document else None
    if document_type is None or document_type.name != DOC_PATENT:
        return []
    parts = parse_patent_number(document.document_number)
    missing = [label for key, label in PATENT_VERIFY_FIELDS if not parts[key]]
    if not normalize_text(document.extra_field_2_value):
        missing.append((document_type.extra_field_2_label or "профессия по патенту").lower())
    return missing


def patent_missing_message(missing):
    return "Патент нельзя отметить проверенным: не заполнено — " + ", ".join(missing) + \
        ". Заполните в карточке документа («Открыть»)."


def _set_document_status(document, user, new_status, comment=""):
    """Сменить статус документа (без аудита и commit). Возвращает (старый статус, старый комментарий)."""
    old_status = document.status
    old_comment = document.comment
    document.status = new_status
    document.comment = normalize_text(comment) or document.comment
    document.updated_at = now_utc()
    if new_status == "verified":
        document.verified_by = user.id
        document.verified_at = now_utc()
    return old_status, old_comment


def _change_document_status(
    request,
    session,
    user,
    *,
    document_id,
    new_status,
    status_filter,
    employee_name,
    comment="",
):

    base_path, _, _ = _documents_base(request)
    document = session.query(EmployeeDocument).filter(
        EmployeeDocument.id == document_id
    ).first()
    if not _document_allowed_for_user(session, document, user):
        return _redirect(base_path, status=status_filter, employee_name=employee_name, error="Нет доступа к документу")
    missing = patent_missing_fields(session, document) if new_status == "verified" else []
    if missing:
        return _redirect(base_path, status=status_filter, employee_name=employee_name,
                         error=patent_missing_message(missing))

    old_status, old_comment = _set_document_status(document, user, new_status, comment)
    action = {
        "verified": "document_verified",
        "rejected": "document_rejected",
        "archived": "document_archived",
    }.get(new_status, "document_updated")
    create_audit_log(
        session,
        request,
        user,
        action,
        "employee_document",
        document.id,
        document.employee_name,
        old_value={"status": old_status, "comment": old_comment},
        new_value={"status": document.status, "comment": document.comment},
    )
    session.commit()
    return _redirect(base_path, status=status_filter, employee_name=employee_name, message="Статус документа обновлен")



@router.get("/admin/document-types", response_class=HTMLResponse)
def admin_document_types(
    request: Request,
    message: str = "",
    error: str = "",
    session: Session = Depends(get_db),
    user=Depends(require_document_manager),
):
    return _render_document_types(request, session, user, message, error)


@router.get("/economist/document-types", response_class=HTMLResponse)
@router.get("/hr/document-types", response_class=HTMLResponse)
def economist_document_types(
    request: Request,
    message: str = "",
    error: str = "",
    session: Session = Depends(get_db),
    user=Depends(require_document_manager),
):
    return _render_document_types(request, session, user, message, error)


@router.post("/admin/document-types/add")
@router.post("/economist/document-types/add")
@router.post("/hr/document-types/add")
async def add_document_type(
    request: Request,
    name: str = Form(...),
    description: str = Form(default=""),
    help_text: str = Form(default=""),
    regime_ids: list[int] = Form(default=[]),
    requires_number: str = Form(default=""),
    requires_issue_date: str = Form(default=""),
    requires_expiry_date: str = Form(default=""),
    allow_permanent: str = Form(default=""),
    extra_field_1_label: str = Form(default=""),
    extra_field_2_label: str = Form(default=""),
    is_required: str = Form(default=""),
    is_active: str = Form(default="1"),
    sort_order: int = Form(default=0),
    is_student_doc: str = Form(default=""),
    sample_files: list[UploadFile] = File(default=[]),
    session: Session = Depends(get_db),
    user=Depends(require_document_manager),
):
    base_path, _, _ = _document_type_base(request)
    try:

        if not normalize_text(name):
            return _redirect(base_path, error="Название обязательно")

        document_type = DocumentType(created_at=now_utc())
        _apply_document_type_fields(
            document_type,
            name=name,
            description=description,
            help_text=help_text,
            requires_number=requires_number,
            requires_issue_date=requires_issue_date,
            requires_expiry_date=requires_expiry_date,
            allow_permanent=allow_permanent,
            extra_field_1_label=extra_field_1_label,
            extra_field_2_label=extra_field_2_label,
            is_required=is_required,
            is_active=is_active,
            sort_order=sort_order,
            is_student_doc=is_student_doc,
        )
        session.add(document_type)
        session.flush()
        for rid in regime_ids:
            session.add(RegimeDocumentRule(regime_id=rid, document_type_id=document_type.id, is_required=True))
        await _save_sample_files(session, document_type, sample_files)
        create_audit_log(
            session,
            request,
            user,
            "document_type_created",
            "document_type",
            document_type.id,
            document_type.name,
            new_value=_document_type_payload(document_type),
        )
        session.commit()
        return _redirect(base_path, message="Тип документа добавлен")
    except Exception as exc:
        session.rollback()
        return _redirect(base_path, error=str(exc))


@router.post("/admin/document-types/update")
@router.post("/economist/document-types/update")
@router.post("/hr/document-types/update")
async def update_document_type(
    request: Request,
    type_id: int = Form(...),
    name: str = Form(...),
    description: str = Form(default=""),
    help_text: str = Form(default=""),
    regime_ids: list[int] = Form(default=[]),
    requires_number: str = Form(default=""),
    requires_issue_date: str = Form(default=""),
    requires_expiry_date: str = Form(default=""),
    allow_permanent: str = Form(default=""),
    extra_field_1_label: str = Form(default=""),
    extra_field_2_label: str = Form(default=""),
    is_required: str = Form(default=""),
    is_active: str = Form(default=""),
    sort_order: int = Form(default=0),
    is_student_doc: str = Form(default=""),
    sample_files: list[UploadFile] = File(default=[]),
    session: Session = Depends(get_db),
    user=Depends(require_document_manager),
):
    base_path, _, _ = _document_type_base(request)
    try:

        document_type = session.query(DocumentType).filter(DocumentType.id == type_id).first()
        if not document_type:
            return _redirect(base_path, error="Тип документа не найден")

        old_value = _document_type_payload(document_type)
        _apply_document_type_fields(
            document_type,
            name=name,
            description=description,
            help_text=help_text,
            requires_number=requires_number,
            requires_issue_date=requires_issue_date,
            requires_expiry_date=requires_expiry_date,
            allow_permanent=allow_permanent,
            extra_field_1_label=extra_field_1_label,
            extra_field_2_label=extra_field_2_label,
            is_required=is_required,
            is_active=is_active,
            sort_order=sort_order,
            is_student_doc=is_student_doc,
        )
        selected_regime_ids = set(regime_ids)
        existing_rules = {r.regime_id: r for r in session.query(RegimeDocumentRule).filter(
            RegimeDocumentRule.document_type_id == type_id
        ).all()}
        all_regime_ids = {r.id for r in session.query(CitizenshipRegime).all()}
        for rid in all_regime_ids:
            is_req = rid in selected_regime_ids
            if rid in existing_rules:
                existing_rules[rid].is_required = is_req
            elif is_req:
                session.add(RegimeDocumentRule(regime_id=rid, document_type_id=type_id, is_required=True))
        document_type.updated_at = now_utc()
        await _save_sample_files(session, document_type, sample_files)
        create_audit_log(
            session,
            request,
            user,
            "document_type_updated",
            "document_type",
            document_type.id,
            document_type.name,
            old_value=old_value,
            new_value=_document_type_payload(document_type),
        )
        session.commit()
        return _redirect(base_path, message="Тип документа обновлен")
    except Exception as exc:
        session.rollback()
        return _redirect(base_path, error=str(exc))


@router.post("/admin/document-types/delete")
@router.post("/economist/document-types/delete")
@router.post("/hr/document-types/delete")
def delete_document_type(
    request: Request,
    type_id: int = Form(...),
    session: Session = Depends(get_db),
    user=Depends(require_document_manager),
):
    base_path, _, _ = _document_type_base(request)

    document_type = session.query(DocumentType).filter(DocumentType.id == type_id).first()
    if document_type:
        old_value = _document_type_payload(document_type)
        document_type.is_active = False
        document_type.updated_at = now_utc()
        create_audit_log(
            session,
            request,
            user,
            "document_type_updated",
            "document_type",
            document_type.id,
            document_type.name,
            old_value=old_value,
            new_value=_document_type_payload(document_type),
            comment="deactivated",
        )
        session.commit()
    return _redirect(base_path, message="Тип документа деактивирован")


@router.post("/admin/document-types/delete-sample")
def delete_document_type_sample(
    request: Request,
    type_id: int = Form(...),
    session: Session = Depends(get_db),
    user=Depends(require_document_manager),
):
    base_path, _, _ = _document_type_base(request)
    document_type = session.query(DocumentType).filter(DocumentType.id == type_id).first()
    if not document_type:
        return _redirect(base_path, error="Тип документа не найден")
    if document_type.sample_image_path:
        storage_delete(document_type.sample_image_path)
        document_type.sample_image_path = None
        document_type.updated_at = now_utc()
        create_audit_log(
            session, request, user,
            "document_type_updated", "document_type",
            document_type.id, document_type.name,
            comment="sample_deleted",
        )
        session.commit()
    return _redirect(base_path, message="Образец удалён")


@router.post("/admin/document-types/hard-delete")
def hard_delete_document_type(
    request: Request,
    type_id: int = Form(...),
    session: Session = Depends(get_db),
    user=Depends(require_document_manager),
):
    base_path, _, _ = _document_type_base(request)
    document_type = session.query(DocumentType).filter(DocumentType.id == type_id).first()
    if not document_type:
        return _redirect(base_path, error="Тип документа не найден")

    from models import EmployeeDocument
    doc_count = session.query(EmployeeDocument).filter(EmployeeDocument.document_type_id == type_id).count()
    if doc_count > 0:
        return _redirect(base_path, error=f"Нельзя удалить: у {doc_count} документов сотрудников указан этот тип. Сначала деактивируйте.")

    session.query(RegimeDocumentRule).filter(RegimeDocumentRule.document_type_id == type_id).delete()
    name = document_type.name
    session.delete(document_type)
    create_audit_log(
        session, request, user,
        "document_type_deleted", "document_type",
        type_id, name,
    )
    session.commit()
    return _redirect(base_path, message=f"Тип документа «{name}» удалён")


@router.get("/admin/documents", response_class=HTMLResponse)
def admin_documents(
    request: Request,
    view: str = "registry",
    tk_filter: str = "",
    name_filter: str = "",
    employee_name: str = "",
    document_type_id: int = 0,
    status: str = "pending_verification",
    message: str = "",
    error: str = "",
    session: Session = Depends(get_db),
    user=Depends(require_document_manager),
):
    if view == "matrix":
        return _render_matrix(request, session, user, tk_filter=tk_filter, name_filter=name_filter)
    return _render_documents(
        request,
        session,
        user,
        employee_name=employee_name,
        document_type_id=document_type_id,
        status=status,
        message=message,
        error=error,
    )


@router.get("/economist/documents", response_class=HTMLResponse)
@router.get("/hr/documents", response_class=HTMLResponse)
def economist_documents(
    request: Request,
    employee_name: str = "",
    document_type_id: int = 0,
    status: str = "pending_verification",
    message: str = "",
    error: str = "",
    session: Session = Depends(get_db),
    user=Depends(require_document_manager),
):
    return _render_documents(
        request,
        session,
        user,
        allowed_names=_employee_scope(session, user),
        employee_name=employee_name,
        document_type_id=document_type_id,
        status=status,
        message=message,
        error=error,
    )


@router.get("/admin/documents/employee/{user_id}", response_class=HTMLResponse)
@router.get("/hr/documents/employee/{user_id}", response_class=HTMLResponse)
def admin_employee_documents(
    request: Request,
    user_id: int,
    message: str = "",
    error: str = "",
    session: Session = Depends(get_db),
    current=Depends(require_document_manager),
):
    base_path, _, _ = _documents_base(request)
    user = session.query(User).filter(User.id == user_id).first()
    if not user:
        return RedirectResponse(url=f"{base_path}?error=Сотрудник не найден", status_code=302)
    return _render_documents(
        request,
        session,
        current,
        employee_name=user.employee_name,
        status="all",
        message=message,
        error=error,
        employee_card=_employee_card_context(session, current, user),
    )


@router.post("/admin/documents/employee/{user_id}/profile")
@router.post("/hr/documents/employee/{user_id}/profile")
def save_employee_profile(
    request: Request,
    user_id: int,
    gender: str = Form(default=""),
    birth_date: str = Form(default=""),
    citizenship_country_id: int = Form(0),
    inn: str = Form(default=""),
    job_title: str = Form(default=""),
    tm_id: int = Form(0),
    legal_entity: str = Form(default=""),
    session: Session = Depends(get_db),
    current=Depends(require_document_manager),
):
    """П4: правка полей сотрудника из карточки документов (источник данных договора)."""
    from datetime import date as date_type

    from legal_entity_helpers import active_legal_entities
    from models import JOB_TITLES
    from rbac import TM_ROLE_VALUES

    base_path, _, _ = _documents_base(request)
    card_url = f"{base_path}/employee/{user_id}"
    if not has_permission(current, "documents.manage"):
        return _redirect(card_url, error="Нет права менять данные сотрудника")
    user = session.query(User).filter(User.id == user_id).first()
    if not user:
        return _redirect(base_path, error="Сотрудник не найден")

    fields = ("gender", "birth_date", "citizenship_country_id", "job_title", "tm_id", "legal_entity")
    old_value = {f: getattr(user, f) for f in fields}
    user.gender = gender if gender in {"m", "f"} else None
    try:
        user.birth_date = date_type.fromisoformat(birth_date) if normalize_text(birth_date) else None
    except ValueError:
        return _redirect(card_url, error="Некорректная дата рождения")
    if citizenship_country_id and session.get(Country, citizenship_country_id):
        user.citizenship_country_id = citizenship_country_id
    elif not citizenship_country_id:
        user.citizenship_country_id = None
    user.job_title = job_title if job_title in JOB_TITLES else None
    tm_ids = {tm.id for tm in session.query(User).filter(User.role.in_(TM_ROLE_VALUES)).all()}
    user.tm_id = tm_id if tm_id in tm_ids and tm_id != user.id else None
    names = {e.name for e in active_legal_entities(session)}
    user.legal_entity = legal_entity if legal_entity in names else (None if not legal_entity else user.legal_entity)
    new_value = {f: getattr(user, f) for f in fields}
    if new_value != old_value:
        create_audit_log(session, request, current, "user_updated", "user", user.id, user.employee_name,
                         old_value=old_value, new_value=new_value, comment="карточка документов сотрудника")
    if normalize_text(inn) and normalize_text(inn) != normalize_text(user.inn):
        set_employee_inn(session, user, normalize_text(inn), source="profile", actor=current, request=request)
    session.commit()
    return _redirect(card_url, message="Данные сотрудника сохранены")


@router.get("/admin/documents/diagnostics", response_class=HTMLResponse)
def admin_documents_diagnostics(
    request: Request,
    type_id: int = 0,
    session: Session = Depends(get_db),
    user=Depends(require_document_manager),
):
    """Диагностика «ложно-зелёных»: помечены бессрочными при снятом флаге срока,
    а тип теперь требует срок и бессрочность недоступна. Только показывает —
    ничего не чинит; дозаполняет срок человек (через матрицу или карточку)."""
    pairs = false_green_documents(session, type_id or None)

    rows = []
    groups: dict = {}
    for doc, dtype in pairs:
        rows.append(
            {
                "employee_name": doc.employee_name,
                "user_id": doc.user_id,
                "type_name": dtype.name,
            }
        )
        g = groups.setdefault(dtype.id, {"name": dtype.name, "count": 0})
        g["count"] += 1

    # Все типы, у которых есть ложно-зелёные — для фильтра (без учёта текущего фильтра).
    all_pairs = false_green_documents(session) if type_id else pairs
    filter_types: dict = {}
    for _doc, dtype in all_pairs:
        filter_types.setdefault(dtype.id, dtype.name)

    no_file_count = (
        session.query(EmployeeDocument)
        .filter(EmployeeDocument.file_path.is_(None))
        .count()
    )

    return templates.TemplateResponse(
        request,
        "documents_diagnostics.html",
        {
            "user": user,
            "rows": rows,
            "groups": sorted(groups.values(), key=lambda g: (-g["count"], g["name"])),
            "total": len(rows),
            "filter_types": sorted(filter_types.items(), key=lambda kv: kv[1]),
            "type_id": type_id,
            "no_file_count": no_file_count,
            "back_url": "/admin/documents?view=matrix",
        },
    )


@router.post("/admin/documents/upload")
@router.post("/economist/documents/upload")
@router.post("/hr/documents/upload")
async def upload_employee_document_by_manager(
    request: Request,
    employee_name: str = Form(...),
    document_type_id: int = Form(...),
    document_number: str = Form(default=""),
    patent_parts: str = Form(default=""),
    patent_series: str = Form(default=""),
    patent_number: str = Form(default=""),
    patent_blank_series: str = Form(default=""),
    patent_blank_number: str = Form(default=""),
    issue_date: str = Form(default=""),
    expiry_date: str = Form(default=""),
    is_permanent: str = Form(default=""),
    extra_field_1_value: str = Form(default=""),
    extra_field_2_value: str = Form(default=""),
    comment: str = Form(default=""),
    file: list[UploadFile] = File(default=[]),
    session: Session = Depends(get_db),
    user=Depends(require_document_manager),
):
    base_path, _, _ = _documents_base(request)
    if patent_parts == "1":  # патент: четыре поля номера (форма подстраивается под тип) — в одну строку
        parts = [patent_series, patent_number, patent_blank_series, patent_blank_number]
        document_number = format_patent_number(*parts) if any(normalize_text(p) for p in parts) else ""
    # Срок — если тип требует (подпись «обязателен» в форме), как в карточке создания и матрице.
    # Загрузку сотрудником из кабинета это не касается: там даты вносит кадровик при проверке.
    required_type = session.get(DocumentType, document_type_id)
    if (required_type is not None and required_type.requires_expiry_date and not normalize_text(expiry_date)
            and not (parse_bool(is_permanent) and required_type.allow_permanent)):
        return _redirect(base_path, error=f"Для документа «{required_type.name}» нужна дата окончания")
    try:
        allowed_names = None if request.url.path.startswith("/admin") else _employee_scope(session, user)
        return await _create_employee_document(
            session,
            request,
            user,
            base_path=base_path,
            allowed_names=allowed_names,
            employee_name=employee_name,
            document_type_id=document_type_id,
            document_number=document_number,
            issue_date=issue_date,
            expiry_date=expiry_date,
            is_permanent=is_permanent,
            extra_field_1_value=extra_field_1_value,
            extra_field_2_value=extra_field_2_value,
            file=file,
            comment=comment,
        )
    except Exception as exc:
        session.rollback()
        return _redirect(base_path, error=str(exc))


@router.post("/cabinet/documents/upload")
async def cabinet_upload_document(
    request: Request,
    document_type_id: int = Form(...),
    file: list[UploadFile] = File(...),
    session: Session = Depends(get_db),
    user=Depends(current_user),
):
    try:
        return await _create_employee_document(
            session,
            request,
            user,
            base_path="/employee_docs",
            allowed_names=[normalize_text(user.employee_name)],
            employee_name=user.employee_name,
            document_type_id=document_type_id,
            document_number="",
            issue_date="",
            expiry_date="",
            is_permanent="",
            extra_field_1_value="",
            extra_field_2_value="",
            file=file,
            comment="",
            status="pending_verification",
        )
    except Exception as exc:
        session.rollback()
        return _redirect("/employee_docs", error=str(exc))


# Сотрудник дописывает страницы к своему документу, пока его не проверили (загрузил 1-й лист, потом 2-й и 3-й).
CABINET_ADD_PAGES_STATUSES = ("uploaded", "pending_verification")


@router.post("/cabinet/documents/{document_id}/pages")
async def cabinet_add_pages(
    request: Request,
    document_id: int,
    file: list[UploadFile] = File(...),
    session: Session = Depends(get_db),
    user=Depends(current_user),
):
    document = session.get(EmployeeDocument, document_id)
    own = document is not None and (document.user_id == user.id or (
        document.user_id is None and normalize_text(document.employee_name) == normalize_text(user.employee_name)))
    if not own:
        return _redirect("/employee_docs", error="Документ не найден")
    if document.status not in CABINET_ADD_PAGES_STATUSES:
        return _redirect("/employee_docs", error="Документ уже проверен — загрузите новый, если нужно")
    if len(document_pages(document)) + len([f for f in file if f.filename]) > MAX_DOCUMENT_PAGES:
        return _redirect("/employee_docs", error=f"Не больше {MAX_DOCUMENT_PAGES} страниц в документе")
    try:
        saved = await save_upload_files(file, f"employee_documents/{user.id}", f"type_{document.document_type_id}")
    except ValueError as exc:
        return _redirect("/employee_docs", error=str(exc))
    if not saved:
        return _redirect("/employee_docs", error="Выберите файл")
    before = len(document_pages(document))
    add_document_pages(document, saved, user.id)
    document.status = "pending_verification"
    document.updated_at = now_utc()
    create_audit_log(
        session, request, user, "document_pages_added", "employee_document", document.id, document.employee_name,
        old_value={"pages": before}, new_value={"pages": before + len(saved), "files": [k for k, _ in saved]},
        comment="кабинет сотрудника",
    )
    session.commit()
    return _redirect("/employee_docs", message=f"Добавлено страниц: {len(saved)}")


BULK_SKIP_REASONS = {
    "archived": "в архиве",
    "verified": "уже проверен",
}


@router.post("/admin/documents/verify-bulk")
@router.post("/economist/documents/verify-bulk")
@router.post("/hr/documents/verify-bulk")
def verify_documents_bulk(
    request: Request,
    document_ids: list[int] = Form(default=[]),
    status: str = Form(default="pending_verification"),
    employee_name: str = Form(default=""),
    session: Session = Depends(get_db),
    user=Depends(require_document_manager),
):
    """П4: «Проверено (N)» — несколько документов разом. Отказ по одному документу
    (нет доступа, в архиве, уже проверен) не отменяет остальные; один аудит на пачку."""
    base_path, _, _ = _documents_base(request)
    verified, skipped = [], []
    for document_id in dict.fromkeys(document_ids):
        document = session.query(EmployeeDocument).filter(EmployeeDocument.id == document_id).first()
        if not _document_allowed_for_user(session, document, user):
            skipped.append((document_id, "нет доступа"))
            continue
        if document.status in BULK_SKIP_REASONS:
            skipped.append((document_id, BULK_SKIP_REASONS[document.status]))
            continue
        if patent_missing_fields(session, document):
            skipped.append((document_id, "патент без бланка или профессии"))
            continue
        _set_document_status(document, user, "verified")
        verified.append(document_id)
    if verified or skipped:
        create_audit_log(
            session, request, user, "documents.verify_bulk", "employee_document", None,
            f"Проверено {len(verified)}",
            new_value={"verified": verified, "skipped": [{"id": i, "reason": r} for i, r in skipped]},
        )
    session.commit()
    message = f"Проверено {len(verified)}"
    if skipped:
        reasons = {}
        for _, reason in skipped:
            reasons[reason] = reasons.get(reason, 0) + 1
        message += ", пропущено %d (%s)" % (len(skipped), ", ".join(f"{r}: {n}" for r, n in reasons.items()))
    return _redirect(base_path, status=status, employee_name=employee_name, message=message)


@router.post("/admin/documents/verify")
@router.post("/economist/documents/verify")
@router.post("/hr/documents/verify")
def verify_document(
    request: Request,
    document_id: int = Form(...),
    status: str = Form(default="pending_verification"),
    employee_name: str = Form(default=""),
    comment: str = Form(default=""),
    session: Session = Depends(get_db),
    user=Depends(require_document_manager),
):
    return _change_document_status(
        request,
        session,
        user,
        document_id=document_id,
        new_status="verified",
        status_filter=status,
        employee_name=employee_name,
        comment=comment,
    )


@router.post("/admin/documents/reject")
@router.post("/economist/documents/reject")
@router.post("/hr/documents/reject")
def reject_document(
    request: Request,
    document_id: int = Form(...),
    status: str = Form(default="pending_verification"),
    employee_name: str = Form(default=""),
    comment: str = Form(default=""),
    session: Session = Depends(get_db),
    user=Depends(require_document_manager),
):
    return _change_document_status(
        request,
        session,
        user,
        document_id=document_id,
        new_status="rejected",
        status_filter=status,
        employee_name=employee_name,
        comment=comment,
    )


@router.post("/admin/documents/archive")
@router.post("/economist/documents/archive")
@router.post("/hr/documents/archive")
def archive_document(
    request: Request,
    document_id: int = Form(...),
    status: str = Form(default="pending_verification"),
    employee_name: str = Form(default=""),
    session: Session = Depends(get_db),
    user=Depends(require_document_manager),
):
    return _change_document_status(
        request,
        session,
        user,
        document_id=document_id,
        new_status="archived",
        status_filter=status,
        employee_name=employee_name,
    )


# ── Карточка документа: просмотр, правка данных и файла, безвозвратное удаление ──
# Правка — documents.manage (ТМ, кадровик, руководитель, суперадмин) в пределах доступа к сотруднику;
# статус не меняется (проверенный остаётся проверенным — решение владельца 14.10.2026), всё — в аудит.
# Удаление — только суперадмин (documents.hard_delete); остальным — «Архив» в реестре.
CARD_FIELDS = ("document_number", "issue_date", "expiry_date", "is_permanent",
               "extra_field_1_value", "extra_field_2_value", "comment", "file_path", "original_filename")


CARD_AUDIT_FIELDS = CARD_FIELDS + ("pages",)


def _card_payload(document):
    payload = {field: (str(getattr(document, field)) if getattr(document, field) is not None else None)
               for field in CARD_FIELDS}
    payload["pages"] = [p.file_path for p in document.pages] or None  # страницы 2…N (ключи хранилища)
    return payload


def _card_url(base_path, document_id, back=""):
    return f"{base_path}/card/{document_id}" + (f"?{urlencode({'back': back})}" if back else "")


def _card_back(base_path, back):
    return safe_return_to(back, base_path)


# Создание документа из строки «Не загружен» реестра: та же карточка в режиме создания (creating).
# Документ, внесённый сотрудником отдела кадров, получает тот же статус, что из формы
# «Добавить документ вручную» (_create_employee_document) — «ожидает проверки».
CREATED_DOCUMENT_STATUS = "pending_verification"
ACTIVE_EXISTING_STATUSES = ("archived", "rejected")  # такие не мешают создать новый документ


def _new_document_target(session, request, user, user_id, document_type_id):
    """(сотрудник, тип, уже существующий документ, ошибка) для режима создания."""
    employee = session.get(User, user_id) if user_id else None
    document_type = session.get(DocumentType, document_type_id) if document_type_id else None
    if employee is None or document_type is None or not document_type.is_active:
        return None, None, None, "Сотрудник или тип документа не найден"
    allowed = None if request.url.path.startswith("/admin") else _employee_scope(session, user)
    if not _is_employee_allowed(employee.employee_name, allowed):
        return None, None, None, "Нет доступа к сотруднику"
    existing = latest_employee_document(session, employee.employee_name, document_type.id)
    if existing is not None and existing.status in ACTIVE_EXISTING_STATUSES:
        existing = None
    return employee, document_type, existing, None


def _existing_redirect(base_path, existing, back):
    card_url = _card_url(base_path, existing.id, back)
    return RedirectResponse(card_url + ("&" if "?" in card_url else "?") + urlencode(
        {"message": "Документ этого типа у сотрудника уже есть — открыта его карточка"}), status_code=302)


def _deny_manage(session, request, user, base_path, back):
    record_denied_action(session, request, user, "documents.manage")
    return _redirect(_card_back(base_path, back), error="Нет права добавлять документы")


@router.get("/admin/documents/new", response_class=HTMLResponse)
@router.get("/economist/documents/new", response_class=HTMLResponse)
@router.get("/hr/documents/new", response_class=HTMLResponse)
def document_new(
    request: Request,
    user_id: int = 0,
    document_type_id: int = 0,
    back: str = "",
    error: str = "",
    session: Session = Depends(get_db),
    user=Depends(require_document_manager),
):
    base_path, _, _ = _documents_base(request)
    if not has_permission(user, "documents.manage"):
        return _deny_manage(session, request, user, base_path, back)
    employee, document_type, existing, problem = _new_document_target(session, request, user, user_id,
                                                                     document_type_id)
    if problem:
        return _redirect(_card_back(base_path, back), error=problem)
    if existing is not None:
        return _existing_redirect(base_path, existing, back)
    draft = EmployeeDocument(user_id=employee.id, employee_name=employee.employee_name,
                             document_type_id=document_type.id)
    return templates.TemplateResponse(request, "document_card.html", {
        "creating": True,
        "document": draft,
        "type": document_type,
        "patent": parse_patent_number("") if document_type.name == DOC_PATENT else None,
        "status": "missing",
        "status_label": STATUS_LABELS["missing"],
        "employee": employee,
        "base_path": base_path,
        "back": _card_back(base_path, back),
        "back_param": back,
        "can_edit": True,
        "can_delete": False,
        "message": None,
        "error": error or None,
    })


@router.post("/admin/documents/new")
@router.post("/economist/documents/new")
@router.post("/hr/documents/new")
async def document_new_save(
    request: Request,
    user_id: int = Form(0),
    document_type_id: int = Form(0),
    back: str = Form(default=""),
    document_number: str = Form(default=""),
    patent_parts: str = Form(default=""),
    patent_series: str = Form(default=""),
    patent_number: str = Form(default=""),
    patent_blank_series: str = Form(default=""),
    patent_blank_number: str = Form(default=""),
    issue_date: str = Form(default=""),
    expiry_date: str = Form(default=""),
    is_permanent: str = Form(default=""),
    extra_field_1_value: str = Form(default=""),
    extra_field_2_value: str = Form(default=""),
    comment: str = Form(default=""),
    add_files: list[UploadFile] = File(default=[]),
    session: Session = Depends(get_db),
    user=Depends(require_document_manager),
):
    base_path, _, _ = _documents_base(request)
    if not has_permission(user, "documents.manage"):
        return _deny_manage(session, request, user, base_path, back)
    employee, document_type, existing, problem = _new_document_target(session, request, user, user_id,
                                                                     document_type_id)
    if problem:
        return _redirect(_card_back(base_path, back), error=problem)
    if existing is not None:  # гонка / второй клик — дубль не создаём
        return _existing_redirect(base_path, existing, back)

    def fail(text):
        query = {"user_id": user_id, "document_type_id": document_type_id, "error": text}
        if back:
            query["back"] = back
        return RedirectResponse(f"{base_path}/new?{urlencode(query)}", status_code=302)

    permanent = parse_bool(is_permanent) and bool(document_type.allow_permanent)
    try:
        parsed_issue = parse_date(issue_date)
        parsed_expiry = None if permanent else parse_date(expiry_date)
    except DocumentDateParseError:
        return fail(INVALID_DATE_MESSAGE)
    if document_type.requires_expiry_date and not permanent and not parsed_expiry:
        return fail(f"Для документа «{document_type.name}» нужна дата окончания")
    if patent_parts == "1":
        parts = [patent_series, patent_number, patent_blank_series, patent_blank_number]
        number = format_patent_number(*parts) if any(normalize_text(p) for p in parts) else ""
    else:
        number = document_number
    try:
        saved = await save_upload_files(add_files, f"employee_documents/{employee.id}", f"type_{document_type.id}")
    except ValueError as exc:
        return fail(str(exc))

    document = EmployeeDocument(
        user_id=employee.id, employee_name=employee.employee_name, document_type_id=document_type.id,
        document_number=normalize_text(number) or None, issue_date=parsed_issue, expiry_date=parsed_expiry,
        is_permanent=permanent, extra_field_1_value=normalize_text(extra_field_1_value) or None,
        extra_field_2_value=normalize_text(extra_field_2_value) or None, comment=normalize_text(comment) or None,
        status=CREATED_DOCUMENT_STATUS, uploaded_by=user.id, uploaded_at=now_utc(),
    )
    session.add(document)
    add_document_pages(document, saved, user.id)
    session.flush()
    payload = _card_payload(document)
    create_audit_log(
        session, request, user, "document_created", "employee_document", document.id,
        f"{document.employee_name} / {document_type.name}",
        new_value={**{k: v for k, v in payload.items() if v is not None}, "status": document.status,
                   "document_type_id": document_type.id, "pages": len(saved)},
        comment="из строки «Не загружен» реестра",
    )
    if document.document_number and document_type.sort_order == INN_DOCUMENT_SORT_ORDER:
        set_employee_inn(session, employee, document.document_number, source="document", actor=user, request=request)
    session.commit()
    target = _card_back(base_path, back)
    return RedirectResponse(target + ("&" if "?" in target else "?") + urlencode(
        {"message": f"Документ «{document_type.name}» добавлен"}), status_code=302)


@router.get("/admin/documents/card/{document_id}", response_class=HTMLResponse)
@router.get("/economist/documents/card/{document_id}", response_class=HTMLResponse)
@router.get("/hr/documents/card/{document_id}", response_class=HTMLResponse)
def document_card(
    request: Request,
    document_id: int,
    back: str = "",
    message: str = "",
    error: str = "",
    session: Session = Depends(get_db),
    user=Depends(require_document_manager),
):
    base_path, _, _ = _documents_base(request)
    document = session.get(EmployeeDocument, document_id)
    if not _document_allowed_for_user(session, document, user):
        return _redirect(_card_back(base_path, back), error="Документ не найден или нет доступа")
    document_type = session.get(DocumentType, document.document_type_id)
    status = computed_document_status(document)
    employee = session.get(User, document.user_id) if document.user_id else None
    people = {u.id: u.employee_name for u in session.query(User).filter(
        User.id.in_([i for i in (document.uploaded_by, document.verified_by) if i]))}
    patent = None
    if document_type is not None and document_type.name == DOC_PATENT:
        patent = parse_patent_number(document.document_number)  # серия, номер, бланк — отдельными полями
    return templates.TemplateResponse(request, "document_card.html", {
        "document": document,
        "type": document_type,
        "patent": patent,
        "status": status,
        "status_label": STATUS_LABELS.get(status, status),
        "employee": employee,
        "uploaded_by": people.get(document.uploaded_by),
        "verified_by": people.get(document.verified_by),
        "base_path": base_path,
        "back": _card_back(base_path, back),
        "back_param": back,
        "can_edit": has_permission(user, "documents.manage"),
        "can_delete": has_permission(user, "documents.hard_delete"),
        "message": message or None,
        "error": error or None,
    })


@router.post("/admin/documents/card/{document_id}")
@router.post("/economist/documents/card/{document_id}")
@router.post("/hr/documents/card/{document_id}")
async def document_card_save(
    request: Request,
    document_id: int,
    back: str = Form(default=""),
    document_number: str = Form(default=""),
    patent_parts: str = Form(default=""),
    patent_series: str = Form(default=""),
    patent_number: str = Form(default=""),
    patent_blank_series: str = Form(default=""),
    patent_blank_number: str = Form(default=""),
    issue_date: str = Form(default=""),
    expiry_date: str = Form(default=""),
    is_permanent: str = Form(default=""),
    extra_field_1_value: str = Form(default=""),
    extra_field_2_value: str = Form(default=""),
    comment: str = Form(default=""),
    file: list[UploadFile] = File(default=[]),
    add_files: list[UploadFile] = File(default=[]),
    session: Session = Depends(get_db),
    user=Depends(require_document_manager),
):
    base_path, _, _ = _documents_base(request)
    document = session.get(EmployeeDocument, document_id)
    if not _document_allowed_for_user(session, document, user):
        return _redirect(_card_back(base_path, back), error="Документ не найден или нет доступа")
    card_url = _card_url(base_path, document_id, back)
    if not has_permission(user, "documents.manage"):
        record_denied_action(session, request, user, "documents.manage")
        return RedirectResponse(card_url + ("&" if "?" in card_url else "?") + urlencode(
            {"error": "Нет права менять документы"}), status_code=302)

    def fail(text):
        return RedirectResponse(card_url + ("&" if "?" in card_url else "?") + urlencode({"error": text}),
                                status_code=302)

    document_type = session.get(DocumentType, document.document_type_id)
    permanent = parse_bool(is_permanent)
    try:
        parsed_issue = parse_date(issue_date)
        parsed_expiry = None if permanent else parse_date(expiry_date)
    except DocumentDateParseError:
        return fail(INVALID_DATE_MESSAGE)
    # «Бессрочно» — только если тип разрешает (как в матрице), иначе его ловит диагностика ложно-зелёных.
    if permanent and document_type is not None and not document_type.allow_permanent:
        return fail(f"Тип «{document_type.name}» требует срок действия — «бессрочно» недоступно")

    # «Заменить файлы» (file) — новые страницы вместо всех прежних; «Добавить страницы» (add_files) — в конец.
    replace_count = len([f for f in file if f.filename])
    total = (replace_count or len(document_pages(document))) + len([f for f in add_files if f.filename])
    if total > MAX_DOCUMENT_PAGES:
        return fail(f"Не больше {MAX_DOCUMENT_PAGES} страниц в документе")
    try:
        folder = f"employee_documents/{document.user_id or normalize_employee_folder(document.employee_name)}"
        replaced = await save_upload_files(file, folder, f"type_{document.document_type_id}")
        added = await save_upload_files(add_files, folder, f"type_{document.document_type_id}")
    except ValueError as exc:
        return fail(str(exc))

    old_value = _card_payload(document)
    old_number = document.document_number
    if patent_parts == "1":
        # Патент: серия, номер, серия и номер бланка — в одну строку «78 №… / ПР …», как ждёт договор.
        parts = [patent_series, patent_number, patent_blank_series, patent_blank_number]
        number = format_patent_number(*parts) if any(normalize_text(p) for p in parts) else ""
    else:
        number = document_number
    document.document_number = normalize_text(number) or None
    document.issue_date = parsed_issue
    document.expiry_date = parsed_expiry
    document.is_permanent = permanent
    document.extra_field_1_value = normalize_text(extra_field_1_value) or None
    document.extra_field_2_value = normalize_text(extra_field_2_value) or None
    document.comment = normalize_text(comment) or None
    if replaced:
        # Прежние файлы не удаляются из хранилища: их ключи остаются в аудите — замену можно откатить.
        document.file_path, document.original_filename = replaced[0]
        document.pages.clear()
        add_document_pages(document, replaced[1:], user.id)
    add_document_pages(document, added, user.id)
    new_value = _card_payload(document)
    if new_value == old_value:
        return RedirectResponse(card_url + ("&" if "?" in card_url else "?") + urlencode(
            {"message": "Изменений нет"}), status_code=302)
    document.updated_at = now_utc()
    changed = [field for field in CARD_AUDIT_FIELDS if old_value[field] != new_value[field]]
    create_audit_log(
        session, request, user, "document_edited", "employee_document", document.id,
        f"{document.employee_name} / {document_type.name if document_type else document.document_type_id}",
        old_value={field: old_value[field] for field in changed},
        new_value={field: new_value[field] for field in changed},
        comment=f"карточка документа; статус «{document.status}» не менялся",
    )
    # ИНН — как при загрузке: номер документа типа ИНН переносится в карточку сотрудника.
    if (document_type is not None and document_type.sort_order == INN_DOCUMENT_SORT_ORDER
            and document.document_number and document.document_number != old_number and document.user_id):
        employee = session.get(User, document.user_id)
        if employee is not None:
            set_employee_inn(session, employee, document.document_number, source="document", actor=user,
                             request=request)
    session.commit()
    return RedirectResponse(card_url + ("&" if "?" in card_url else "?") + urlencode(
        {"message": "Документ сохранён"}), status_code=302)


@router.post("/admin/documents/card/{document_id}/pages/{page}/remove")
@router.post("/economist/documents/card/{document_id}/pages/{page}/remove")
@router.post("/hr/documents/card/{document_id}/pages/{page}/remove")
def document_page_remove(
    request: Request,
    document_id: int,
    page: int,
    back: str = Form(default=""),
    session: Session = Depends(get_db),
    user=Depends(require_document_manager),
):
    """Убрать одну страницу (неудачное фото). Файл в хранилище остаётся — ключ в аудите, это обратимо,
    поэтому право — documents.manage, а не суперадмин. Статус документа не меняется."""
    base_path, _, _ = _documents_base(request)
    document = session.get(EmployeeDocument, document_id)
    if not _document_allowed_for_user(session, document, user):
        return _redirect(_card_back(base_path, back), error="Документ не найден или нет доступа")
    card_url = _card_url(base_path, document_id, back)
    separator = "&" if "?" in card_url else "?"
    if not has_permission(user, "documents.manage"):
        record_denied_action(session, request, user, "documents.manage")
        return RedirectResponse(card_url + separator + urlencode({"error": "Нет права менять документы"}),
                                status_code=302)
    total = len(document_pages(document))
    removed = remove_document_page(document, page)
    if removed is None:
        return RedirectResponse(card_url + separator + urlencode({"error": "Страница не найдена"}), status_code=302)
    document.updated_at = now_utc()
    document_type = session.get(DocumentType, document.document_type_id)
    create_audit_log(
        session, request, user, "document_page_removed", "employee_document", document.id,
        f"{document.employee_name} / {document_type.name if document_type else document.document_type_id}",
        old_value={"page": page, "pages": total, "file_path": removed["key"], "original_filename": removed["name"]},
        new_value={"pages": total - 1},
        comment="файл остаётся в хранилище",
    )
    session.commit()
    return RedirectResponse(card_url + separator + urlencode({"message": f"Страница {page} убрана"}), status_code=302)


@router.post("/admin/documents/card/{document_id}/delete")
@router.post("/economist/documents/card/{document_id}/delete")
@router.post("/hr/documents/card/{document_id}/delete")
def document_card_delete(
    request: Request,
    document_id: int,
    back: str = Form(default=""),
    session: Session = Depends(get_db),
    user=Depends(require_document_manager),
):
    base_path, _, _ = _documents_base(request)
    target = _card_back(base_path, back)
    document = session.get(EmployeeDocument, document_id)
    if not _document_allowed_for_user(session, document, user):
        return _redirect(target, error="Документ не найден или нет доступа")
    if not has_permission(user, "documents.hard_delete"):
        record_denied_action(session, request, user, "documents.hard_delete")
        return RedirectResponse(_card_url(base_path, document_id, back) + ("&" if back else "?") + urlencode(
            {"error": "Безвозвратное удаление доступно только суперадминистратору — используйте «Архив»"}),
            status_code=302)
    document_type = session.get(DocumentType, document.document_type_id)
    old_value = _card_payload(document)
    old_value.update({"status": document.status, "employee_name": document.employee_name,
                      "document_type_id": document.document_type_id})
    file_keys = [page["key"] for page in document_pages(document)]
    create_audit_log(session, request, user, "document_deleted", "employee_document", document.id,
                     f"{document.employee_name} / {document_type.name if document_type else document.document_type_id}",
                     old_value=old_value)
    session.delete(document)
    session.commit()
    for key in file_keys:  # после commit: запись удалена — файлы больше никому не нужны
        storage_delete(key)
    separator = "&" if "?" in target else "?"
    return RedirectResponse(f"{target}{separator}{urlencode({'message': 'Документ удалён'})}", status_code=302)


def _page_file(document, page):
    """(ключ, имя) страницы page (1…N) документа или (None, None)."""
    pages = document_pages(document)
    if not 1 <= page <= len(pages):
        return None, None
    return pages[page - 1]["key"], pages[page - 1]["name"]


@router.get("/documents/files/{document_id}")
def document_file(
    request: Request,
    document_id: int,
    page: int = 1,
    session: Session = Depends(get_db),
    user=Depends(current_user),
):
    document = session.query(EmployeeDocument).filter(EmployeeDocument.id == document_id).first()
    if not _document_allowed_for_user(session, document, user):
        return RedirectResponse(url="/", status_code=302)
    key, name = _page_file(document, page)
    if key is None:
        return RedirectResponse(url="/", status_code=302)
    return storage_response(
        key,
        filename=name or Path(key).name,
        media_type=_safe_media_type(key),
        disposition="attachment",
    ) or RedirectResponse(url="/", status_code=302)


@router.get("/documents/preview/{document_id}")
def document_preview(
    request: Request,
    document_id: int,
    page: int = 1,
    session: Session = Depends(get_db),
    user=Depends(current_user),
):
    """Inline preview for modal — same access rules as /documents/files/{id} but Content-Disposition: inline."""
    document = session.query(EmployeeDocument).filter(EmployeeDocument.id == document_id).first()
    if not _document_allowed_for_user(session, document, user):
        return RedirectResponse(url="/", status_code=302)
    key, name = _page_file(document, page)
    ext = Path(key or "").suffix.lower()
    if key is None or ext not in SAFE_MEDIA_TYPES or ext == ".heic":
        return RedirectResponse(url="/", status_code=302)
    return storage_response(
        key,
        filename=name or Path(key).name,
        media_type=_safe_media_type(key),
        disposition="inline",
    ) or RedirectResponse(url="/", status_code=302)


@router.get("/documents/samples/file/{sample_id}")
def document_sample_file(
    sample_id: int,
    session: Session = Depends(get_db),
    user=Depends(current_user),
):
    sample = session.query(DocumentTypeSample).filter(DocumentTypeSample.id == sample_id).first()
    if not sample:
        return RedirectResponse(url="/", status_code=302)
    return storage_response(
        sample.file_path,
        filename=sample.original_filename or Path(sample.file_path or "").name,
        media_type=_safe_media_type(sample.file_path),
        disposition="inline",
    ) or RedirectResponse(url="/", status_code=302)


@router.post("/admin/document-types/delete-sample-file")
def delete_document_type_sample_file(
    request: Request,
    sample_id: int = Form(...),
    session: Session = Depends(get_db),
    user=Depends(require_document_manager),
):
    base_path, _, _ = _document_type_base(request)
    sample = session.query(DocumentTypeSample).filter(DocumentTypeSample.id == sample_id).first()
    if not sample:
        return _redirect(base_path, error="Образец не найден")
    storage_delete(sample.file_path)
    type_name = session.query(DocumentType.name).filter(DocumentType.id == sample.document_type_id).scalar() or ""
    session.delete(sample)
    create_audit_log(
        session, request, user,
        "document_type_updated", "document_type",
        sample.document_type_id, type_name,
        comment="sample_file_deleted",
    )
    session.commit()
    return _redirect(base_path, message="Образец удалён")


@router.get("/documents/samples/{type_id}")
def document_type_sample(
    request: Request,
    type_id: int,
    session: Session = Depends(get_db),
    user=Depends(current_user),
):
    first_new = session.query(DocumentTypeSample).filter(
        DocumentTypeSample.document_type_id == type_id
    ).order_by(DocumentTypeSample.sort_order, DocumentTypeSample.uploaded_at).first()
    if first_new:
        response = storage_response(
            first_new.file_path,
            filename=first_new.original_filename or Path(first_new.file_path or "").name,
            media_type=_safe_media_type(first_new.file_path),
            disposition="inline",
        )
        if response is not None:
            return response
    document_type = session.query(DocumentType).filter(DocumentType.id == type_id).first()
    if not document_type or not document_type.sample_image_path:
        return RedirectResponse(url="/", status_code=302)
    return storage_response(
        document_type.sample_image_path,
        filename=Path(document_type.sample_image_path).name,
        media_type=_safe_media_type(document_type.sample_image_path),
        disposition="inline",
    ) or RedirectResponse(url="/", status_code=302)


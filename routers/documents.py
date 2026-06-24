from pathlib import Path
from typing import Optional
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from access import accessible_employee_names
from audit_helpers import create_audit_log
from dependencies import (
    RedirectException,
    current_user,
    get_db,
)
from document_helpers import (
    DocumentDateParseError,
    INVALID_DATE_MESSAGE,
    MATRIX_COLUMNS,
    STATUS_LABELS,
    active_document_types,
    batch_employee_completeness,
    build_document_registry_rows,
    computed_document_status,
    document_file_exists,
    economist_employee_names,
    employee_names,
    normalize_employee_folder,
    parse_bool,
    parse_date,
    save_upload_file,
)
from models import CitizenshipRegime, Country, DocumentType, DocumentTypeSample, EmployeeDocument, EmployeeStoreAssignment, RegimeDocumentRule, Store, User
from store_helpers import extract_tk_number
from rbac import canonical_role, has_permission, is_superadmin
from sqlalchemy.orm import Session
from time_helpers import now_utc
from utils import normalize_text


router = APIRouter()
templates = Jinja2Templates(directory="templates")


SAFE_MEDIA_TYPES = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".pdf": "application/pdf",
    ".heic": "application/octet-stream",
}


def _safe_media_type(path):
    return SAFE_MEDIA_TYPES.get(Path(path).suffix.lower(), "application/octet-stream")


def _content_disposition(disposition_type, filename):
    safe_name = Path(filename or "document").name.replace('"', "")
    return f"{disposition_type}; filename*=UTF-8''{quote(safe_name)}"


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
    if request.url.path.startswith("/hr") and canonical_role(user) not in {"hr_lead", "hr_manager"}:
        raise RedirectException("/")
    return user

def _document_type_base(request):
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
    if admin or canonical_role(user) in {"superadmin", "hr_lead"}:
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
            "back_url": back_url,
            "back_label": back_label,
            "message": message or None,
            "error": error or None,
        },
    )


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
    file_path, original_filename = await save_upload_file(
        file,
        folder,
        f"type_{document_type.id}",
    )

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
        },
        comment=document.comment,
    )
    session.commit()
    return _redirect(base_path, message="Документ загружен")


def _document_allowed_for_user(session, document, user):
    if not document:
        return False
    if canonical_role(user) in {"superadmin", "hr_lead"}:
        return True
    if canonical_role(user) in {"economist", "hr_manager"}:
        allowed = accessible_employee_names(session, user)
        return _is_employee_allowed(document.employee_name, allowed)
    return normalize_text(document.employee_name) == normalize_text(user.employee_name)


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

    old_status = document.status
    old_comment = document.comment
    document.status = new_status
    document.comment = normalize_text(comment) or document.comment
    document.updated_at = now_utc()
    if new_status == "verified":
        document.verified_by = user.id
        document.verified_at = now_utc()
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
        Path(document_type.sample_image_path).unlink(missing_ok=True)
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
def admin_employee_documents(
    request: Request,
    user_id: int,
    session: Session = Depends(get_db),
    current=Depends(require_document_manager),
):
    user = session.query(User).filter(User.id == user_id).first()
    if not user:
        return RedirectResponse(url="/admin/documents?error=Сотрудник не найден", status_code=302)
    return _render_documents(
        request,
        session,
        current,
        employee_name=user.employee_name,
        status="all",
    )


@router.post("/admin/documents/upload")
@router.post("/economist/documents/upload")
@router.post("/hr/documents/upload")
async def upload_employee_document_by_manager(
    request: Request,
    employee_name: str = Form(...),
    document_type_id: int = Form(...),
    document_number: str = Form(default=""),
    issue_date: str = Form(default=""),
    expiry_date: str = Form(default=""),
    is_permanent: str = Form(default=""),
    extra_field_1_value: str = Form(default=""),
    extra_field_2_value: str = Form(default=""),
    comment: str = Form(default=""),
    file: UploadFile = File(...),
    session: Session = Depends(get_db),
    user=Depends(require_document_manager),
):
    base_path, _, _ = _documents_base(request)
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
    file: UploadFile = File(...),
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


@router.get("/documents/files/{document_id}")
def document_file(
    request: Request,
    document_id: int,
    session: Session = Depends(get_db),
    user=Depends(current_user),
):
    document = session.query(EmployeeDocument).filter(EmployeeDocument.id == document_id).first()
    if not _document_allowed_for_user(session, document, user):
        return RedirectResponse(url="/", status_code=302)
    if not document_file_exists(document.file_path):
        return RedirectResponse(url="/", status_code=302)
    return FileResponse(
        Path(document.file_path),
        media_type=_safe_media_type(document.file_path),
        headers={
            "Content-Disposition": _content_disposition(
                "attachment",
                document.original_filename or Path(document.file_path).name,
            ),
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/documents/preview/{document_id}")
def document_preview(
    request: Request,
    document_id: int,
    session: Session = Depends(get_db),
    user=Depends(current_user),
):
    """Inline preview for modal — same access rules as /documents/files/{id} but Content-Disposition: inline."""
    document = session.query(EmployeeDocument).filter(EmployeeDocument.id == document_id).first()
    if not _document_allowed_for_user(session, document, user):
        return RedirectResponse(url="/", status_code=302)
    if not document_file_exists(document.file_path):
        return RedirectResponse(url="/", status_code=302)
    ext = Path(document.file_path).suffix.lower()
    if ext not in SAFE_MEDIA_TYPES or ext == ".heic":
        return RedirectResponse(url="/", status_code=302)
    return FileResponse(
        Path(document.file_path),
        media_type=_safe_media_type(document.file_path),
        headers={
            "Content-Disposition": _content_disposition(
                "inline",
                document.original_filename or Path(document.file_path).name,
            ),
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/documents/samples/file/{sample_id}")
def document_sample_file(
    sample_id: int,
    session: Session = Depends(get_db),
    user=Depends(current_user),
):
    sample = session.query(DocumentTypeSample).filter(DocumentTypeSample.id == sample_id).first()
    if not sample or not document_file_exists(sample.file_path):
        return RedirectResponse(url="/", status_code=302)
    return FileResponse(
        Path(sample.file_path),
        media_type=_safe_media_type(sample.file_path),
        headers={
            "Content-Disposition": _content_disposition("inline", sample.original_filename or Path(sample.file_path).name),
            "X-Content-Type-Options": "nosniff",
        },
    )


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
    Path(sample.file_path).unlink(missing_ok=True)
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
    if first_new and document_file_exists(first_new.file_path):
        return FileResponse(
            Path(first_new.file_path),
            media_type=_safe_media_type(first_new.file_path),
            headers={
                "Content-Disposition": _content_disposition("inline", first_new.original_filename or Path(first_new.file_path).name),
                "X-Content-Type-Options": "nosniff",
            },
        )
    document_type = session.query(DocumentType).filter(DocumentType.id == type_id).first()
    if not document_type or not document_file_exists(document_type.sample_image_path):
        return RedirectResponse(url="/", status_code=302)
    return FileResponse(
        Path(document_type.sample_image_path),
        media_type=_safe_media_type(document_type.sample_image_path),
        headers={
            "Content-Disposition": _content_disposition("inline", Path(document_type.sample_image_path).name),
            "X-Content-Type-Options": "nosniff",
        },
    )


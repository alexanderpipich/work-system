from datetime import date, datetime
import os
from pathlib import Path
import re
from uuid import uuid4

from sqlalchemy import text

from database import engine
from models import DocumentType, EmployeeDocument, Requisite, Shift, User
from time_helpers import business_today, now_utc
from utils import normalize_text


DOCUMENT_UPLOAD_ROOT = Path(os.getenv("DOCUMENT_UPLOAD_ROOT", "uploaded_documents"))
MAX_UPLOAD_BYTES = 15 * 1024 * 1024
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".pdf", ".heic"}
INVALID_DATE_MESSAGE = "Некорректный формат даты (ожидается ГГГГ-ММ-ДД)"


class DocumentDateParseError(ValueError):
    pass


STATUS_LABELS = {
    "missing": "Не загружен",
    "uploaded": "Загружен",
    "pending_verification": "Ожидает проверки",
    "verified": "Проверен",
    "rejected": "Отклонен",
    "expired": "Истек срок действия",
    "archived": "В архиве",
}


def ensure_document_tables():
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS document_types (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR NOT NULL,
                    description TEXT,
                    help_text TEXT,
                    sample_image_path VARCHAR,
                    citizenship_filter VARCHAR,
                    requires_number BOOLEAN DEFAULT TRUE,
                    requires_issue_date BOOLEAN DEFAULT TRUE,
                    requires_expiry_date BOOLEAN DEFAULT TRUE,
                    allow_permanent BOOLEAN DEFAULT TRUE,
                    extra_field_1_label VARCHAR,
                    extra_field_2_label VARCHAR,
                    is_required BOOLEAN DEFAULT TRUE,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP
                )
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS employee_documents (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER,
                    employee_name VARCHAR NOT NULL,
                    document_type_id INTEGER NOT NULL,
                    document_number VARCHAR,
                    issue_date DATE,
                    expiry_date DATE,
                    is_permanent BOOLEAN DEFAULT FALSE,
                    extra_field_1_value VARCHAR,
                    extra_field_2_value VARCHAR,
                    file_path VARCHAR,
                    original_filename VARCHAR,
                    status VARCHAR DEFAULT 'uploaded',
                    comment TEXT,
                    uploaded_by INTEGER,
                    verified_by INTEGER,
                    uploaded_at TIMESTAMP DEFAULT NOW(),
                    verified_at TIMESTAMP,
                    updated_at TIMESTAMP
                )
                """
            )
        )


def parse_bool(value) -> bool:
    return str(value or "").lower() in {"1", "true", "on", "yes"}


def parse_date(value):
    value = normalize_text(value)
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as exc:
        raise DocumentDateParseError(INVALID_DATE_MESSAGE) from exc


def user_citizenship(session, user):
    if not user:
        return ""
    citizenship = normalize_text(user.citizenship_country)
    if citizenship:
        return citizenship

    requisite = session.query(Requisite).filter(
        Requisite.employee_name == normalize_text(user.employee_name),
        Requisite.is_active == True,
    ).first()
    return normalize_text(requisite.citizenship) if requisite else ""


def citizenship_matches(document_type, citizenship):
    filters = normalize_text(document_type.citizenship_filter)
    if not filters:
        return True

    citizenship_clean = normalize_text(citizenship).lower()
    allowed = {
        normalize_text(item).lower()
        for item in filters.split(",")
        if normalize_text(item)
    }
    return citizenship_clean in allowed


def active_document_types(session, citizenship="", required_only=False):
    query = session.query(DocumentType).filter(DocumentType.is_active == True)
    if required_only:
        query = query.filter(DocumentType.is_required == True)

    types = query.order_by(DocumentType.name.asc()).all()
    return [item for item in types if citizenship_matches(item, citizenship)]


def latest_employee_document(session, employee_name, document_type_id):
    return session.query(EmployeeDocument).filter(
        EmployeeDocument.employee_name == normalize_text(employee_name),
        EmployeeDocument.document_type_id == document_type_id,
    ).order_by(
        EmployeeDocument.uploaded_at.desc(),
        EmployeeDocument.id.desc(),
    ).first()


def computed_document_status(document, today=None):
    today = today or business_today()
    if not document:
        return "missing"
    if document.status in {"rejected", "archived"}:
        return document.status
    if not document.is_permanent and document.expiry_date and document.expiry_date < today:
        return "expired"
    return document.status or "uploaded"


def document_status_class(status):
    if status in {"missing", "rejected", "expired"}:
        return "bad"
    if status in {"pending_verification", "uploaded"}:
        return "warn"
    if status == "verified":
        return "ok"
    return "muted"


def employee_document_rows(session, user, required_only=True):
    citizenship = user_citizenship(session, user)
    rows = []
    for document_type in active_document_types(session, citizenship, required_only):
        document = latest_employee_document(session, user.employee_name, document_type.id)
        status = computed_document_status(document)
        rows.append({
            "type": document_type,
            "document": document,
            "status": status,
            "status_label": STATUS_LABELS.get(status, status),
            "status_class": document_status_class(status),
        })
    return rows


def employee_names(session):
    users = {
        normalize_text(row.employee_name)
        for row in session.query(User.employee_name).all()
        if normalize_text(row[0])
    }
    shifts = {
        normalize_text(row.employee)
        for row in session.query(Shift.employee).distinct().all()
        if normalize_text(row[0])
    }
    return sorted(users | shifts)


def economist_employee_names(session, allowed_cities):
    if allowed_cities is None:
        return employee_names(session)
    if not allowed_cities:
        return []
    rows = session.query(Shift.employee).filter(
        Shift.city.in_(allowed_cities)
    ).distinct().all()
    return sorted({normalize_text(row[0]) for row in rows if normalize_text(row[0])})


def user_by_employee_name(session, employee_name):
    return session.query(User).filter(
        User.employee_name == normalize_text(employee_name)
    ).first()


def employee_citizenship_by_name(session, employee_name):
    user = user_by_employee_name(session, employee_name)
    if user:
        return user_citizenship(session, user)

    requisite = session.query(Requisite).filter(
        Requisite.employee_name == normalize_text(employee_name),
        Requisite.is_active == True,
    ).first()
    return normalize_text(requisite.citizenship) if requisite else ""


def build_document_registry_rows(
    session,
    employees,
    *,
    employee_name="",
    document_type_id=0,
    status="",
):
    selected_employee = normalize_text(employee_name)
    if selected_employee:
        employees = [name for name in employees if name == selected_employee]

    rows = []
    for name in employees:
        citizenship = employee_citizenship_by_name(session, name)
        types = active_document_types(session, citizenship, required_only=True)
        if document_type_id:
            types = [item for item in types if item.id == document_type_id]

        for document_type in types:
            document = latest_employee_document(session, name, document_type.id)
            current_status = computed_document_status(document)
            if status and status != "all" and current_status != status:
                continue
            rows.append({
                "employee_name": name,
                "citizenship": citizenship,
                "type": document_type,
                "document": document,
                "status": current_status,
                "status_label": STATUS_LABELS.get(current_status, current_status),
                "status_class": document_status_class(current_status),
            })
    return rows


def safe_filename(filename):
    name = Path(filename or "document").name
    stem = Path(name).stem or "document"
    suffix = Path(name).suffix.lower()
    stem = re.sub(r"[^A-Za-zА-Яа-я0-9._-]+", "_", stem).strip("._")
    return f"{stem or 'document'}{suffix}"


async def save_upload_file(upload_file, folder, prefix):
    if not upload_file or not upload_file.filename:
        return None, None

    original = safe_filename(upload_file.filename)
    suffix = Path(original).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise ValueError("Недопустимый формат файла")

    content = await upload_file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise ValueError("Файл больше 15 MB")

    target_dir = DOCUMENT_UPLOAD_ROOT / folder
    target_dir.mkdir(parents=True, exist_ok=True)

    filename = f"{prefix}_{now_utc().strftime('%Y%m%d%H%M%S')}_{uuid4().hex[:8]}_{original}"
    path = target_dir / filename
    path.write_bytes(content)
    return str(path), upload_file.filename


def document_file_exists(path):
    return bool(path) and Path(path).is_file()


def normalize_employee_folder(employee_name):
    return re.sub(r"[^A-Za-zА-Яа-я0-9._-]+", "_", normalize_text(employee_name))[:120] or "employee"

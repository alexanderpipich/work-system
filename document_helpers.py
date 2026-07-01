from datetime import date, datetime, timedelta
import os
from pathlib import Path
import re
from uuid import uuid4

from sqlalchemy import or_, text

from database import engine
from models import Country, DocumentType, EmployeeDocument, RegimeDocumentRule, Requisite, Shift, User
from time_helpers import business_today, now_utc
from utils import normalize_text


DOCUMENT_UPLOAD_ROOT = Path(os.getenv("DOCUMENT_UPLOAD_ROOT", "uploaded_documents"))
MAX_UPLOAD_BYTES = 15 * 1024 * 1024
EXPIRY_WARNING_DAYS = 30
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
    "expiring_soon": "Истекает в ближайшие 30 дней",
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
    """DEPRECATED: используйте `citizenship_display`. Оставлено для совместимости;
    `Requisite.citizenship` больше НЕ читается (Блок 1 нормализации)."""
    return citizenship_display(session, user)


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


def required_document_types(session, user):
    """Обязательные типы документов сотрудника — ЕДИНЫЙ СТРУКТУРНЫЙ ИСТОЧНИК.

    Канон (Блок 1 нормализации): student-режим → `User.citizenship_country_id` →
    `Country` → `regime_id` → `RegimeDocumentRule`. Гражданство берётся ТОЛЬКО из
    привязки к справочнику. Нет привязки → пустой набор (сотрудник виден как
    «не заведён», а не подбирается по legacy-строке citizenship_filter).
    `Requisite.citizenship` здесь больше НЕ участвует.
    """
    if getattr(user, "is_student", False):
        base = (
            session.query(DocumentType)
            .filter(
                DocumentType.is_active == True,
                DocumentType.is_student_doc == False,
                DocumentType.sort_order >= 1,
                DocumentType.sort_order <= 5,
            )
            .order_by(DocumentType.sort_order.asc())
            .all()
        )
        student_docs = (
            session.query(DocumentType)
            .filter(DocumentType.is_active == True, DocumentType.is_student_doc == True)
            .order_by(DocumentType.sort_order.asc())
            .all()
        )
        return base + student_docs

    country_id = getattr(user, "citizenship_country_id", None) if user else None
    if country_id:
        country = session.query(Country).filter(Country.id == country_id).first()
        if country:
            type_ids = {
                r.document_type_id
                for r in session.query(RegimeDocumentRule).filter(
                    RegimeDocumentRule.regime_id == country.regime_id,
                    RegimeDocumentRule.is_required == True,
                ).all()
            }
            return (
                session.query(DocumentType)
                .filter(DocumentType.id.in_(type_ids), DocumentType.is_active == True)
                .order_by(DocumentType.sort_order.asc())
                .all()
            )
    return []


def citizenship_display(session, user):
    """Строка гражданства для ОТОБРАЖЕНИЯ — из канона (`citizenship_country_id` →
    `Country.name`), затем legacy `User.citizenship_country`. `Requisite.citizenship`
    больше НЕ источник (Блок 1 нормализации)."""
    if not user:
        return ""
    country_id = getattr(user, "citizenship_country_id", None)
    if country_id:
        country = session.query(Country).filter(Country.id == country_id).first()
        if country:
            return normalize_text(country.name)
    return normalize_text(user.citizenship_country)


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
    rows = []
    for document_type in required_document_types(session, user):
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


def employee_document_status(session, user) -> list[dict]:
    today = business_today()

    def _classify(doc):
        if not doc or doc.status in {"rejected", "archived"}:
            return "missing"
        if not doc.is_permanent and doc.expiry_date and doc.expiry_date < today:
            return "expired"
        if doc.status == "verified":
            if not doc.is_permanent and doc.expiry_date and doc.expiry_date <= today + timedelta(days=EXPIRY_WARNING_DAYS):
                return "expiring_soon"
            return "ok"
        if doc.status in {"uploaded", "pending_verification"}:
            return "pending"
        return "missing"

    def _rows(doc_types):
        return [
            {
                "document_type": dt,
                "required": True,
                "status": _classify(latest_employee_document(session, user.employee_name, dt.id)),
            }
            for dt in doc_types
        ]

    return _rows(required_document_types(session, user))


SORT_ORDER_TO_ICON_KEY = {
    2: "lmk",
    3: "passport",
    4: "inn",
    5: "snils",
    6: "registration",
    7: "patent",
    8: "fingerprints",
    9: "passport_translation",
    10: "dms",
    11: "migration_card",
    12: "patent_receipts",
}

ICON_KEY_TITLES = {
    "requisites": "Реквизиты",
    "lmk": "ЛМК",
    "passport": "Паспорт",
    "inn": "ИНН",
    "snils": "СНИЛС",
    "registration": "Регистрация",
    "patent": "Патент",
    "fingerprints": "Дактилоскопия",
    "passport_translation": "Перевод паспорта",
    "dms": "ДМС",
    "migration_card": "Миграционная карта",
    "patent_receipts": "Чеки по патенту",
}


def employee_completeness(session, user) -> list[dict]:
    """
    Returns ≤12 completeness items for a user:
      [0]    requisites  (from Requisite table)
      [1..N] documents   (from employee_document_status, regime-filtered)
    Each item: {position, title, icon_key, status, document_type, source}
    """
    name_clean = normalize_text(user.employee_name)
    req = (
        session.query(Requisite)
        .filter(
            Requisite.is_active == True,
            or_(
                Requisite.user_id == user.id,
                Requisite.employee_name == name_clean,
            ),
        )
        .first()
    )
    if req is None:
        req_status = "missing"
    elif req.is_verified:
        req_status = "ok"
    else:
        req_status = "pending"

    rows = [
        {
            "position": 0,
            "title": ICON_KEY_TITLES["requisites"],
            "icon_key": "requisites",
            "status": req_status,
            "document_type": None,
            "source": "requisite",
        }
    ]

    for i, row in enumerate(employee_document_status(session, user), start=1):
        dt = row["document_type"]
        icon_key = SORT_ORDER_TO_ICON_KEY.get(dt.sort_order, f"doc_{dt.id}")
        rows.append({
            "position": i,
            "title": ICON_KEY_TITLES.get(icon_key, dt.name),
            "icon_key": icon_key,
            "status": row["status"],
            "document_type": dt,
            "source": "document",
        })

    return rows


MATRIX_COLUMNS = [
    ("requisites", "Реквизиты"),
    ("lmk", "ЛМК"),
    ("passport", "Паспорт"),
    ("inn", "ИНН"),
    ("snils", "СНИЛС"),
    ("registration", "Регистрация"),
    ("patent", "Патент"),
    ("fingerprints", "Дактило"),
    ("passport_translation", "Перевод"),
    ("dms", "ДМС"),
    ("migration_card", "Миг. карта"),
    ("patent_receipts", "Чеки"),
]


def batch_employee_completeness(session, users: list) -> dict:
    """
    Batch version of employee_completeness for a list of users.
    Returns {user.id: {icon_key: item_dict}} — 6 DB queries total.
    """
    if not users:
        return {}

    today = business_today()

    all_doc_types = session.query(DocumentType).filter(
        DocumentType.is_active == True
    ).order_by(DocumentType.sort_order.asc()).all()

    all_rules = session.query(RegimeDocumentRule).filter(
        RegimeDocumentRule.is_required == True
    ).all()
    regime_to_type_ids: dict = {}
    for rule in all_rules:
        regime_to_type_ids.setdefault(rule.regime_id, set()).add(rule.document_type_id)

    all_countries = {c.id: c for c in session.query(Country).all()}

    names = {normalize_text(u.employee_name) for u in users}
    all_docs = session.query(EmployeeDocument).filter(
        EmployeeDocument.employee_name.in_(names)
    ).order_by(EmployeeDocument.uploaded_at.asc(), EmployeeDocument.id.asc()).all()
    docs_map: dict = {}
    for doc in all_docs:
        docs_map[(normalize_text(doc.employee_name), doc.document_type_id)] = doc

    user_ids = [u.id for u in users if getattr(u, "id", None)]
    all_reqs = session.query(Requisite).filter(
        Requisite.is_active == True,
        or_(Requisite.user_id.in_(user_ids), Requisite.employee_name.in_(names)),
    ).all()
    reqs_by_uid: dict = {}
    reqs_by_name: dict = {}
    for req in all_reqs:
        if req.user_id and req.user_id not in reqs_by_uid:
            reqs_by_uid[req.user_id] = req
        nk = normalize_text(req.employee_name)
        if nk not in reqs_by_name:
            reqs_by_name[nk] = req

    def _classify(doc):
        if not doc or doc.status in {"rejected", "archived"}:
            return "missing"
        if not doc.is_permanent and doc.expiry_date and doc.expiry_date < today:
            return "expired"
        if doc.status == "verified":
            if not doc.is_permanent and doc.expiry_date and doc.expiry_date <= today + timedelta(days=EXPIRY_WARNING_DAYS):
                return "expiring_soon"
            return "ok"
        if doc.status in {"uploaded", "pending_verification"}:
            return "pending"
        return "missing"

    def _doc_types_for(user):
        if getattr(user, "is_student", False):
            base = [dt for dt in all_doc_types if not dt.is_student_doc and 1 <= dt.sort_order <= 5]
            stu = [dt for dt in all_doc_types if dt.is_student_doc]
            return base + stu
        cid = getattr(user, "citizenship_country_id", None)
        if cid:
            country = all_countries.get(cid)
            if country and country.regime_id in regime_to_type_ids:
                ids = regime_to_type_ids[country.regime_id]
                return [dt for dt in all_doc_types if dt.id in ids]
        return [dt for dt in all_doc_types if dt.is_required]

    result = {}
    for user in users:
        name_clean = normalize_text(user.employee_name)
        req = reqs_by_uid.get(user.id) or reqs_by_name.get(name_clean)
        req_status = "missing" if req is None else ("ok" if req.is_verified else "pending")

        items: dict = {
            "requisites": {
                "position": 0,
                "title": ICON_KEY_TITLES["requisites"],
                "icon_key": "requisites",
                "status": req_status,
                "document_type": None,
                "source": "requisite",
            }
        }
        for i, dt in enumerate(_doc_types_for(user), start=1):
            ik = SORT_ORDER_TO_ICON_KEY.get(dt.sort_order, f"doc_{dt.id}")
            doc = docs_map.get((name_clean, dt.id))
            items[ik] = {
                "position": i,
                "title": ICON_KEY_TITLES.get(ik, dt.name),
                "icon_key": ik,
                "status": _classify(doc),
                "document_type": dt,
                "source": "document",
            }
        result[user.id] = items

    return result


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
    """Гражданство по ФИО — из канона (User). `Requisite.citizenship` больше НЕ
    fallback (Блок 1 нормализации)."""
    return citizenship_display(session, user_by_employee_name(session, employee_name))


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
        user = user_by_employee_name(session, name)
        citizenship = citizenship_display(session, user)
        types = required_document_types(session, user)
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

"""Данные сотрудника для карточки и договора (П4).

Источник истины — поля User и документы сотрудника (EmployeeDocument): паспорт,
СНИЛС, патент. Отдельной сущности «анкета» нет — «увеличенная привязка данных
к сотруднику» собирается здесь. Генератор договора и ходатайства берёт данные
только отсюда.

Патент хранится так (см. docs/contracts.md):
  document_number      — «78 №2600131320 / ПР 8408114» (серия, номер, бланк);
  issue_date/expiry    — даты; если срок не указан, считается «год минус день»;
  extra_field_1_value  — орган выдачи; extra_field_2_value — профессия по патенту.
Паспорт: document_number, issue_date, extra_field_1_value — кем выдан.
"""

import re
from datetime import timedelta

from sqlalchemy import or_

from models import Country, DocumentType, EmployeeDocument, LegalEntity, User
from region_helpers import region_for_employee
from utils import normalize_person_name, normalize_text

DOC_PASSPORT = "Паспорт"
DOC_SNILS = "СНИЛС"
DOC_PATENT = "ПАТЕНТ"
DOC_CONTRACT = "ТРУДОВОЙ ДОГОВОР"
DOC_PETITION = "ХОДАТАЙСТВО"
DOC_RECOMMENDATION = "РЕКОМЕНДАТЕЛЬНОЕ ПИСЬМО"
INACTIVE_DOC_STATUSES = {"archived", "rejected"}
# П5: что компания выдаёт сотруднику — блок «От компании» в «Мои документы».
COMPANY_DOC_TYPES = (DOC_CONTRACT, DOC_PETITION, DOC_RECOMMENDATION)

MALE_ENDINGS = ("вич", "ич", "угли", "оглы", "ули", "уулу")
FEMALE_ENDINGS = ("вна", "ична", "чна", "кизи", "кызы", "гызы")

PATENT_NUMBER_RE = re.compile(
    r"^\s*(?P<series>\d{2})\s*№?\s*(?P<number>\d+)"
    r"(?:\s*/\s*(?:бланк\s*)?(?P<blank_series>[A-ZА-ЯЁ]{1,3})\s*№?\s*(?P<blank_number>\d+))?\s*$",
    re.IGNORECASE,
)


def split_fio(full_name):
    """(фамилия, имя, отчество) — отчество может быть из двух слов («Исломбой Кизи»)."""
    parts = normalize_text(full_name).split()
    surname = parts[0] if parts else ""
    name = parts[1] if len(parts) > 1 else ""
    patronymic = " ".join(parts[2:])
    return surname, name, patronymic


def guess_gender(full_name):
    """m | f | None по отчеству (-вич/-ич/Угли/Оглы → m; -вна/-ична/Кизи/Кызы → f)."""
    _, _, patronymic = split_fio(full_name)
    key = normalize_person_name(patronymic)
    if not key:
        return None
    last = key.split()[-1]
    if any(last.endswith(e) for e in FEMALE_ENDINGS):
        return "f"
    if any(last.endswith(e) for e in MALE_ENDINGS):
        return "m"
    return None


def initials(full_name):
    """«Отабоева Н.И.»"""
    surname, name, patronymic = split_fio(full_name)
    letters = "".join(f"{part[0]}." for part in (name, patronymic.split()[0] if patronymic else "") if part)
    return f"{surname} {letters}".strip()


def parse_patent_number(value):
    """«78 №2600131320 / ПР 8408114» → dict(series, number, blank_series, blank_number)."""
    match = PATENT_NUMBER_RE.match(normalize_text(value))
    if not match:
        return {"series": "", "number": normalize_text(value), "blank_series": "", "blank_number": ""}
    return {key: (match.group(key) or "").upper() if key == "blank_series" else (match.group(key) or "")
            for key in ("series", "number", "blank_series", "blank_number")}


def format_patent_number(series, number, blank_series="", blank_number=""):
    text = f"{normalize_text(series)} №{normalize_text(number)}".strip()
    if normalize_text(blank_number):
        text += f" / {normalize_text(blank_series).upper()} {normalize_text(blank_number)}".rstrip()
    return text


def patent_expiry(document):
    """(дата окончания, вычислена ли): если срок не указан — выдача + год − день."""
    if document is None:
        return None, False
    if document.expiry_date:
        return document.expiry_date, False
    if document.issue_date:
        issue = document.issue_date
        try:
            year_later = issue.replace(year=issue.year + 1)
        except ValueError:  # 29 февраля
            year_later = issue.replace(year=issue.year + 1, day=28)
        return year_later - timedelta(days=1), True
    return None, False


def latest_document(session, user, type_name):
    """Последний действующий (не архив и не отклонён) документ типа."""
    doc_type = session.query(DocumentType).filter(DocumentType.name == type_name).order_by(DocumentType.id).first()
    if doc_type is None:
        return None, None
    query = session.query(EmployeeDocument).filter(
        EmployeeDocument.document_type_id == doc_type.id,
        EmployeeDocument.status.notin_(INACTIVE_DOC_STATUSES),
    )
    by_user = query.filter(EmployeeDocument.user_id == user.id).order_by(
        EmployeeDocument.uploaded_at.desc(), EmployeeDocument.id.desc()).first()
    if by_user is not None:
        return doc_type, by_user
    return doc_type, query.filter(EmployeeDocument.employee_name == user.employee_name).order_by(
        EmployeeDocument.uploaded_at.desc(), EmployeeDocument.id.desc()).first()


def company_documents(session, user):
    """Документы от компании этого сотрудника (договор, ходатайство, рекомендация) с файлом —
    новые сверху. Скачивание — /documents/files/{id}, там же проверка «только своё»."""
    types = {t.id: t for t in session.query(DocumentType).filter(DocumentType.name.in_(COMPANY_DOC_TYPES))}
    if not types:
        return []
    docs = session.query(EmployeeDocument).filter(
        EmployeeDocument.document_type_id.in_(types),
        EmployeeDocument.file_path.isnot(None),
        EmployeeDocument.file_path != "",
        EmployeeDocument.status.notin_(INACTIVE_DOC_STATUSES),
        or_(EmployeeDocument.user_id == user.id, EmployeeDocument.employee_name == user.employee_name),
    ).order_by(EmployeeDocument.uploaded_at.desc(), EmployeeDocument.id.desc()).all()
    return [{"document": doc, "type": types[doc.document_type_id],
             "date": doc.issue_date or (doc.uploaded_at.date() if doc.uploaded_at else None)} for doc in docs]


def is_russian(country):
    return bool(country and normalize_person_name(country.name) in {"россия", "российская федерация"})


def employee_profile(session, user):
    """Все данные сотрудника для карточки и договора с источником каждого поля."""
    country = session.get(Country, user.citizenship_country_id) if user.citizenship_country_id else None
    _, passport = latest_document(session, user, DOC_PASSPORT)
    _, snils = latest_document(session, user, DOC_SNILS)
    patent_type, patent = latest_document(session, user, DOC_PATENT)
    _, contract = latest_document(session, user, DOC_CONTRACT)
    surname, name, patronymic = split_fio(user.employee_name)
    guessed = guess_gender(user.employee_name)
    tm = session.get(User, user.tm_id) if user.tm_id else None
    legal_entity = None
    if user.legal_entity:
        legal_entity = session.query(LegalEntity).filter(LegalEntity.name == user.legal_entity).first()
    patent_parts = parse_patent_number(patent.document_number) if patent else {}
    expiry, expiry_computed = patent_expiry(patent)
    return {
        "user": user,
        "fio": normalize_text(user.employee_name),
        "surname": surname,
        "name": name,
        "patronymic": patronymic,
        "initials": initials(user.employee_name),
        "gender": user.gender or guessed,
        "gender_guessed": not user.gender and guessed is not None,
        "birth_date": user.birth_date,
        "country": country,
        "citizenship_genitive": (country.name_genitive or country.name) if country else "",
        "is_russian": is_russian(country),
        "inn": normalize_text(user.inn),
        "snils_doc": snils,
        "snils": normalize_text(snils.document_number) if snils else "",
        "passport_doc": passport,
        "passport_number": normalize_text(passport.document_number) if passport else "",
        "passport_issue_date": passport.issue_date if passport else None,
        "passport_issuer": normalize_text(passport.extra_field_1_value) if passport else "",
        "patent_type": patent_type,
        "patent_doc": patent,
        "patent_series": patent_parts.get("series", ""),
        "patent_number": patent_parts.get("number", ""),
        "patent_blank_series": patent_parts.get("blank_series", ""),
        "patent_blank_number": patent_parts.get("blank_number", ""),
        "patent_issue_date": patent.issue_date if patent else None,
        "patent_expiry": expiry,
        "patent_expiry_computed": expiry_computed,
        "patent_authority": normalize_text(patent.extra_field_1_value) if patent else "",
        "patent_profession": normalize_text(patent.extra_field_2_value) if patent else "",
        "job_title": normalize_text(user.job_title),
        "tm": tm,
        "legal_entity": legal_entity,
        "legal_entity_name": normalize_text(user.legal_entity),
        "region": region_for_employee(session, user.employee_name),
        "contract_doc": contract,
    }

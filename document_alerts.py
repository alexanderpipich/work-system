"""Сроки документов и напоминания (П4).

Правило: у документа с датой окончания (типы с requires_expiry_date — РЕГИСТРАЦИЯ,
ПАТЕНТ и др.) напоминания на уровнях alert_days типа (по умолчанию 30/14/7/0 дней
до окончания). При проверке берётся самый «тесный» достигнутый уровень — если
документ впервые увидели за 20 дней, уходит уровень 30, следующий — на 14.

Адресаты: все кадровики (hr_clerk) и руководители (hr_lead, П5), ТМ сотрудника (User.tm_id),
сам сотрудник.
Каналы: в приложении (DocumentExpiryAlert — счётчик в шапке, баннер в
кабинете) и email, если у адресата заполнен User.email (EmailLog
scenario="document_expiry"). Telegram — П6.

run_document_expiry_alerts идемпотентна по (документ, уровень, адресат).
Запуск: кнопка «Проверить сроки» и раз в сутки при старте приложения
(maybe_run_daily; последний запуск — запись аудита documents.expiry_run).
"""

from datetime import timedelta, timezone

from audit_helpers import create_audit_log
from document_helpers import alert_levels
from email_engine import send_email
from models import AuditLog, DocumentExpiryAlert, DocumentType, EmailLog, EmployeeDocument, User
from rbac import ROLE_HR_CLERK, ROLE_HR_LEAD
from time_helpers import business_today, now_utc
from utils import normalize_person_name, normalize_text

RUN_ACTION = "documents.expiry_run"
INACTIVE = {"archived", "rejected"}


def reached_level(levels, days_left):
    """Самый тесный достигнутый уровень: days_left ≤ уровня. None — ещё рано."""
    reached = [level for level in levels if days_left <= level]
    return min(reached) if reached else None


def expiring_documents(session, today=None):
    """[(документ, тип, дней до окончания, уровень)] — документы на уровне напоминания."""
    today = today or business_today()
    types = {t.id: t for t in session.query(DocumentType).filter(DocumentType.requires_expiry_date == True).all()}  # noqa: E712
    if not types:
        return []
    horizon = today + timedelta(days=max(max(alert_levels(t)) for t in types.values()))
    docs = session.query(EmployeeDocument).filter(
        EmployeeDocument.document_type_id.in_(types),
        EmployeeDocument.expiry_date != None,  # noqa: E711
        EmployeeDocument.expiry_date <= horizon,
        EmployeeDocument.is_permanent != True,  # noqa: E712
        EmployeeDocument.status.notin_(INACTIVE),
    ).order_by(EmployeeDocument.expiry_date.asc()).all()
    # Только последний документ сотрудника этого типа: старый истёкший патент при
    # новом действующем — не повод для тревоги.
    latest = {}
    for doc in session.query(EmployeeDocument).filter(
        EmployeeDocument.document_type_id.in_(types),
        EmployeeDocument.status.notin_(INACTIVE),
    ).order_by(EmployeeDocument.uploaded_at.asc(), EmployeeDocument.id.asc()).all():
        latest[(normalize_person_name(doc.employee_name), doc.document_type_id)] = doc.id
    result = []
    for doc in docs:
        if latest.get((normalize_person_name(doc.employee_name), doc.document_type_id)) != doc.id:
            continue
        doc_type = types[doc.document_type_id]
        days_left = (doc.expiry_date - today).days
        level = reached_level(alert_levels(doc_type), days_left)
        if level is not None:
            result.append((doc, doc_type, days_left, level))
    return result


def _employee_user(session, doc):
    if doc.user_id:
        user = session.get(User, doc.user_id)
        if user:
            return user
    key = normalize_person_name(doc.employee_name)
    return session.query(User).filter(User.employee_name_norm == key).first()


def recipients(session, doc):
    """Кадровики, руководители, ТМ сотрудника, сам сотрудник (без повторов)."""
    people = {u.id: u for u in session.query(User).filter(User.role.in_((ROLE_HR_CLERK, ROLE_HR_LEAD))).all()}
    employee = _employee_user(session, doc)
    if employee:
        people[employee.id] = employee
        if employee.tm_id:
            tm = session.get(User, employee.tm_id)
            if tm:
                people[tm.id] = tm
    return list(people.values()), employee


def alert_text(doc, doc_type, for_employee):
    date_text = doc.expiry_date.strftime("%d.%m.%Y")
    if for_employee:
        return f"Истекает срок документа {doc_type.name} {date_text} — требуется новый"
    return f"{doc.employee_name}: истекает срок документа {doc_type.name} {date_text}"


def run_document_expiry_alerts(session, today=None, request=None, actor=None):
    """Создать недостающие напоминания и разослать почту. Возвращает счётчики."""
    created = emailed = 0
    for doc, doc_type, days_left, level in expiring_documents(session, today):
        people, employee = recipients(session, doc)
        for person in people:
            exists = session.query(DocumentExpiryAlert.id).filter(
                DocumentExpiryAlert.document_id == doc.id,
                DocumentExpiryAlert.level == level,
                DocumentExpiryAlert.recipient_user_id == person.id,
            ).first()
            if exists:
                continue
            alert = DocumentExpiryAlert(document_id=doc.id, level=level, recipient_user_id=person.id,
                                        created_at=now_utc())
            email = normalize_text(person.email)
            if email:
                text = alert_text(doc, doc_type, for_employee=employee is not None and person.id == employee.id)
                result = send_email(email, f"Срок документа: {doc_type.name}", f"<p>{text}</p>", body_text=text)
                alert.email_status = result["status"]
                session.add(EmailLog(to_addresses=email, subject=f"Срок документа: {doc_type.name}",
                                     status=result["status"], error=result.get("error"),
                                     scenario="document_expiry", created_at=now_utc(),
                                     created_by=getattr(actor, "id", None)))
                emailed += 1
            session.add(alert)
            created += 1
    create_audit_log(session, request, actor, RUN_ACTION, "document_expiry", None, "Проверка сроков",
                     new_value={"alerts_created": created, "emails": emailed})
    session.commit()
    return {"alerts_created": created, "emails": emailed}


def maybe_run_daily(session):
    """При старте приложения: прогнать проверку, если прошлый запуск был > 24 ч назад."""
    last = session.query(AuditLog.created_at).filter(AuditLog.action == RUN_ACTION).order_by(
        AuditLog.created_at.desc()).first()
    last_at = last[0] if last else None
    if last_at is not None and last_at.tzinfo is None:
        last_at = last_at.replace(tzinfo=timezone.utc)  # колонка без пояса, now_utc() — с поясом
    if last_at and last_at > now_utc() - timedelta(hours=24):
        return None
    return run_document_expiry_alerts(session)


def unread_count(session, user_id):
    return session.query(DocumentExpiryAlert).filter(
        DocumentExpiryAlert.recipient_user_id == user_id,
        DocumentExpiryAlert.read_at == None,  # noqa: E711
    ).count()


def employee_banners(session, user):
    """Баннеры кабинета: по каждому документу — самое свежее напоминание сотруднику."""
    alerts = session.query(DocumentExpiryAlert).filter(
        DocumentExpiryAlert.recipient_user_id == user.id,
    ).order_by(DocumentExpiryAlert.level.asc()).all()
    seen, banners = set(), []
    for alert in alerts:
        if alert.document_id in seen:
            continue
        seen.add(alert.document_id)
        doc = session.get(EmployeeDocument, alert.document_id)
        if not doc or doc.status in INACTIVE or not doc.expiry_date:
            continue
        newer = session.query(EmployeeDocument.id).filter(
            EmployeeDocument.document_type_id == doc.document_type_id,
            EmployeeDocument.employee_name == doc.employee_name,
            EmployeeDocument.status.notin_(INACTIVE),
            EmployeeDocument.id > doc.id,
        ).first()
        if newer:
            continue  # уже загружен новый документ этого типа
        doc_type = session.get(DocumentType, doc.document_type_id)
        banners.append(alert_text(doc, doc_type, for_employee=True))
    return banners

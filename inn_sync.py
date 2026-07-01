"""
Блок 2 нормализации атрибутов — синхронизация ИНН сотрудника.

ИНН индивидуален и сквозной: введён/изменён в ЛЮБОЙ из трёх точек
(`User.inn`, активный `Requisite.inn`, номер документа-ИНН
`EmployeeDocument.document_number`) → синхронизируется во все три.
Каждое изменение фиксируется в audit-log. Модератор изменений — человек;
конфликты не затираются молча, а фиксируются.

Canonical для ЧТЕНИЯ — `User.inn`. Запись — двусторонняя (любая точка пишет
через сервис, сервис приводит все три к одному значению).

⚠️ `LegalEntity.inn` — ИНН ЮРЛИЦА, отдельная сущность, этот модуль её не трогает.
"""

from models import DocumentType, Requisite
from audit_helpers import create_audit_log
from document_helpers import latest_employee_document
from utils import normalize_text

# Канонический sort_order типа документа «ИНН» (см. CLAUDE.md — порядок 12 типов
# карточки комплектности: реквизиты, ЛМК, паспорт, ИНН, СНИЛС, ...).
INN_DOCUMENT_SORT_ORDER = 4


def inn_document_type(session):
    return (
        session.query(DocumentType)
        .filter(DocumentType.sort_order == INN_DOCUMENT_SORT_ORDER, DocumentType.is_active == True)
        .first()
    )


def active_requisite_for_user(session, user):
    return (
        session.query(Requisite)
        .filter(Requisite.user_id == user.id, Requisite.is_active == True)
        .first()
    ) or (
        session.query(Requisite)
        .filter(Requisite.employee_name == normalize_text(user.employee_name), Requisite.is_active == True)
        .first()
    )


def inn_document_for_user(session, user):
    doc_type = inn_document_type(session)
    if not doc_type:
        return None
    return latest_employee_document(session, user.employee_name, doc_type.id)


def get_employee_inn(session, user) -> str:
    """Единое чтение ИНН сотрудника — из canonical User.inn."""
    return normalize_text(user.inn) if user else ""


def set_employee_inn(session, user, new_inn, *, source, actor=None, request=None):
    """
    Синхронизировать ИНН сотрудника во все три точки.

    source: "profile" | "requisite" | "document" — откуда пришло изменение
    (для audit-log; сама запись всё равно идёт во все точки).

    Идемпотентно: если new_inn совпадает с текущим canonical (User.inn) —
    ничего не пишем и не плодим аудит, даже если другие точки рассинхронены
    (та рассинхронизация фиксируется отдельным аудит-скриптом, см. Шаг 5 ТЗ).

    Возвращает dict {"changed": bool, "conflict": bool}.
    """
    normalized = normalize_text(new_inn)
    current = normalize_text(user.inn)
    if normalized == current:
        return {"changed": False, "conflict": False}

    requisite = active_requisite_for_user(session, user)
    document = inn_document_for_user(session, user)

    old_values = {
        "user_inn": current,
        "requisite_inn": normalize_text(requisite.inn) if requisite else "",
        "document_number": normalize_text(document.document_number) if document else "",
    }

    # Конфликт: до записи точки уже расходились между собой (не только с новым
    # значением) — историческая рассинхронизация. Не блокируем, применяем
    # canonical (новое значение), но фиксируем отдельной audit-записью.
    non_empty_old = {v for v in old_values.values() if v}
    conflict = len(non_empty_old) > 1

    user.inn = normalized or None
    if requisite is not None:
        requisite.inn = normalized or None
    if document is not None:
        document.document_number = normalized or None

    create_audit_log(
        session, request, actor,
        "inn_synced", "user", user.id, user.employee_name,
        old_value=old_values,
        new_value={"inn": normalized, "source": source},
        comment=f"ИНН синхронизирован из источника «{source}»",
    )
    if conflict:
        create_audit_log(
            session, request, actor,
            "inn_conflict_detected", "user", user.id, user.employee_name,
            old_value=old_values,
            new_value={"resolved_to": normalized, "source": source},
            comment="Точки ИНН расходились до синхронизации — применено новое значение",
        )

    return {"changed": True, "conflict": conflict}

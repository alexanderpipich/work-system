"""Справочники как код: выгрузка в data/reference/*.json и идемпотентная загрузка.

JSON в репозитории — источник справочников для чистой базы. Внешние ключи
хранятся естественными ключами (код режима, имя типа документа + sort_order,
имя услуги), id не переносятся: на новой базе они другие.

Загрузка сверяет записи по естественному ключу: нет в базе — вставка, есть и
отличается — обновление (JSON главнее базы), совпадает — пропуск. Повторный
запуск ничего не дублирует.

Не выгружаются: legal_entities (юрлица новой компании заводятся вручную) и
document_type_samples (файлы образцов утеряны при переезде на S3).
DocumentType.sample_image_path по той же причине не переносится.
"""

import json
from datetime import date
from pathlib import Path

from models import (
    CitizenshipRegime,
    Country,
    DocumentType,
    EmployeeMonitoringSettings,
    Rate,
    ReferralSettings,
    RegimeDocumentRule,
    Service,
    Store,
)

REFERENCE_DIR = Path(__file__).resolve().parent / "data" / "reference"

DOCUMENT_TYPE_FIELDS = [
    "name", "sort_order", "description", "help_text", "citizenship_filter",
    "requires_number", "requires_issue_date", "requires_expiry_date", "allow_permanent",
    "extra_field_1_label", "extra_field_2_label", "is_required", "is_active", "is_student_doc",
]
RATE_KEY = ["service", "level", "format", "city", "store", "employee_name", "active_from", "active_to"]
DATE_FIELDS = {"active_from", "active_to"}


class _Refs:
    """Перевод id ↔ естественный ключ для внешних ключей справочников."""

    def __init__(self, session):
        self.session = session
        self.reload()

    def reload(self):
        regimes = self.session.query(CitizenshipRegime).all()
        self.regime_code = {r.id: r.code for r in regimes}
        self.regime_id = {r.code: r.id for r in regimes}
        types = self.session.query(DocumentType).all()
        self.doc_type_key = {t.id: (t.name, t.sort_order) for t in types}
        self.doc_type_id = {(t.name, t.sort_order): t.id for t in types}
        services = self.session.query(Service).all()
        self.service_name = {s.id: s.name for s in services}
        self.service_id = {s.name: s.id for s in services}


def _plain(obj, fields):
    record = {}
    for field in fields:
        value = getattr(obj, field)
        record[field] = value.isoformat() if isinstance(value, date) else value
    return record


def _from_json(field, value):
    if field in DATE_FIELDS and value:
        return date.fromisoformat(value)
    return value


# --- описание таблиц ---------------------------------------------------------
# key(record) — естественный ключ записи JSON; to_record(obj, refs) — строка БД → JSON;
# to_values(record, refs) — JSON → значения колонок модели.

def _regime_spec():
    fields = ["code", "name", "description", "is_active", "sort_order"]
    return dict(
        model=CitizenshipRegime,
        key=lambda r: r["code"],
        to_record=lambda o, refs: _plain(o, fields),
        to_values=lambda r, refs: {f: r[f] for f in fields},
    )


def _country_spec():
    def to_record(o, refs):
        record = _plain(o, ["name", "is_active", "aliases"])
        record["regime_code"] = refs.regime_code.get(o.regime_id)
        return record

    def to_values(r, refs):
        return {
            "name": r["name"], "is_active": r["is_active"], "aliases": r["aliases"],
            "regime_id": refs.regime_id[r["regime_code"]],
        }

    return dict(model=Country, key=lambda r: r["name"], to_record=to_record, to_values=to_values)


def _document_type_spec():
    return dict(
        model=DocumentType,
        key=lambda r: (r["name"], r["sort_order"]),
        to_record=lambda o, refs: _plain(o, DOCUMENT_TYPE_FIELDS),
        to_values=lambda r, refs: {f: r[f] for f in DOCUMENT_TYPE_FIELDS},
    )


def _rule_spec():
    def to_record(o, refs):
        name, sort_order = refs.doc_type_key.get(o.document_type_id, (None, None))
        return {
            "regime_code": refs.regime_code.get(o.regime_id),
            "document_type_name": name,
            "document_type_sort_order": sort_order,
            "is_required": o.is_required,
        }

    def to_values(r, refs):
        return {
            "regime_id": refs.regime_id[r["regime_code"]],
            "document_type_id": refs.doc_type_id[(r["document_type_name"], r["document_type_sort_order"])],
            "is_required": r["is_required"],
        }

    return dict(
        model=RegimeDocumentRule,
        key=lambda r: (r["regime_code"], r["document_type_name"], r["document_type_sort_order"]),
        to_record=to_record,
        to_values=to_values,
    )


def _service_spec():
    fields = ["name", "aliases", "is_active"]
    return dict(
        model=Service,
        key=lambda r: r["name"],
        to_record=lambda o, refs: _plain(o, fields),
        to_values=lambda r, refs: {f: r[f] for f in fields},
    )


def _store_spec():
    fields = ["tk_number", "display_name", "city", "format", "object_address", "is_active", "comment"]
    return dict(
        model=Store,
        key=lambda r: r["tk_number"],
        to_record=lambda o, refs: _plain(o, fields),
        to_values=lambda r, refs: {f: r[f] for f in fields},
    )


def _rate_spec():
    fields = RATE_KEY + ["hourly_rate", "comment"]

    def to_record(o, refs):
        record = _plain(o, fields)
        record["service_name"] = refs.service_name.get(o.service_id)
        return record

    def to_values(r, refs):
        values = {f: _from_json(f, r[f]) for f in fields}
        values["service_id"] = refs.service_id.get(r["service_name"]) if r["service_name"] else None
        return values

    return dict(
        model=Rate,
        key=lambda r: tuple(r[f] for f in RATE_KEY),
        to_record=to_record,
        to_values=to_values,
    )


def _singleton_spec(model, fields):
    # Одна строка настроек на базу: ключ один и тот же у любой записи.
    return dict(
        model=model,
        key=lambda r: "settings",
        to_record=lambda o, refs: _plain(o, fields),
        to_values=lambda r, refs: {f: r[f] for f in fields},
        singleton=True,
    )


# Порядок важен: справочники, на которые ссылаются, идут раньше ссылающихся.
TABLES = [
    ("citizenship_regimes", _regime_spec()),
    ("countries", _country_spec()),
    ("document_types", _document_type_spec()),
    ("regime_document_rules", _rule_spec()),
    ("services", _service_spec()),
    ("stores", _store_spec()),
    ("rates", _rate_spec()),
    ("employee_monitoring_settings", _singleton_spec(
        EmployeeMonitoringSettings, ["inactive_days", "minimum_shifts", "analysis_days"])),
    ("referral_settings", _singleton_spec(ReferralSettings, ["hours_threshold", "bonus_amount"])),
]


def _sort_key(key):
    # None в ключе (ставка без формата/магазина) — в начало, без TypeError при сравнении.
    parts = key if isinstance(key, tuple) else (key,)
    return tuple((part is not None, str(part) if part is not None else "") for part in parts)


def export_reference_data(session):
    """{таблица: [записи]} из текущей базы, отсортировано по естественному ключу."""
    refs = _Refs(session)
    data = {}
    for table, spec in TABLES:
        query = session.query(spec["model"]).order_by(spec["model"].id)
        if spec.get("singleton"):
            first = query.first()
            records = [spec["to_record"](first, refs)] if first else []
        else:
            records = [spec["to_record"](obj, refs) for obj in query.all()]
        data[table] = sorted(records, key=lambda r: _sort_key(spec["key"](r)))
    return data


def write_reference_files(data, directory=REFERENCE_DIR):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    for table, records in data.items():
        path = directory / f"{table}.json"
        path.write_text(json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read_reference_files(directory=REFERENCE_DIR):
    directory = Path(directory)
    data = {}
    for table, _spec in TABLES:
        path = directory / f"{table}.json"
        if path.exists():
            data[table] = json.loads(path.read_text(encoding="utf-8"))
    return data


def seed_reference_data(session, data):
    """Загрузить справочники; вернуть {таблица: {inserted, updated, skipped}}. Коммит — на вызывающем."""
    refs = _Refs(session)
    stats = {}
    for table, spec in TABLES:
        if table not in data:
            continue
        model = spec["model"]
        existing = {}
        for obj in session.query(model).order_by(model.id).all():
            existing.setdefault(spec["key"](spec["to_record"](obj, refs)), obj)

        counts = {"inserted": 0, "updated": 0, "skipped": 0}
        for record in data[table]:
            values = spec["to_values"](record, refs)
            obj = existing.get(spec["key"](record))
            if obj is None:
                obj = model(**values)
                session.add(obj)
                existing[spec["key"](record)] = obj
                counts["inserted"] += 1
                continue
            changed = False
            for field, value in values.items():
                if getattr(obj, field) != value:
                    setattr(obj, field, value)
                    changed = True
            counts["updated" if changed else "skipped"] += 1

        session.flush()
        refs.reload()  # следующие таблицы ссылаются на только что вставленные id
        stats[table] = counts
    return stats

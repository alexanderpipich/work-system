import os
import unittest
from datetime import datetime, timedelta

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from database import Base
from document_helpers import build_document_registry_rows
from models import CitizenshipRegime, Country, DocumentType, EmployeeDocument, RegimeDocumentRule, User
from time_helpers import business_today


RF = "Иванов Иван Иванович"
FOREIGN = "Каримов Алишер"
STUDENT = "Петрова Анна"
NO_COUNTRY = "Сидоров Без Страны"
SHIFT_ONLY = "Только Из Смен"
LEGACY_ONLY = "Старый Формат Гражданства"

EMPLOYEES = sorted([RF, FOREIGN, STUDENT, NO_COUNTRY, SHIFT_ONLY, LEGACY_ONLY])


def _engine():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine


def _seed(s):
    s.add_all([
        CitizenshipRegime(id=1, code="rf", name="РФ"),
        CitizenshipRegime(id=2, code="patent", name="Патент"),
    ])
    s.add_all([
        Country(id=1, name="Россия", regime_id=1),
        Country(id=2, name="Узбекистан", regime_id=2),
    ])
    s.add_all([
        DocumentType(id=1, name="Паспорт", sort_order=1, is_active=True),
        DocumentType(id=2, name="СНИЛС", sort_order=2, is_active=True),
        DocumentType(id=3, name="Патент", sort_order=7, is_active=True),
        DocumentType(id=4, name="ЛМК", sort_order=4, is_active=True),
        DocumentType(id=5, name="Справка с учёбы", sort_order=9, is_active=True, is_student_doc=True),
        DocumentType(id=6, name="Неактивный", sort_order=3, is_active=False),
    ])
    s.add_all([
        RegimeDocumentRule(regime_id=1, document_type_id=1),
        RegimeDocumentRule(regime_id=1, document_type_id=2),
        RegimeDocumentRule(regime_id=1, document_type_id=4),
        RegimeDocumentRule(regime_id=1, document_type_id=6),  # неактивный тип не попадает
        RegimeDocumentRule(regime_id=2, document_type_id=1),
        RegimeDocumentRule(regime_id=2, document_type_id=3),
        RegimeDocumentRule(regime_id=2, document_type_id=4),
        RegimeDocumentRule(regime_id=2, document_type_id=2, is_required=False),
    ])
    s.add_all([
        User(phone="+70000000001", password_hash="x", employee_name=RF, citizenship_country_id=1),
        User(phone="+70000000002", password_hash="x", employee_name=FOREIGN, citizenship_country_id=2),
        User(phone="+70000000003", password_hash="x", employee_name=STUDENT, is_student=True),
        User(phone="+70000000004", password_hash="x", employee_name=NO_COUNTRY),
        User(phone="+70000000005", password_hash="x", employee_name=LEGACY_ONLY, citizenship_country="Киргизия"),
    ])

    today = business_today()
    t0 = datetime(2026, 1, 1, 12, 0, 0)

    def doc(name, type_id, status, *, at=t0, expiry=None, permanent=False, doc_id=None):
        s.add(EmployeeDocument(
            id=doc_id, employee_name=name, document_type_id=type_id, status=status,
            uploaded_at=at, expiry_date=expiry, is_permanent=permanent,
        ))

    # РФ — полный комплект, паспорт бессрочный.
    doc(RF, 1, "verified", permanent=True, doc_id=1)
    doc(RF, 2, "verified", doc_id=2)
    doc(RF, 4, "verified", expiry=today + timedelta(days=90), doc_id=3)
    # Иностранец: патент отклонён, ЛМК просрочен, паспорт — два документа.
    doc(FOREIGN, 3, "rejected", doc_id=10)
    doc(FOREIGN, 4, "verified", expiry=today - timedelta(days=1), doc_id=11)
    doc(FOREIGN, 1, "verified", at=t0, doc_id=12)
    doc(FOREIGN, 1, "pending_verification", at=t0 + timedelta(days=1), doc_id=13)  # последний по времени
    # Студент: при равном uploaded_at побеждает больший id.
    doc(STUDENT, 5, "verified", at=t0, doc_id=20)
    doc(STUDENT, 5, "pending_verification", at=t0, doc_id=21)
    # Документы у имени без User не влияют на реестр.
    doc(SHIFT_ONLY, 1, "pending_verification", doc_id=30)
    s.commit()


def _shape(rows):
    return [
        (
            r["employee_name"], r["citizenship"], r["type"].id,
            r["document"].id if r["document"] else None,
            r["status"], r["status_label"], r["status_class"],
        )
        for r in rows
    ]


class RegistryRowsTests(unittest.TestCase):
    def setUp(self):
        self.engine = _engine()
        self.s = sessionmaker(bind=self.engine)()
        _seed(self.s)

    def tearDown(self):
        self.s.close()

    def _rows(self, **kw):
        return _shape(build_document_registry_rows(self.s, EMPLOYEES, **kw))

    def test_all_rows(self):
        self.assertEqual(self._rows(status="all"), [
            (RF, "Россия", 1, 1, "verified", "Проверен", "ok"),
            (RF, "Россия", 2, 2, "verified", "Проверен", "ok"),
            (RF, "Россия", 4, 3, "verified", "Проверен", "ok"),
            (FOREIGN, "Узбекистан", 1, 13, "pending_verification", "Ожидает проверки", "warn"),
            (FOREIGN, "Узбекистан", 4, 11, "expired", "Истек срок действия", "bad"),
            (FOREIGN, "Узбекистан", 3, 10, "rejected", "Отклонен", "bad"),
            (STUDENT, "", 1, None, "missing", "Не загружен", "bad"),
            (STUDENT, "", 2, None, "missing", "Не загружен", "bad"),
            (STUDENT, "", 4, None, "missing", "Не загружен", "bad"),
            (STUDENT, "", 5, 21, "pending_verification", "Ожидает проверки", "warn"),
        ])

    def test_empty_status_equals_all(self):
        self.assertEqual(self._rows(status=""), self._rows(status="all"))

    def test_status_filter(self):
        self.assertEqual(
            [(r[0], r[2]) for r in self._rows(status="pending_verification")],
            [(FOREIGN, 1), (STUDENT, 5)],
        )

    def test_document_type_filter(self):
        self.assertEqual(
            [(r[0], r[3]) for r in self._rows(status="all", document_type_id=4)],
            [(RF, 3), (FOREIGN, 11), (STUDENT, None)],
        )

    def test_employee_filter(self):
        self.assertEqual([r[2] for r in self._rows(status="all", employee_name=f"  {RF} ")], [1, 2, 4])
        self.assertEqual(self._rows(status="all", employee_name=SHIFT_ONLY), [])

    def test_empty_employees(self):
        self.assertEqual(build_document_registry_rows(self.s, [], status="all"), [])

    def test_query_count_does_not_depend_on_employee_count(self):
        counter = {"n": 0}

        def count(*_args):
            counter["n"] += 1

        event.listen(self.engine, "before_cursor_execute", count)
        try:
            build_document_registry_rows(self.s, EMPLOYEES, status="all")
            small = counter["n"]
            counter["n"] = 0
            build_document_registry_rows(self.s, EMPLOYEES + [f"Нет {i}" for i in range(200)], status="all")
            large = counter["n"]
        finally:
            event.remove(self.engine, "before_cursor_execute", count)
        self.assertLessEqual(small, 5)
        self.assertEqual(small, large)


if __name__ == "__main__":
    unittest.main()

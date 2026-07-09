import json
import os
import unittest
from datetime import timedelta
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from document_helpers import classify_document
from models import AuditLog, DocumentType, EmployeeDocument, User
from routers.documents import admin_documents_matrix_toggle
from time_helpers import business_today


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _payload(response):
    return json.loads(bytes(response.body).decode("utf-8"))


class MatrixMarkTests(unittest.TestCase):
    """Отметка «документ есть» без файла: вариант B — срочным типам нужна дата."""

    def setUp(self):
        self.s = _session()
        self.admin = SimpleNamespace(id=1, role="superadmin", is_admin=True)
        self.employee = User(phone="+70000000001", password_hash="x", employee_name="Иванов И.И.", role="employee")
        self.s.add(self.employee)
        # Паспорт — бессрочный (дата не нужна); ЛМК — со сроком.
        self.s.add(DocumentType(id=3, name="Паспорт", sort_order=3, is_active=True,
                                requires_expiry_date=False, allow_permanent=True))
        self.s.add(DocumentType(id=2, name="ЛМК", sort_order=2, is_active=True,
                                requires_expiry_date=True, allow_permanent=False))
        self.s.commit()

    def tearDown(self):
        self.s.close()

    def _toggle(self, type_id, action="mark", expiry_date=""):
        return _payload(admin_documents_matrix_toggle(
            request=None,
            user_id=self.employee.id,
            document_type_id=type_id,
            action=action,
            expiry_date=expiry_date,
            session=self.s,
            user=self.admin,
        ))

    def _docs(self, type_id):
        return self.s.query(EmployeeDocument).filter(EmployeeDocument.document_type_id == type_id).all()

    def test_permanent_type_marked_without_date_is_green(self):
        data = self._toggle(3)
        self.assertTrue(data["ok"])
        self.assertEqual(data["status"], "ok")
        doc = self._docs(3)[0]
        self.assertEqual(doc.status, "verified")
        self.assertIsNone(doc.file_path)
        self.assertIsNone(doc.expiry_date)
        self.assertTrue(doc.is_permanent)
        self.assertEqual(doc.verified_by, self.admin.id)
        self.assertIsNotNone(doc.verified_at)

    def test_expiring_type_without_date_is_refused(self):
        data = self._toggle(2)
        self.assertFalse(data["ok"])
        self.assertTrue(data["needs_expiry"])
        self.assertEqual(self._docs(2), [])

    def test_expiring_type_with_bad_date_is_refused(self):
        data = self._toggle(2, expiry_date="31.12.2026")
        self.assertFalse(data["ok"])
        self.assertEqual(self._docs(2), [])

    def test_expiring_type_with_date_is_green_and_tracked(self):
        far = business_today() + timedelta(days=200)
        data = self._toggle(2, expiry_date=far.isoformat())
        self.assertTrue(data["ok"])
        self.assertEqual(data["status"], "ok")

        doc = self._docs(2)[0]
        self.assertEqual(doc.expiry_date, far)
        self.assertFalse(doc.is_permanent)
        self.assertIsNone(doc.file_path)

        # Срок отслеживается обычной статус-логикой.
        soon = business_today() + timedelta(days=10)
        data = self._toggle(2, expiry_date=soon.isoformat())
        self.assertEqual(data["status"], "expiring_soon")
        past = business_today() - timedelta(days=1)
        data = self._toggle(2, expiry_date=past.isoformat())
        self.assertEqual(data["status"], "expired")

    def test_mark_is_idempotent(self):
        self._toggle(3)
        self._toggle(3)
        self.assertEqual(len(self._docs(3)), 1)

    def test_unmark_returns_cell_to_missing(self):
        self._toggle(3)
        data = self._toggle(3, action="unmark")
        self.assertTrue(data["ok"])
        self.assertEqual(data["status"], "missing")
        self.assertFalse(data["marked"])
        self.assertEqual(self._docs(3), [])
        # Повторное снятие безопасно.
        self.assertEqual(self._toggle(3, action="unmark")["status"], "missing")

    def test_document_with_file_is_never_touched(self):
        doc = EmployeeDocument(
            user_id=self.employee.id,
            employee_name="Иванов И.И.",
            document_type_id=3,
            file_path="uploaded_documents/employee_documents/1/passport.pdf",
            original_filename="passport.pdf",
            status="verified",
        )
        self.s.add(doc)
        self.s.commit()

        for action in ("mark", "unmark"):
            with self.subTest(action=action):
                data = self._toggle(3, action=action)
                self.assertFalse(data["ok"])

        kept = self._docs(3)
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].file_path, "uploaded_documents/employee_documents/1/passport.pdf")

    def test_unknown_type_or_employee_is_refused(self):
        self.assertFalse(self._toggle(999)["ok"])
        data = _payload(admin_documents_matrix_toggle(
            request=None, user_id=4242, document_type_id=3, action="mark",
            expiry_date="", session=self.s, user=self.admin,
        ))
        self.assertFalse(data["ok"])

    def test_mark_and_unmark_are_audited(self):
        self._toggle(3)
        self._toggle(3, action="unmark")
        actions = [row.action for row in self.s.query(AuditLog).all()]
        self.assertIn("document_marked_manually", actions)
        self.assertIn("document_mark_removed", actions)


class ClassifyDocumentTests(unittest.TestCase):
    """Статус-логика не тронута: отметка без файла классифицируется как обычный документ."""

    def test_verified_permanent_is_ok(self):
        doc = SimpleNamespace(status="verified", is_permanent=True, expiry_date=None)
        self.assertEqual(classify_document(doc), "ok")

    def test_missing_when_no_document(self):
        self.assertEqual(classify_document(None), "missing")

    def test_expiring_soon_within_warning_window(self):
        doc = SimpleNamespace(status="verified", is_permanent=False,
                              expiry_date=business_today() + timedelta(days=10))
        self.assertEqual(classify_document(doc), "expiring_soon")


class MatrixToggleRouteTests(unittest.TestCase):
    def test_route_registered(self):
        import main
        paths = {r.path for r in main.app.routes}
        self.assertIn("/admin/documents/matrix/toggle", paths)


if __name__ == "__main__":
    unittest.main()

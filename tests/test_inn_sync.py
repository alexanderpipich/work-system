import os
import unittest
from datetime import date

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import AuditLog, DocumentType, EmployeeDocument, LegalEntity, Requisite, User
from inn_sync import get_employee_inn, set_employee_inn


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


class InnSyncTests(unittest.TestCase):
    def setUp(self):
        self.s = _session()
        self.user = User(phone="+70000000001", password_hash="x", employee_name="Иванов И.И.")
        self.s.add(self.user)
        self.s.add(DocumentType(id=4, name="ИНН", sort_order=4, is_active=True))
        self.s.commit()

    def tearDown(self):
        self.s.close()

    def _requisite(self, inn=""):
        req = Requisite(user_id=self.user.id, employee_name="Иванов И.И.", inn=inn, is_active=True)
        self.s.add(req)
        self.s.commit()
        return req

    def _inn_document(self, number=""):
        doc = EmployeeDocument(
            user_id=self.user.id, employee_name="Иванов И.И.", document_type_id=4,
            document_number=number, status="uploaded",
        )
        self.s.add(doc)
        self.s.commit()
        return doc

    def test_write_from_requisite_propagates_to_user_and_document(self):
        self._requisite()
        self._inn_document()
        result = set_employee_inn(self.s, self.user, "770123456789", source="requisite")
        self.assertTrue(result["changed"])
        self.assertFalse(result["conflict"])

        self.assertEqual(get_employee_inn(self.s, self.user), "770123456789")
        req = self.s.query(Requisite).filter(Requisite.user_id == self.user.id).first()
        doc = self.s.query(EmployeeDocument).filter(EmployeeDocument.user_id == self.user.id).first()
        self.assertEqual(req.inn, "770123456789")
        self.assertEqual(doc.document_number, "770123456789")

    def test_change_via_document_propagates_to_all(self):
        self._requisite(inn="111")
        self._inn_document(number="111")
        set_employee_inn(self.s, self.user, "111", source="requisite")  # sync baseline

        set_employee_inn(self.s, self.user, "999888777", source="document")
        self.assertEqual(get_employee_inn(self.s, self.user), "999888777")
        req = self.s.query(Requisite).filter(Requisite.user_id == self.user.id).first()
        self.assertEqual(req.inn, "999888777")

    def test_repeat_same_value_does_not_duplicate_audit(self):
        self._requisite()
        set_employee_inn(self.s, self.user, "555", source="requisite")
        count_after_first = self.s.query(AuditLog).filter(AuditLog.action == "inn_synced").count()

        result = set_employee_inn(self.s, self.user, "555", source="requisite")
        self.assertFalse(result["changed"])
        count_after_repeat = self.s.query(AuditLog).filter(AuditLog.action == "inn_synced").count()
        self.assertEqual(count_after_first, count_after_repeat)

    def test_conflict_detected_and_fixed_but_not_lost(self):
        self._requisite(inn="AAA")
        self._inn_document(number="BBB")  # разные значения ДО первой синхронизации
        result = set_employee_inn(self.s, self.user, "CCC", source="profile")
        self.assertTrue(result["conflict"])

        conflict_logs = self.s.query(AuditLog).filter(AuditLog.action == "inn_conflict_detected").all()
        self.assertEqual(len(conflict_logs), 1)
        # Новое значение применено везде (canonical).
        self.assertEqual(get_employee_inn(self.s, self.user), "CCC")
        req = self.s.query(Requisite).filter(Requisite.user_id == self.user.id).first()
        doc = self.s.query(EmployeeDocument).filter(EmployeeDocument.user_id == self.user.id).first()
        self.assertEqual(req.inn, "CCC")
        self.assertEqual(doc.document_number, "CCC")

    def test_no_requisite_or_document_still_updates_user(self):
        result = set_employee_inn(self.s, self.user, "123456789012", source="profile")
        self.assertTrue(result["changed"])
        self.assertFalse(result["conflict"])
        self.assertEqual(get_employee_inn(self.s, self.user), "123456789012")

    def test_legal_entity_inn_untouched(self):
        entity = LegalEntity(name="ООО ПРОГРЕСС", inn="7700000000")
        self.s.add(entity)
        self.s.commit()

        self._requisite()
        set_employee_inn(self.s, self.user, "999", source="requisite")

        entity_after = self.s.query(LegalEntity).filter(LegalEntity.id == entity.id).first()
        self.assertEqual(entity_after.inn, "7700000000")  # не тронут


if __name__ == "__main__":
    unittest.main()

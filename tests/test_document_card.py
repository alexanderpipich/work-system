"""Карточка документа: просмотр из реестра, правка данных и файла (статус не меняется, всё в аудит),
безвозвратное удаление — только суперадмину."""

import os
import re
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from file_storage import reset_client_cache, storage_exists, storage_save
from models import AuditLog, DocumentType, EmployeeDocument, User
from test_documents_contracts import EMP, _session, seed as seed_contracts
from test_predemo_p411 import _Client

S3_ENV = ("S3_BUCKET", "S3_ACCESS_KEY", "S3_SECRET_KEY", "S3_ENDPOINT", "S3_REGION")
OLD_KEY = "uploaded_documents/employee_documents/1/patent_old.png"


def seed(session):
    seed_contracts(session)
    session.add(User(id=50, employee_name="Экономист", role="economist", phone="70000000050", password_hash="x"))
    patent = session.query(EmployeeDocument).filter(EmployeeDocument.document_number.like("78 №%")).one()
    patent.file_path, patent.original_filename = OLD_KEY, "патент.png"
    session.commit()


class DocumentCardTests(_Client):
    seed = staticmethod(seed)

    def make_session(self):
        return _session()

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        env = {"DOCUMENT_UPLOAD_ROOT": str(Path(self._tmp.name) / "uploaded_documents")}
        self._env = patch.dict(os.environ, env)
        self._env.start()
        for name in S3_ENV:
            os.environ.pop(name, None)
        reset_client_cache()
        storage_save(OLD_KEY, b"old-scan")
        super().setUp()
        self._as(30)  # руководитель
        db = self.Session()
        self.patent = db.query(EmployeeDocument).filter(EmployeeDocument.file_path == OLD_KEY).one()
        self.card = f"/hr/documents/card/{self.patent.id}"

    def tearDown(self):
        super().tearDown()
        self._env.stop()
        self._tmp.cleanup()
        reset_client_cache()

    def _doc(self):
        return self.Session().get(EmployeeDocument, self.patent.id)

    def _save(self, path=None, files=None, **fields):
        data = {"document_number": self.patent.document_number, "issue_date": "2026-08-18",
                "extra_field_1_value": self.patent.extra_field_1_value,
                "extra_field_2_value": self.patent.extra_field_2_value, "back": "/hr/documents?status=all"}
        data.update(fields)
        return self.client.post(path or self.card, data=data, files=files, follow_redirects=False)

    def test_registry_has_open_button(self):
        html = self.client.get("/hr/documents?status=all&employee_name=" + EMP).text
        link = re.search(r'href="(/hr/documents/card/%d\?back=[^"]+)"(?: data-tour="docs-open")?>Открыть</a>' % self.patent.id, html)
        self.assertIsNotNone(link)
        self.assertIn("back=/hr/documents%3Fstatus%3Dall%26employee_name%3D", link.group(1))
        # возврат из карточки — на реестр с теми же фильтрами
        html = self.client.get(link.group(1)).text
        self.assertRegex(html, r'href="/hr/documents\?status=all&amp;employee_name=%D0[^"]*" class="back-link"')

    def test_card_shows_data(self):
        html = self.client.get(self.card + "?back=/hr/documents%3Fstatus%3Dall").text
        # патент — по частям: серия, номер, серия и номер бланка
        for name, value in (("patent_series", "78"), ("patent_number", "2600131320"),
                            ("patent_blank_series", "ПР"), ("patent_blank_number", "8408114")):
            self.assertIn(f'name="{name}" value="{value}"', html)
        self.assertNotIn('name="document_number"', html)
        self.assertIn('value="2026-08-18"', html)
        self.assertIn("подсобный рабочий", html)
        self.assertIn("патент.png", html)
        self.assertIn('href="/hr/documents?status=all" class="back-link"', html)
        self.assertIn(">Сохранить</button>", html)
        self.assertNotIn("Удалить документ", html)  # руководителю — только «Архив»

    def test_edit_keeps_verified_status_and_audits(self):
        response = self._save(expiry_date="2027-08-17", extra_field_2_value="грузчик")
        self.assertEqual(response.status_code, 302)
        self.assertIn("message=", response.headers["location"])
        self.assertTrue(response.headers["location"].startswith(self.card + "?back="))
        doc = self._doc()
        self.assertEqual((doc.expiry_date, doc.extra_field_2_value, doc.status), (date(2027, 8, 17), "грузчик", "verified"))
        self.assertEqual(doc.file_path, OLD_KEY)
        log = self.Session().query(AuditLog).filter(AuditLog.action == "document_edited").one()
        self.assertEqual(int(log.entity_id), doc.id)
        self.assertIn("подсобный рабочий", log.old_value)
        self.assertIn("грузчик", log.new_value)
        self.assertNotIn("document_number", log.new_value)  # в аудите только изменённые поля

    def test_patent_blank_fields_saved(self):
        """001: серия и номер бланка патента — отдельные поля, собираются в номер документа."""
        self._save(patent_parts="1", patent_series="78", patent_number="2600131320", patent_blank_series="пр",
                   patent_blank_number="9990001")
        self.assertEqual(self._doc().document_number, "78 №2600131320 / ПР 9990001")
        self._save(patent_parts="1", patent_series="", patent_number="", patent_blank_series="",
                   patent_blank_number="")
        self.assertIsNone(self._doc().document_number)

    def test_no_changes(self):
        self.assertIn("message=%D0%98%D0%B7%D0%BC%D0%B5%D0%BD%D0%B5%D0%BD%D0%B8%D0%B9", self._save().headers["location"])
        self.assertEqual(self.Session().query(AuditLog).filter(AuditLog.action == "document_edited").count(), 0)

    def test_replace_file_keeps_old_in_audit(self):
        self._save(files={"file": ("new.png", b"\x89PNG new", "image/png")})
        doc = self._doc()
        self.assertNotEqual(doc.file_path, OLD_KEY)
        self.assertEqual(doc.original_filename, "new.png")
        self.assertTrue(storage_exists(doc.file_path))
        self.assertTrue(storage_exists(OLD_KEY))  # прежний скан не удалён
        log = self.Session().query(AuditLog).filter(AuditLog.action == "document_edited").one()
        self.assertIn(OLD_KEY, log.old_value)

    def test_bad_input_rejected(self):
        self.assertIn("error=", self._save(files={"file": ("x.exe", b"MZ", "application/octet-stream")}).headers["location"])
        db = self.Session()
        db.query(DocumentType).filter(DocumentType.name == "ПАТЕНТ").one().allow_permanent = False
        db.commit()
        self.assertIn("error=", self._save(is_permanent="1").headers["location"])
        self.assertIsNone(self._doc().expiry_date)
        self.assertFalse(self._doc().is_permanent)

    def test_verify_only_role_cannot_edit(self):
        self._as(50)  # экономист: documents.verify без documents.manage
        path = f"/economist/documents/card/{self.patent.id}"
        html = self.client.get(path).text
        self.assertIn("<fieldset disabled", html)
        self.assertNotIn(">Сохранить</button>", html)
        self.assertIn("error=", self._save(path, extra_field_2_value="грузчик").headers["location"])
        self.assertEqual(self._doc().extra_field_2_value, "подсобный рабочий")
        self.assertTrue(self.Session().query(AuditLog).filter(AuditLog.action == "permission_denied",
                                                              AuditLog.entity_name == "documents.manage").count())

    def test_delete_only_superadmin(self):
        response = self.client.post(self.card + "/delete", data={"back": "/hr/documents"}, follow_redirects=False)
        self.assertIn("error=", response.headers["location"])
        self.assertIsNotNone(self._doc())
        self.assertTrue(self.Session().query(AuditLog).filter(AuditLog.entity_name == "documents.hard_delete").count())

        self._as(40)  # суперадмин
        path = f"/admin/documents/card/{self.patent.id}"
        self.assertIn("Удалить документ", self.client.get(path).text)
        response = self.client.post(path + "/delete", data={"back": "/admin/documents?status=all"},
                                    follow_redirects=False)
        self.assertTrue(response.headers["location"].startswith("/admin/documents?status=all&message="))
        self.assertIsNone(self._doc())
        self.assertFalse(storage_exists(OLD_KEY))
        log = self.Session().query(AuditLog).filter(AuditLog.action == "document_deleted").one()
        self.assertIn("78 №2600131320", log.old_value)

    def test_foreign_back_url_ignored(self):
        html = self.client.get(self.card + "?back=https://evil.example/x").text
        self.assertIn('href="/hr/documents" class="back-link"', html)


if __name__ == "__main__":
    unittest.main()

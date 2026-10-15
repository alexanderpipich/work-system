"""Многостраничный документ: несколько файлов на один документ (регистрация на 3 листа — 3 фото).
Страница 1 — EmployeeDocument.file_path, страницы 2…N — EmployeeDocumentPage."""

import json
import os
import re
import tempfile
from html import unescape
from pathlib import Path
from unittest.mock import patch
from urllib.parse import unquote_plus

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from document_helpers import MAX_DOCUMENT_PAGES, document_pages
from file_storage import reset_client_cache, storage_exists, storage_save
from models import AuditLog, DocumentType, EmployeeDocument, EmployeeDocumentPage, User
from test_document_card import OLD_KEY, S3_ENV, seed
from test_documents_contracts import EMP, _session
from test_predemo_p411 import _Client


def _png(tag):
    return (f"{tag}.png", b"\x89PNG " + tag.encode(), "image/png")


class DocumentPagesTests(_Client):
    seed = staticmethod(seed)

    def make_session(self):
        return _session()

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = patch.dict(os.environ, {"DOCUMENT_UPLOAD_ROOT": str(Path(self._tmp.name) / "uploaded_documents")})
        self._env.start()
        for name in S3_ENV:
            os.environ.pop(name, None)
        reset_client_cache()
        storage_save(OLD_KEY, b"old-scan")
        super().setUp()
        self._as(30)  # руководитель
        db = self.Session()
        self.passport_type = db.query(DocumentType).filter(DocumentType.name == "Паспорт").one().id
        self.patent_id = db.query(EmployeeDocument).filter(EmployeeDocument.file_path == OLD_KEY).one().id

    def tearDown(self):
        super().tearDown()
        self._env.stop()
        self._tmp.cleanup()
        reset_client_cache()

    def _upload(self, files, path="/hr/documents/upload"):
        return self.client.post(path, data={"employee_name": EMP, "document_type_id": str(self.passport_type)},
                                files=[("file", f) for f in files], follow_redirects=False)

    def _newest(self):
        db = self.Session()
        return db.query(EmployeeDocument).order_by(EmployeeDocument.id.desc()).first()

    def _location(self, response):
        return unquote_plus(response.headers["location"])

    # Загрузка
    def test_upload_several_files_one_document(self):
        before = self.Session().query(EmployeeDocument).count()
        response = self._upload([_png("p1"), _png("p2"), _png("p3")])
        self.assertIn("Документ загружен", self._location(response))
        self.assertEqual(self.Session().query(EmployeeDocument).count(), before + 1)
        doc = self._newest()
        pages = document_pages(doc)
        self.assertEqual([p["name"] for p in pages], ["p1.png", "p2.png", "p3.png"])
        self.assertEqual(doc.original_filename, "p1.png")
        self.assertTrue(all(storage_exists(p["key"]) for p in pages))
        audit = self.Session().query(AuditLog).filter(AuditLog.action == "document_uploaded").one()
        self.assertEqual(json.loads(audit.new_value)["pages"], 3)

    def test_bad_file_in_batch_saves_nothing(self):
        before = self.Session().query(EmployeeDocument).count()
        response = self._upload([_png("ok"), ("virus.exe", b"MZ", "application/octet-stream")])
        self.assertIn("Недопустимый формат файла «virus.exe»", self._location(response))
        self.assertEqual(self.Session().query(EmployeeDocument).count(), before)
        folder = Path(self._tmp.name) / "uploaded_documents" / "employee_documents"
        self.assertFalse(folder.exists() and any(folder.rglob("*ok.png")))

    def test_too_many_files(self):
        response = self._upload([_png(f"p{i}") for i in range(MAX_DOCUMENT_PAGES + 1)])
        self.assertIn(f"Не больше {MAX_DOCUMENT_PAGES} файлов", self._location(response))

    def test_single_file_as_before(self):
        self._upload([_png("one")])
        doc = self._newest()
        self.assertEqual((doc.original_filename, doc.pages), ("one.png", []))

    # Просмотр и скачивание по страницам
    def test_files_and_preview_by_page(self):
        self._upload([_png("p1"), _png("p2")])
        doc_id = self._newest().id
        self.assertEqual(self.client.get(f"/documents/files/{doc_id}?page=2").content, b"\x89PNG p2")
        self.assertEqual(self.client.get(f"/documents/preview/{doc_id}?page=2").content, b"\x89PNG p2")
        self.assertEqual(self.client.get(f"/documents/files/{doc_id}").content, b"\x89PNG p1")
        self.assertEqual(self.client.get(f"/documents/files/{doc_id}?page=3", follow_redirects=False).status_code,
                         302)
        self._as(10)  # ТМ видит документы (scopes выключены) — а чужой сотрудник нет
        db = self.Session()
        db.add(User(id=60, employee_name="Чужой Сотрудник", role="employee"))
        db.commit()
        self._as(60)
        self.assertEqual(self.client.get(f"/documents/files/{doc_id}?page=2", follow_redirects=False).status_code,
                         302)

    def test_registry_link_has_pages(self):
        # в реестре — обязательные по гражданству типы (у сотрудника — патент)
        self._card(self.patent_id, files=[("add_files", _png("p2")), ("add_files", _png("p3"))])
        doc_id = self.patent_id
        html = self.client.get("/hr/documents?status=all&document_type_id=0").text
        match = re.search(r'data-download-url="/documents/files/%d\?page=1" data-preview-pages="([^"]+)">Открыть \(3 стр\.\)<'
                          % doc_id, html)
        self.assertIsNotNone(match)
        pages = json.loads(unescape(match.group(1)))
        self.assertEqual([p["url"] for p in pages], [f"/documents/preview/{doc_id}?page={n}" for n in (1, 2, 3)])
        self.assertIn('name="file" accept="image/*,.pdf,.heic" multiple', html)

    # Карточка документа
    def _card(self, doc_id, **kwargs):
        doc = self.Session().get(EmployeeDocument, doc_id)
        data = {"document_number": doc.document_number or "", "issue_date": "2026-08-18",
                "extra_field_1_value": doc.extra_field_1_value or "", "extra_field_2_value": doc.extra_field_2_value or ""}
        return self.client.post(f"/hr/documents/card/{doc_id}", data=data, follow_redirects=False, **kwargs)

    def test_card_adds_pages_keeps_status(self):
        self._card(self.patent_id, files=[("add_files", _png("b")), ("add_files", _png("c"))])
        doc = self.Session().get(EmployeeDocument, self.patent_id)
        self.assertEqual([p["name"] for p in document_pages(doc)], ["патент.png", "b.png", "c.png"])
        self.assertEqual(doc.status, "verified")
        audit = self.Session().query(AuditLog).filter(AuditLog.action == "document_edited").all()[-1]
        self.assertIn("pages", json.loads(audit.new_value))
        html = self.client.get(f"/hr/documents/card/{self.patent_id}").text
        self.assertIn("Страницы (3)", html)
        self.assertEqual(len(re.findall(r'/pages/\d/remove"', html)), 3)

    def test_card_replace_all_pages(self):
        self._card(self.patent_id, files=[("add_files", _png("b"))])
        self._card(self.patent_id, files=[("file", _png("x")), ("file", _png("y"))])
        doc = self.Session().get(EmployeeDocument, self.patent_id)
        self.assertEqual([p["name"] for p in document_pages(doc)], ["x.png", "y.png"])
        self.assertTrue(storage_exists(OLD_KEY))  # прежний файл — в хранилище и в аудите

    def test_card_page_limit(self):
        response = self._card(self.patent_id, files=[("add_files", _png(f"p{i}")) for i in range(MAX_DOCUMENT_PAGES)])
        self.assertIn(f"Не больше {MAX_DOCUMENT_PAGES} страниц", self._location(response))
        self.assertEqual(len(document_pages(self.Session().get(EmployeeDocument, self.patent_id))), 1)

    def test_remove_pages(self):
        self._card(self.patent_id, files=[("add_files", _png("b")), ("add_files", _png("c"))])
        url = f"/hr/documents/card/{self.patent_id}/pages/1/remove"
        self.assertIn("Страница 1 убрана", self._location(self.client.post(url, follow_redirects=False)))
        doc = self.Session().get(EmployeeDocument, self.patent_id)
        self.assertEqual([p["name"] for p in document_pages(doc)], ["b.png", "c.png"])  # 2-я стала первой
        self.assertEqual(doc.original_filename, "b.png")
        self.assertTrue(storage_exists(OLD_KEY))
        audit = self.Session().query(AuditLog).filter(AuditLog.action == "document_page_removed").one()
        self.assertEqual(json.loads(audit.old_value)["file_path"], OLD_KEY)
        self.client.post(f"/hr/documents/card/{self.patent_id}/pages/2/remove")
        self.client.post(f"/hr/documents/card/{self.patent_id}/pages/1/remove")
        doc = self.Session().get(EmployeeDocument, self.patent_id)
        self.assertEqual((doc.file_path, doc.status, document_pages(doc)), (None, "verified", []))
        self.assertIn("Страница не найдена", self._location(self.client.post(url, follow_redirects=False)))

    def test_remove_page_needs_manage(self):
        self._as(50)  # экономист: documents.verify без documents.manage
        response = self.client.post(f"/economist/documents/card/{self.patent_id}/pages/1/remove",
                                    follow_redirects=False)
        self.assertIn("Нет права менять документы", self._location(response))
        self.assertEqual(self.Session().get(EmployeeDocument, self.patent_id).file_path, OLD_KEY)

    def test_hard_delete_removes_all_page_files(self):
        self._card(self.patent_id, files=[("add_files", _png("b"))])
        keys = [p["key"] for p in document_pages(self.Session().get(EmployeeDocument, self.patent_id))]
        self._as(40)  # суперадмин
        self.client.post(f"/admin/documents/card/{self.patent_id}/delete")
        self.assertIsNone(self.Session().get(EmployeeDocument, self.patent_id))
        self.assertEqual(self.Session().query(EmployeeDocumentPage).count(), 0)
        self.assertFalse(any(storage_exists(k) for k in keys))

    # Кабинет сотрудника
    def test_cabinet_upload_and_add_pages(self):
        self._as(1)
        response = self.client.post("/cabinet/documents/upload", data={"document_type_id": str(self.passport_type)},
                                    files=[("file", _png("s1")), ("file", _png("s2"))], follow_redirects=False)
        self.assertIn("Документ загружен", self._location(response))
        doc = self._newest()
        self.assertEqual((doc.status, len(document_pages(doc))), ("pending_verification", 2))
        response = self.client.post(f"/cabinet/documents/{doc.id}/pages", files=[("file", _png("s3"))],
                                    follow_redirects=False)
        self.assertIn("Добавлено страниц: 1", self._location(response))
        self.assertEqual([p["name"] for p in document_pages(self._newest())], ["s1.png", "s2.png", "s3.png"])
        self.assertEqual(self.Session().query(AuditLog).filter(AuditLog.action == "document_pages_added").count(), 1)

    def test_cabinet_cannot_add_to_verified_or_foreign(self):
        self._as(1)
        response = self.client.post(f"/cabinet/documents/{self.patent_id}/pages", files=[("file", _png("z"))],
                                    follow_redirects=False)
        self.assertIn("Документ уже проверен", self._location(response))
        db = self.Session()
        db.add(User(id=61, employee_name="Другой Сотрудник", role="employee"))
        db.commit()
        db.get(EmployeeDocument, self.patent_id).status = "pending_verification"
        db.commit()
        self._as(61)
        response = self.client.post(f"/cabinet/documents/{self.patent_id}/pages", files=[("file", _png("z"))],
                                    follow_redirects=False)
        self.assertIn("Документ не найден", self._location(response))
        self.assertEqual(len(document_pages(self.Session().get(EmployeeDocument, self.patent_id))), 1)

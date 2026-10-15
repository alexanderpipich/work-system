"""Реестр документов: строка «Не загружен» → карточка документа в режиме создания
(/…/documents/new?user_id=&document_type_id=), без дублей; подписи полей формы — из типа документа."""

import json
import os
import re
import tempfile
from html import unescape
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote, unquote_plus

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from file_storage import reset_client_cache
from models import AuditLog, CitizenshipRegime, DocumentType, EmployeeDocument, RegimeDocumentRule
from test_document_card import S3_ENV, seed as seed_card
from test_documents_contracts import EMP, _session
from test_predemo_p411 import _Client

REGISTRY = "/hr/documents?status=all&document_type_id=0"


def seed(session):
    seed_card(session)
    regime = session.query(CitizenshipRegime).filter(CitizenshipRegime.code == "patent").one()
    reg = session.query(DocumentType).filter(DocumentType.name == "РЕГИСТРАЦИЯ").one()
    reg.extra_field_1_label, reg.extra_field_2_label = "Адрес регистрации", "Принимающая сторона"
    reg.allow_permanent = False
    session.add(RegimeDocumentRule(regime_id=regime.id, document_type_id=reg.id))  # обязательна — строки нет
    session.commit()


class DocumentCreateTests(_Client):
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
        super().setUp()
        self._as(11)  # кадровик
        db = self.Session()
        self.reg = db.query(DocumentType).filter(DocumentType.name == "РЕГИСТРАЦИЯ").one().id
        self.patent_type = db.query(DocumentType).filter(DocumentType.name == "ПАТЕНТ").one().id
        self.new_url = f"/hr/documents/new?user_id=1&document_type_id={self.reg}"

    def tearDown(self):
        super().tearDown()
        self._env.stop()
        self._tmp.cleanup()
        reset_client_cache()

    def _regs(self):
        return self.Session().query(EmployeeDocument).filter(EmployeeDocument.document_type_id == self.reg).all()

    def _post(self, **fields):
        data = {"user_id": "1", "document_type_id": str(self.reg), "back": REGISTRY, "document_number": "R-1",
                "issue_date": "2026-09-01", "expiry_date": "2026-12-01", "extra_field_1_value": "СПб, Лиговский 30"}
        data.update(fields)
        return self.client.post("/hr/documents/new", data=data, follow_redirects=False)

    def test_missing_row_links_to_create(self):
        html = self.client.get(REGISTRY).text
        href = re.search(r'<tr[^>]* class="row-link" data-row-href="([^"]+)"', html)
        self.assertIsNotNone(href)
        url = unescape(href.group(1))
        self.assertTrue(url.startswith(self.new_url + "&back="))
        self.assertTrue(url.endswith("&back=" + quote(REGISTRY, safe="/")))  # возврат в реестр с фильтрами
        self.assertIn(f'href="{href.group(1)}">Добавить</a>', html)
        self.assertEqual(html.count('class="row-link"'), 1)  # у строк с документом — нет

    def test_no_link_without_manage(self):
        self._as(50)  # экономист: documents.verify без documents.manage
        html = self.client.get("/economist/documents?status=all&document_type_id=0").text
        self.assertIn("Не загружен", html)
        self.assertNotIn("/documents/new?", html)
        response = self.client.get(f"/economist/documents/new?user_id=1&document_type_id={self.reg}",
                                   follow_redirects=False)
        self.assertIn("Нет права добавлять документы", unquote_plus(response.headers["location"]))
        self._post()
        self.assertEqual(self._regs(), [])

    def test_create_card_fields_from_type(self):
        html = self.client.get(self.new_url + "&back=" + quote(REGISTRY, safe="")).text
        self.assertIn("новый документ", html)
        self.assertIn(EMP, html)
        self.assertIn('action="/hr/documents/new"', html)
        self.assertIn('name="user_id" value="1"', html)
        self.assertIn(f'name="document_type_id" value="{self.reg}"', html)
        self.assertIn("<label>Адрес регистрации</label>", html)
        self.assertIn("<label>Принимающая сторона</label>", html)
        self.assertIn("(обязателен)", html)  # срок — тип требует
        self.assertNotIn('name="is_permanent"', html)  # тип не разрешает «бессрочно»
        self.assertIn('name="add_files"', html)
        self.assertNotIn("Удалить документ", html)

    def test_save_creates_and_returns_to_registry(self):
        response = self._post()
        location = unquote_plus(response.headers["location"])
        self.assertTrue(location.startswith(REGISTRY + "&message="))
        self.assertIn("Документ «РЕГИСТРАЦИЯ» добавлен", location)
        [doc] = self._regs()
        self.assertEqual((doc.user_id, doc.employee_name, doc.status, doc.document_number, doc.extra_field_1_value,
                          doc.uploaded_by), (1, EMP, "pending_verification", "R-1", "СПб, Лиговский 30", 11))
        audit = self.Session().query(AuditLog).filter(AuditLog.action == "document_created").one()
        self.assertEqual(int(audit.entity_id), doc.id)
        html = self.client.get(REGISTRY).text
        self.assertNotIn('class="row-link"', html)  # строка уже с документом

    def test_save_with_files(self):
        response = self.client.post("/hr/documents/new", data={
            "user_id": "1", "document_type_id": str(self.reg), "expiry_date": "2026-12-01"},
            files=[("add_files", ("r1.png", b"\x89PNG 1", "image/png")),
                   ("add_files", ("r2.png", b"\x89PNG 2", "image/png"))], follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        [doc] = self._regs()
        self.assertEqual((doc.original_filename, [p.original_filename for p in doc.pages]), ("r1.png", ["r2.png"]))

    def test_no_duplicate(self):
        self._post()
        response = self._post(document_number="R-2")
        self.assertEqual(len(self._regs()), 1)
        doc_id = self._regs()[0].id
        location = unquote_plus(response.headers["location"])
        self.assertTrue(location.startswith(f"/hr/documents/card/{doc_id}?back="))
        self.assertIn("уже есть — открыта его карточка", location)
        response = self.client.get(self.new_url, follow_redirects=False)  # второй клик по старой ссылке
        self.assertTrue(response.headers["location"].startswith(f"/hr/documents/card/{doc_id}"))

    def test_archived_does_not_block(self):
        self._post()
        db = self.Session()
        db.query(EmployeeDocument).filter(EmployeeDocument.document_type_id == self.reg).one().status = "archived"
        db.commit()
        self.assertEqual(self.client.get(self.new_url).status_code, 200)
        self._post(document_number="R-2")
        self.assertEqual(sorted(d.document_number for d in self._regs()), ["R-1", "R-2"])

    def test_required_expiry(self):
        response = self._post(expiry_date="")
        location = unquote_plus(response.headers["location"])
        self.assertTrue(location.startswith(f"/hr/documents/new?user_id=1&document_type_id={self.reg}"))
        self.assertIn("нужна дата окончания", location)
        self.assertEqual(self._regs(), [])

    def test_admin_path_for_superadmin(self):
        self._as(40)
        html = self.client.get("/admin/documents?status=all&document_type_id=0").text
        self.assertIn(f"/admin/documents/new?user_id=1&amp;document_type_id={self.reg}", html)

    def test_manual_form_labels_and_patent_parts(self):
        html = self.client.get(REGISTRY).text
        fields = json.loads(unescape(re.search(r'data-type-fields="([^"]+)"', html).group(1)))
        self.assertEqual(fields[str(self.reg)]["extra1"], "Адрес регистрации")
        self.assertTrue(fields[str(self.patent_type)]["patent"])
        for name in ("patent_series", "patent_number", "patent_blank_series", "patent_blank_number"):
            self.assertIn(f'name="{name}"', html)
        self.client.post("/hr/documents/upload", data={
            "employee_name": EMP, "document_type_id": str(self.patent_type), "patent_parts": "1",
            "patent_series": "78", "patent_number": "2600999999", "patent_blank_series": "пр",
            "patent_blank_number": "1234567", "issue_date": "2026-10-01", "expiry_date": "2027-09-30"},
            follow_redirects=False)
        doc = self.Session().query(EmployeeDocument).order_by(EmployeeDocument.id.desc()).first()
        self.assertEqual(doc.document_number, "78 №2600999999 / ПР 1234567")

    def test_manual_form_requires_expiry_when_type_requires(self):
        response = self.client.post("/hr/documents/upload", data={
            "employee_name": EMP, "document_type_id": str(self.reg), "document_number": "R-9"},
            follow_redirects=False)
        self.assertIn("нужна дата окончания", unquote_plus(response.headers["location"]))
        self.assertEqual(self._regs(), [])
        self._as(1)  # сотрудник из кабинета — без дат, как раньше
        self.client.post("/cabinet/documents/upload", data={"document_type_id": str(self.reg)},
                         files=[("file", ("r.png", b"\x89PNG r", "image/png"))], follow_redirects=False)
        self.assertEqual(len(self._regs()), 1)

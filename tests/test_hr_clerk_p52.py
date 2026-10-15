"""П5.2: кадровик правит личные поля карточки сотрудника (users.edit_personal), патент без бланка
и профессии не отмечается проверенным, тур кадровика (data/tours/hr_clerk.json)."""

import json
import os
import re
import unittest
from datetime import date
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import quote, unquote_plus

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from models import (AuditLog, CitizenshipRegime, Country, DocumentType, EmployeeDocument, RegimeDocumentRule,
                    TourSettings, User)
from rbac import has_permission
from test_documents_contracts import EMP, _session, seed as seed_contracts
from test_predemo_p411 import _Client
from tours import TOUR_IDS, build_tour_context, load_tour, tour_for_user

CLERK = SimpleNamespace(role="hr_clerk", is_admin=False, tour_seen_at=None)


def seed(session):
    seed_contracts(session)
    session.add(User(id=50, employee_name="Экономист", role="economist", phone="70000000050", password_hash="x"))
    snils = session.query(DocumentType).filter(DocumentType.name == "СНИЛС").one()
    regime = session.query(CitizenshipRegime).filter(CitizenshipRegime.code == "patent").one()
    session.add(RegimeDocumentRule(regime_id=regime.id, document_type_id=snils.id))  # строка в реестре
    # документ «на проверке» — якорь шага «Откуда берутся документы»
    session.add(EmployeeDocument(id=300, user_id=1, employee_name=EMP, document_type_id=snils.id,
                                 document_number="123-456-789 00", status="pending_verification"))
    session.commit()


def _anchors(html):
    return set(re.findall(r'data-tour="([^"]+)"', html))


class PermissionTests(unittest.TestCase):
    def test_edit_personal(self):
        for role, expected in (("hr_clerk", True), ("hr_lead", True), ("superadmin", True), ("tm", False),
                               ("economist", False), ("employee", False)):
            with self.subTest(role=role):
                self.assertEqual(has_permission(SimpleNamespace(role=role, is_admin=False), "users.edit_personal"),
                                 expected)
        self.assertFalse(has_permission(SimpleNamespace(role="hr_clerk", is_admin=False), "users.manage"))


class ClerkEditsEmployeeTests(_Client):
    seed = staticmethod(seed)

    def make_session(self):
        return _session()

    def setUp(self):
        super().setUp()
        self._as(11)  # кадровик

    def _post(self, **fields):
        data = {"user_id": "1", **fields}
        return self.client.post("/admin/update-user", data=data, follow_redirects=False)

    def test_personal_fields_saved_rest_ignored(self):
        ru = self.Session().query(Country).filter(Country.name == "Россия").one()
        response = self._post(birth_date="1999-04-02", gender="f", citizenship_country_id=str(ru.id),
                              job_title="РТЗ", is_student=["", "1"], inn="780114424010",
                              # чужие поля — отбрасываются без ошибки
                              employee_name="Новое ФИО", role="superadmin", phone="79990001122", tm_id="11",
                              password="secret", new_password="secret", legal_entity="", email="x@example.com",
                              scope_cities="Москва")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["location"].endswith("#user-1"))
        user = self.Session().get(User, 1)
        self.assertEqual((user.birth_date, user.gender, user.citizenship_country_id, user.job_title, user.is_student),
                         (date(1999, 4, 2), "f", ru.id, "РТЗ", True))
        self.assertEqual((user.employee_name, user.role, user.phone, user.tm_id, user.legal_entity, user.email,
                          user.password_hash), (EMP, "employee", None, 10, "ООО «Новая»", None, None))
        audit = self.Session().query(AuditLog).filter(AuditLog.action == "user_updated").one()
        self.assertEqual(audit.user_id, 11)
        new = json.loads(audit.new_value)
        self.assertEqual(set(new), {"birth_date", "gender", "citizenship_country_id", "job_title", "is_student"})
        self.assertEqual(json.loads(audit.old_value)["birth_date"], "1998-03-21")

    def test_absent_fields_unchanged(self):
        self._post(role="hr_lead", phone="79990001122")
        user = self.Session().get(User, 1)
        self.assertEqual((user.birth_date, user.role, user.phone, user.is_student), (date(1998, 3, 21), "employee",
                                                                                     None, False))
        self.assertEqual(self.Session().query(AuditLog).filter(AuditLog.action == "user_updated").count(), 0)
        # чекбокс снят: скрытое пустое значение без «1»
        self._post(is_student=[""])
        self.assertFalse(self.Session().get(User, 1).is_student)

    def test_other_roles_forbidden(self):
        for user_id in (10, 50, 30):  # ТМ, экономист, руководитель
            with self.subTest(user_id=user_id):
                before = self.Session().get(User, user_id)
                response = self._post(user_id=str(user_id), birth_date="1990-01-01", role="employee")
                self.assertEqual(response.status_code, 403)
                after = self.Session().get(User, user_id)
                self.assertEqual((after.role, after.birth_date), (before.role, before.birth_date))
        denied = self.Session().query(AuditLog).filter(AuditLog.action == "users.denied").all()
        self.assertEqual(sorted(int(a.entity_id) for a in denied), [10, 30, 50])

    def test_password_and_delete_still_closed(self):
        self.client.post("/admin/change-password", data={"user_id": "1", "new_password": "x123456"})
        self.client.post("/admin/delete-user", data={"user_id": "1"})
        user = self.Session().get(User, 1)
        self.assertIsNotNone(user)
        self.assertIsNone(user.password_hash)

    def test_card_shows_personal_form_only_for_employees(self):
        html = self.client.get("/admin/users").text
        employee = html[html.index('id="user-1"'):]
        employee = employee[:employee.index("</details>")]
        self.assertIn("data-personal-form", employee)
        for name in ("birth_date", "gender", "citizenship_country_id", "job_title", "inn", "is_student"):
            self.assertIn(f'name="{name}"', employee)
        for name in ("role", "phone", "tm_id", "legal_entity", "email", "new_password", "scope_cities"):
            self.assertNotIn(f'name="{name}"', employee)
        self.assertIn(f'value="{EMP}" readonly', employee)  # ФИО — только чтение
        self.assertIn("/hr/documents?employee_name=" + quote(EMP), employee)
        tm = html[html.index('id="user-10"'):]
        tm = tm[:tm.index("</details>")]
        self.assertNotIn("<form", tm)

    def test_hr_lead_keeps_full_form(self):
        self._as(30)
        html = self.client.get("/admin/users").text
        self.assertNotIn("data-personal-form", html)
        self.assertIn('name="role" data-role-select', html)


class PatentVerifyTests(_Client):
    seed = staticmethod(seed)

    def make_session(self):
        return _session()

    def setUp(self):
        super().setUp()
        self._as(11)
        db = self.Session()
        self.patent = db.query(EmployeeDocument).filter(EmployeeDocument.document_number.like("78 №%")).one()
        self.patent.status, self.patent.document_number, self.patent.extra_field_2_value = (
            "pending_verification", "78 №2600131320", None)
        db.commit()
        self.patent_id = self.patent.id

    def _status(self, doc_id):
        return self.Session().get(EmployeeDocument, doc_id).status

    def test_single_verify_refused_with_fields(self):
        response = self.client.post("/hr/documents/verify", data={"document_id": self.patent_id, "status": "all"},
                                    follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        location = unquote_plus(response.headers["location"])
        self.assertIn("Патент нельзя отметить проверенным: не заполнено — серия бланка, номер бланка, "
                      "профессия по патенту.", location)
        self.assertEqual(self._status(self.patent_id), "pending_verification")

    def test_bulk_skips_patent_verifies_others(self):
        response = self.client.post("/hr/documents/verify-bulk", data={"document_ids": [self.patent_id, 300]},
                                    follow_redirects=False)
        self.assertIn("пропущено 1 (патент без бланка или профессии: 1)", unquote_plus(response.headers["location"]))
        self.assertEqual((self._status(self.patent_id), self._status(300)), ("pending_verification", "verified"))

    def test_filled_patent_verifies(self):
        db = self.Session()
        patent = db.get(EmployeeDocument, self.patent_id)
        patent.document_number, patent.extra_field_2_value = "78 №2600131320 / ПР 8408114", "подсобный рабочий"
        db.commit()
        self.client.post("/hr/documents/verify", data={"document_id": self.patent_id}, follow_redirects=False)
        self.assertEqual(self._status(self.patent_id), "verified")

    def test_only_profession_missing(self):
        db = self.Session()
        db.get(EmployeeDocument, self.patent_id).document_number = "78 №2600131320 / ПР 8408114"
        db.commit()
        location = unquote_plus(self.client.post("/hr/documents/verify", data={"document_id": self.patent_id},
                                                 follow_redirects=False).headers["location"])
        self.assertIn("не заполнено — профессия по патенту.", location)


class ClerkTourDataTests(unittest.TestCase):
    def _steps(self, demo=""):
        with patch.dict(os.environ, {"TOUR_DEMO_EMPLOYEE": demo}):
            return tour_for_user(CLERK)["steps"]

    def test_registered(self):
        self.assertIn("hr_clerk", TOUR_IDS)
        tour = tour_for_user(CLERK)
        self.assertEqual((tour["id"], tour["start_url"]), ("hr_clerk", "/hr"))

    def test_shape_with_demo(self):
        steps = self._steps("Гаффуров Мурод Мехмоналиевич")
        cards = [s for s in steps if s["type"] != "navigate"]
        self.assertEqual(len(cards), 14)
        self.assertEqual([s.get("anchor") for s in cards], [
            None, "rail", ["docs-expiry-banner", "docs-expiry"], "docs-table", "docs-pending", "docs-open",
            "docs-verify", "employees-first", "docs-table", "contracts-create", "contracts-petition",
            "contracts-recommendation", None, None])
        name = quote("Гаффуров Мурод Мехмоналиевич")
        self.assertEqual([s["url"] for s in steps if s["type"] == "navigate"], [
            "/hr/documents?status=all&document_type_id=0", "/admin/users?role=employee",
            f"/hr/documents?employee_name={name}&document_type_id=0&status=all", f"/admin/contracts?q={name}"])
        self.assertEqual(len(cards[-2]["tiles"]), 1)
        self.assertEqual(cards[-2]["tiles"][0]["title"], "Уведомления в МВД")
        self.assertEqual((cards[0]["next_label"], cards[-1]["next_label"]), ("Начать", "Готово"))

    def test_without_demo_steps_dropped(self):
        steps = self._steps("")
        titles = [s.get("title") for s in steps if s["type"] != "navigate"]
        self.assertEqual(len(titles), 10)
        for title in ("Документы одного сотрудника", "Договор", "Ходатайство", "Рекомендательное письмо"):
            self.assertNotIn(title, titles)
        self.assertEqual([s["url"] for s in steps if s["type"] == "navigate"],
                         ["/hr/documents?status=all&document_type_id=0", "/admin/users?role=employee"])
        self.assertFalse(any("requires" in s for s in steps))

    def test_texts_from_owner_draft(self):
        text = json.dumps(load_tour("hr_clerk"), ensure_ascii=False)
        for phrase in (
                "Это рабочее место специалиста по кадровому учёту.",
                "Система напоминает за 30, 14 и 7 дней и в день окончания",
                "Пока они не заполнены, патент нельзя отметить проверенным",
                "Адресат подбирается по месту работы сотрудника",
                "Роли, пароли и выплаты остаются у руководителя и экономиста.",
                "Тур можно открыть снова кнопкой «?»."):
            self.assertIn(phrase, text)
        step = next(s for s in load_tour("hr_clerk")["steps"] if s.get("title") == "Карточки сотрудников")
        self.assertNotIn("ФИО", step["body"])  # ФИО кадровик не правит (решение владельца)

    def test_settings_from_tour_page(self):
        settings = {"autostart_mode": "always", "demo_employee": "Гаффуров Мурод Мехмоналиевич"}
        with patch.dict(os.environ, {"TOUR_AUTOSTART": "off", "TOUR_DEMO_EMPLOYEE": ""}):
            ctx = build_tour_context(CLERK, "/hr", settings=settings)
            steps = tour_for_user(CLERK, settings)["steps"]
        self.assertEqual((ctx["id"], ctx["mode"], ctx["autostart"]), ("hr_clerk", "always", True))
        self.assertTrue(ctx["demo_norm"])
        self.assertIn("Ходатайство", [s.get("title") for s in steps])


class ClerkTourPagesTests(_Client):
    seed = staticmethod(seed)

    def make_session(self):
        return _session()

    def setUp(self):
        super().setUp()
        self._as(11)

    def test_anchors_exist_for_clerk(self):
        with patch.dict(os.environ, {"TOUR_DEMO_EMPLOYEE": EMP}):
            tour = tour_for_user(CLERK)
            page, pages = tour["start_url"], {}
            for step in tour["steps"]:
                if step["type"] == "navigate":
                    page = step["url"]
                    continue
                if step["type"] != "element":
                    continue
                if page not in pages:
                    response = self.client.get(page)
                    self.assertEqual(response.status_code, 200, page)
                    pages[page] = _anchors(response.text)
                names = step["anchor"] if isinstance(step["anchor"], list) else [step["anchor"]]
                with self.subTest(page=page, anchor=step["anchor"]):
                    self.assertTrue(set(names) & pages[page], f"{step['anchor']} нет на {page}")

    def test_petition_anchor_in_demo_row(self):
        with patch.dict(os.environ, {"TOUR_DEMO_EMPLOYEE": EMP}):
            html = self.client.get("/admin/contracts").text
        self.assertRegex(html, r'href="/admin/contracts/petition/1" data-tour="contracts-petition"')
        self.assertEqual(html.count('data-tour="contracts-petition"'), 1)

    def test_pending_anchor_only_on_pending_row(self):
        html = self.client.get("/hr/documents?status=all&document_type_id=0").text
        self.assertEqual(html.count('data-tour="docs-pending"'), 1)
        self.assertEqual(html.count('data-tour="docs-open"'), 1)
        row = html[html.index('data-tour="docs-pending"'):]
        self.assertIn("СНИЛС", row[:row.index("</tr>")])
        db = self.Session()
        db.get(EmployeeDocument, 300).status = "verified"
        db.commit()
        html = self.client.get("/hr/documents?status=all&document_type_id=0").text
        self.assertNotIn('data-tour="docs-pending"', html)  # нет строки «на проверке» — шаг пропустится

    def test_tour_data_and_config(self):
        db = self.Session()
        db.add(TourSettings(autostart_mode="always", demo_employee=EMP))
        db.commit()
        data = self.client.get("/tour/data").json()
        self.assertEqual((data["id"], data["start_url"]), ("hr_clerk", "/hr"))
        self.assertEqual(data["settings"]["source"]["demo_employee"], "настройки")
        self.assertIn("Ходатайство", [s.get("title") for s in data["steps"]])

    def test_clerk_listed_on_tour_settings_page(self):
        self._as(40)
        html = self.client.get("/admin/tour-settings").text
        self.assertIn("Кадровик", html)
        self.assertIn("Руководители и кадровики в списке всегда", html)


if __name__ == "__main__":
    unittest.main()

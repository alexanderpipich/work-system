"""П5: демо-туры — данные туров, якоря в шаблонах, режимы TOUR_AUTOSTART, «тур просмотрен»,
тур по роли; кабинет сотрудника — «От компании», «Поддержка», «Вакансии»; подпись «Руководитель»."""

import json
import os
import re
import unittest
from datetime import date, timedelta
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from fastapi import Request
from sqlalchemy.orm import sessionmaker

from document_alerts import run_document_expiry_alerts
from models import (AuditLog, CitizenshipRegime, Country, DocumentExpiryAlert, DocumentType, EmployeeDocument,
                    EmployeeQr, RegimeDocumentRule, Shift, User)
from rbac import ROLE_LABELS
from utils import get_password_hash
from test_payouts import A, WEEK, _engine, _shift, seed as seed_payouts
from test_predemo_p411 import _Client
from time_helpers import business_today
from tours import STEP_TYPES, TOUR_IDS, build_tour_context, load_tour, tour_for_user
from urllib.parse import quote
from utils import normalize_person_name

NO_REQ = "Деревянко Дмитрий"
HR_LEAD = SimpleNamespace(role="hr_lead", is_admin=False, tour_seen_at=None)  # сотрудник со сменами, но без реквизитов — розовая строка


def seed(session):
    seed_payouts(session)
    session.add(User(id=5, employee_name=NO_REQ, role="employee", tm_id=11))
    session.add(_shift(NO_REQ, WEEK + timedelta(days=1)))
    no_plan = _shift(A, WEEK + timedelta(days=5), hours=0)
    no_plan.request_type = "Смена без плана"
    session.add(no_plan)
    # Кабинет сотрудника: вход, QR, закреплённый ТМ (Пиунов Андрей, id=10).
    employee = session.get(User, 1)
    employee.phone, employee.password_hash = "70000000001", "x"
    session.add(EmployeeQr(user_id=1, image_path="uploaded_documents/qr/1.png", label="Пропуск"))
    for i, name in enumerate(("ТРУДОВОЙ ДОГОВОР", "РЕКОМЕНДАТЕЛЬНОЕ ПИСЬМО", "ПАТЕНТ"), 1):
        session.add(DocumentType(id=100 + i, name=name))
    session.add_all([
        EmployeeDocument(id=201, user_id=1, employee_name=A, document_type_id=101, document_number="26-0007",
                         issue_date=date(2026, 10, 1), file_path="generated_files/contracts/a.docx", status="uploaded"),
        EmployeeDocument(id=202, user_id=1, employee_name=A, document_type_id=102, issue_date=date(2026, 10, 13),
                         file_path="generated_files/contracts/a_rec.docx", status="uploaded"),
        # не «от компании» и не своё — в блок не попадают
        EmployeeDocument(id=203, user_id=1, employee_name=A, document_type_id=103,
                         file_path="uploaded_documents/patent.jpg", status="verified"),
        EmployeeDocument(id=204, user_id=2, employee_name="Борисова Вера", document_type_id=101,
                         document_number="26-0099", file_path="generated_files/contracts/b.docx", status="uploaded"),
        # договор без файла и архивный — тоже нет
        EmployeeDocument(id=205, user_id=1, employee_name=A, document_type_id=101, document_number="26-0001",
                         status="uploaded"),
        EmployeeDocument(id=206, user_id=1, employee_name=A, document_type_id=101, document_number="26-0002",
                         file_path="generated_files/contracts/old.docx", status="archived"),
    ])
    session.commit()


def _anchors(html):
    return set(re.findall(r'data-tour="([^"]+)"', html))


class TourDataTests(unittest.TestCase):
    def test_tours_are_valid(self):
        for tour_id in TOUR_IDS:
            with self.subTest(tour=tour_id):
                tour = load_tour(tour_id)
                self.assertEqual((tour["id"], tour["version"]), (tour_id, 1))
                self.assertTrue(tour["start_url"].startswith("/"))
                for step in tour["steps"]:
                    self.assertIn(step["type"], STEP_TYPES)
                    if step["type"] == "navigate":
                        self.assertTrue(step["url"].startswith("/") or step["url"] == "@start")
                        continue
                    self.assertTrue(step["title"])
                    for text in [step["title"], step.get("body", "")] + [
                            t[k] for t in step.get("tiles", []) for k in ("title", "text")]:
                        self.assertNotRegex(text, r"<[a-zA-Z/]")  # никакого HTML
                    if step["type"] == "element":
                        self.assertTrue(step["anchor"])
                        self.assertIn(step["placement"], ("right", "left", "top", "bottom"))

    def test_employee_tour_shape(self):
        steps = load_tour("employee")["steps"]
        self.assertEqual(len(steps), 9)
        self.assertEqual([s["type"] for s in steps], ["screen"] + ["element"] * 7 + ["screen"])
        self.assertEqual([s.get("anchor") for s in steps[1:8]],
                         ["qr", "docs-panel", "stats", "nav-docs", "nav-stores", "nav-vacancies", "nav-support"])
        self.assertEqual((steps[0]["next_label"], steps[-1]["next_label"]), ("Начать", "Закрыть"))

    def test_hr_lead_tour_shape(self):
        with patch.dict(os.environ, {"TOUR_DEMO_EMPLOYEE": ""}):
            steps = tour_for_user(HR_LEAD)["steps"]
        shown = [s for s in steps if s["type"] != "navigate"]
        self.assertEqual(len(shown), 26)  # 0a–0c + шаги 1–23; без демо-сотрудника — как раньше
        self.assertEqual([s["url"] for s in steps if s["type"] == "navigate"], [
            "/admin/payouts/weekly", "/admin/payouts/advances", "/hr/documents?status=all&document_type_id=0",
            "/admin/contracts", "/hr/team", "/hr"])
        self.assertNotIn("Документы сотрудника", [s["title"] for s in shown])
        self.assertFalse(any("requires" in s or "url_demo" in s for s in steps))
        self.assertEqual(len(shown[1]["tiles"]), 7)
        self.assertEqual(shown[1]["tiles"][0]["title"], "Руководитель")
        self.assertEqual([t["title"] for t in shown[-2]["tiles"]], ["Уведомления в МВД", "Связка с CRM найма."])
        text = json.dumps(steps, ensure_ascii=False)
        for word in ("Автозагрузка timebook", "Коммуникации", "[РЕШИТЬ]"):
            self.assertNotIn(word, text)
        self.assertTrue(shown[-3].get("expand"))  # «Остальные разделы» — полоса раскрыта

    def test_texts_verbatim_from_owner_files(self):
        """Ключевые фразы — дословно из P5_1_…_v2.md и P5_2_…_v3.md (docs/tours)."""
        employee = json.dumps(load_tour("employee"), ensure_ascii=False)
        hr_lead = json.dumps(load_tour("hr_lead"), ensure_ascii=False)
        self.assertIn("Это ваш QR-код. Показывайте его на входе и выходе в магазине", employee)
        self.assertIn("Готово. Тур можно открыть снова в любой момент — кнопка «?» в шапке.", employee)
        self.assertIn("Красным — смены, которые пришли без плана магазина.", hr_lead)
        self.assertIn("аванс и табель ушли в банк → документы под контролем.", hr_lead)


class DemoEmployeeTests(unittest.TestCase):
    """TOUR_DEMO_EMPLOYEE: документы одного сотрудника после акта 3, договоры — с фильтром по ФИО."""

    def test_with_demo_employee(self):
        with patch.dict(os.environ, {"TOUR_DEMO_EMPLOYEE": " Гаффуров  Мурод Мехмоналиевич "}):
            steps = tour_for_user(HR_LEAD)["steps"]
            ctx = build_tour_context(HR_LEAD, "/hr")
        titles = [s.get("title") for s in steps]
        i = titles.index("Документы сотрудника")
        self.assertEqual(titles[i - 2], "Сроки патентов")
        self.assertEqual(steps[i]["anchor"], "docs-table")
        self.assertTrue(steps[i]["body"].startswith("Вот документы одного сотрудника: паспорт, патент, регистрация"))
        name = quote("Гаффуров Мурод Мехмоналиевич")
        self.assertEqual(steps[i - 1], {"type": "navigate", "url":
                         f"/hr/documents?employee_name={name}&document_type_id=0&status=all"})
        self.assertEqual(steps[i + 1], {"type": "navigate", "url": f"/admin/contracts?q={name}"})
        self.assertEqual(len([s for s in steps if s["type"] != "navigate"]), 27)
        self.assertEqual(ctx["demo_norm"], normalize_person_name("Гаффуров Мурод Мехмоналиевич"))


class AutostartTests(unittest.TestCase):
    hr_lead = SimpleNamespace(role="hr_lead", is_admin=False, tour_seen_at=None)

    def ctx(self, path="/hr", query_tour=False, mode="first", user=None):
        return build_tour_context(user or self.hr_lead, path, query_tour, mode)

    def test_modes(self):
        seen = SimpleNamespace(role="hr_lead", is_admin=False, tour_seen_at=date(2026, 10, 14))
        self.assertTrue(self.ctx(mode="always")["autostart"])
        self.assertTrue(self.ctx(mode="always", user=seen)["autostart"])
        self.assertTrue(self.ctx(mode="first")["autostart"])
        self.assertFalse(self.ctx(mode="first", user=seen)["autostart"])
        self.assertFalse(self.ctx(mode="off")["autostart"])

    def test_only_on_start_url(self):
        ctx = self.ctx("/admin/payouts/weekly", mode="always")
        self.assertFalse(ctx["autostart"])
        self.assertEqual((ctx["start_url"], ctx["help_url"]), ("/hr", "/hr?tour=1"))

    def test_query_forces_even_when_off(self):
        self.assertTrue(self.ctx(query_tour=True, mode="off")["force"])
        self.assertFalse(self.ctx("/hr/team", query_tour=True, mode="off")["force"])

    def test_env_default_first(self):
        with patch.dict(os.environ, {"TOUR_AUTOSTART": ""}):
            self.assertEqual(build_tour_context(self.hr_lead, "/hr")["mode"], "first")
        with patch.dict(os.environ, {"TOUR_AUTOSTART": "Always"}):
            self.assertEqual(build_tour_context(self.hr_lead, "/hr")["mode"], "always")

    def test_roles(self):
        employee = SimpleNamespace(role="employee", is_admin=False, tour_seen_at=None)
        self.assertEqual(self.ctx("/cabinet", user=employee)["id"], "employee")
        self.assertEqual(self.ctx(user=employee)["start_url"], "/cabinet")
        for role in ("tm", "economist", "hr_clerk", "superadmin", "brigadier", "headhunter"):
            with self.subTest(role=role):
                self.assertIsNone(self.ctx(user=SimpleNamespace(role=role, is_admin=False, tour_seen_at=None)))


class TourPagesTests(_Client):
    seed = staticmethod(seed)

    def make_session(self):
        return sessionmaker(bind=_engine())

    def _as(self, user_id):
        db = self.Session()
        user = db.get(User, user_id)
        user.qr_codes  # кабинет читает QR после отвязки пользователя от сессии
        db.expunge(user)

        def override(request: Request):
            request.state.user = user
            return user

        self.app.dependency_overrides[self.current_user] = override

    def _page(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200, path)
        return response.text

    def _element_anchors(self, tour_id):
        """Якоря element-шагов по страницам: [(страница, якорь или список запасных)]."""
        tour = tour_for_user(SimpleNamespace(role=tour_id, is_admin=False, tour_seen_at=None))
        page, result = tour["start_url"], []
        for step in tour["steps"]:
            if step["type"] == "navigate":
                page = step["url"]
            elif step["type"] == "element":
                result.append((page, step["anchor"]))
        return result

    def _check_anchors(self, tour_id, params=None):
        pages = {}
        for page, anchor in self._element_anchors(tour_id):
            if page not in pages:
                pages[page] = _anchors(self._page(page + (params or {}).get(page, "")))
            names = anchor if isinstance(anchor, list) else [anchor]
            with self.subTest(page=page, anchor=anchor):
                self.assertTrue(set(names) & pages[page], f"{anchor} нет на {page}")

    def test_hr_lead_anchors_exist(self):
        self._as(30)
        week = f"?week={WEEK.isoformat()}"
        self._check_anchors("hr_lead", {"/admin/payouts/weekly": week, "/admin/payouts/advances": week})
        with patch.dict(os.environ, {"TOUR_DEMO_EMPLOYEE": A}):
            self._check_anchors("hr_lead", {"/admin/payouts/weekly": week, "/admin/payouts/advances": week})

    # Признак «в таблице есть строка данных» по страницам переходов тура руководителя.
    DATA_ROWS = {
        "/admin/payouts/weekly": (r'<tr class="(noreq)?" data-tour="weekly-row"|<tr class="(noreq)?"\s', "Нет смен за неделю"),
        "/admin/payouts/advances": (r'name="employee_names"|<tr>\s*<td', "Нет сотрудников со сменами за неделю"),
        "/hr/documents": (r'data-tour="docs-table"(?:(?!</tbody>).)*?<tr>\s*<td>', "Нет строк по выбранным фильтрам"),
        "/admin/contracts": (r'href="/admin/contracts/contract/\d+"', "Нет сотрудников по фильтрам"),
        "/hr/team": (r'class="tm-block"', None),
    }

    def test_hr_lead_navigate_pages_not_empty(self):
        """Каждый переход тура руководителя открывает страницу, где есть хотя бы одна строка данных:
        реестр документов — со всеми статусами и типами, а не с фильтром «на проверке» по умолчанию."""
        db = self.Session()  # как на демо-копии: у сотрудника гражданство с обязательными документами
        db.add(CitizenshipRegime(id=900, code="patent", name="Патент"))
        db.add(Country(id=900, name="Узбекистан", regime_id=900))
        db.add_all([RegimeDocumentRule(regime_id=900, document_type_id=type_id) for type_id in (101, 102, 103)])
        db.get(User, 1).citizenship_country_id = 900
        db.commit()
        self._as(30)
        week = f"week={WEEK.isoformat()}"  # посев — в фиксированной неделе; на проде — прошлая полная
        for demo in ("", A):
            with patch.dict(os.environ, {"TOUR_DEMO_EMPLOYEE": demo}):
                urls = [s["url"] for s in tour_for_user(HR_LEAD)["steps"] if s["type"] == "navigate"]
            self.assertEqual(urls[-1], "/hr")  # возврат на рабочий стол — без таблицы
            for url in urls[:-1]:
                path = url.split("?")[0]
                with self.subTest(demo=demo, url=url):
                    if path.startswith("/admin/payouts/"):
                        url += ("&" if "?" in url else "?") + week
                    html = self._page(url)
                    rows, empty = self.DATA_ROWS[path]
                    self.assertRegex(html, re.compile(rows, re.S))
                    if empty:
                        self.assertNotIn(empty, html)
        # голый реестр (фильтр по умолчанию «на проверке») в посеве пуст — поэтому переход с параметрами
        self.assertIn("Нет строк по выбранным фильтрам", self._page("/hr/documents"))

    def test_demo_employee_pages(self):
        self._as(30)
        with patch.dict(os.environ, {"TOUR_DEMO_EMPLOYEE": "Борисова Вера"}):
            docs = self._page("/hr/documents?employee_name=" + quote("Борисова Вера") + "&document_type_id=0&status=all")
            self.assertIn('data-tour="docs-table"', docs)
            # кнопки шагов «Договор» / «Рекомендация» — в строке демо-сотрудника (id=2), даже без фильтра
            html = self._page("/admin/contracts")
            self.assertRegex(html, r'href="/admin/contracts/contract/2" data-tour="contracts-create"')
            self.assertRegex(html, r'href="/admin/contracts/recommendation/2" data-tour="contracts-recommendation"')
            self.assertEqual(html.count('data-tour="contracts-create"'), 1)
            filtered = self._page("/admin/contracts?q=" + quote("Борисова Вера"))
            self.assertEqual(re.findall(r'href="/admin/contracts/contract/(\d+)"', filtered), ["2"])
        with patch.dict(os.environ, {"TOUR_DEMO_EMPLOYEE": "Нет Такого"}):
            html = self._page("/admin/contracts")  # строки нет — первая, как раньше
            self.assertEqual(html.count('data-tour="contracts-create"'), 1)
            self.assertNotRegex(html, r'contract/2" data-tour')

    def test_hr_lead_weekly_anchor_cells(self):
        self._as(30)
        html = self._page(f"/admin/payouts/weekly?week={WEEK.isoformat()}")
        for anchor in ("weekly-row", "weekly-norequisites", "weekly-noplan", "weekly-rate", "weekly-tm"):
            self.assertEqual(html.count(f'data-tour="{anchor}"'), 1, anchor)
        self.assertRegex(html, r'<tr class="noreq" data-tour="weekly-norequisites"')
        self.assertRegex(html, r'<td class="day np" data-tour="weekly-noplan"')

    def test_employee_anchors_exist(self):
        self._as(1)
        self._check_anchors("employee")

    def test_tour_config_on_pages(self):
        self._as(30)
        with patch.dict(os.environ, {"TOUR_AUTOSTART": "always"}):
            html = self._page("/hr")
            self.assertIn('"autostart": true', html)
            self.assertIn('src="/static/tour.js', html)
            self.assertIn('href="/static/tour.css', html)
            self.assertIn('<a href="/hr?tour=1" class="tour-help', html)
            inner = self._page("/hr/team")
            self.assertIn('"autostart": false', inner)  # внутри — только продолжение активного тура
            self.assertIn('<a href="/hr?tour=1" class="tour-help', inner)
        with patch.dict(os.environ, {"TOUR_AUTOSTART": "off"}):
            self.assertIn('"autostart": false', self._page("/hr"))
            self.assertIn('"force": true', self._page("/hr?tour=1"))

    def test_no_tour_for_other_roles(self):
        self._as(10)  # ТМ
        html = self._page("/hr")
        self.assertNotIn("WS_TOUR", html)
        self.assertNotIn("tour-help", html)
        self.assertEqual(self.client.get("/tour/data").status_code, 404)
        self.assertEqual(self.client.post("/tour/seen").status_code, 404)

    def test_tour_data_by_role(self):
        self._as(1)
        data = self.client.get("/tour/data").json()
        self.assertEqual((data["id"], data["start_url"]), ("employee", "/cabinet"))
        self.assertIn('<a href="/cabinet?tour=1" class="tour-help', self._page("/cabinet"))
        self._as(30)
        data = self.client.get("/tour/data").json()
        self.assertEqual((data["id"], data["start_url"]), ("hr_lead", "/hr"))
        self.assertEqual([s["url"] for s in data["steps"] if s["type"] == "navigate"][-1], "/hr")

    def test_tour_seen(self):
        self._as(30)
        with patch.dict(os.environ, {"TOUR_AUTOSTART": "first"}):
            self.assertIn('"autostart": true', self._page("/hr"))
            self.assertEqual(self.client.post("/tour/seen").json(), {"ok": True})
            db = self.Session()
            self.assertIsNotNone(db.get(User, 30).tour_seen_at)
            self.assertEqual(db.query(AuditLog).filter(AuditLog.action == "tour.seen").count(), 1)
            self._as(30)  # пользователь перечитан из базы
            self.assertIn('"autostart": false', self._page("/hr"))

    def test_login_clears_tour_flags(self):
        self.app.dependency_overrides.pop(self.current_user, None)
        html = self._page("/login")
        self.assertIn("ws-tour", html)
        self.assertNotIn("WS_TOUR", html)

    # D1
    def test_company_documents_only_own(self):
        self._as(1)
        html = self._page("/employee_docs")
        block = html[html.index('id="company-docs"'):]
        self.assertIn("ТРУДОВОЙ ДОГОВОР №26-0007", block)
        self.assertIn("РЕКОМЕНДАТЕЛЬНОЕ ПИСЬМО", block)
        self.assertIn('href="/documents/files/201"', block)
        self.assertIn('href="/documents/files/202"', block)
        self.assertLess(block.index("РЕКОМЕНДАТЕЛЬНОЕ ПИСЬМО"), block.index("ТРУДОВОЙ ДОГОВОР"))  # новые сверху
        for doc_id in (203, 204, 205, 206):
            self.assertNotIn(f'/documents/files/{doc_id}"', block)
        self.assertNotIn("26-0099", block)
        # чужой файл не отдаётся: /documents/files проверяет «только своё»
        response = self.client.get("/documents/files/204", follow_redirects=False)
        self.assertEqual(response.status_code, 302)

    def test_company_documents_empty(self):
        self._as(5)
        self.assertIn("Документы от компании появятся здесь", self._page("/employee_docs"))

    # D2
    def test_support_with_manager(self):
        self._as(1)
        html = self._page("/support")
        self.assertIn("Пиунов Андрей", html)
        self.assertIn('href="tel:+70000000010"', html)
        self.assertIn("+7 (000) 000-00-10", html)
        self.assertEqual(html.count("<details>"), 6)
        for question in ("Где смотреть", "смена без плана", "загрузить документ", "Когда выплаты",
                         "сменить пароль", "по реквизитам"):
            self.assertIn(question, html)
        self.assertIn("Аванс — еженедельно, если менеджер подал вас на аванс по итогам проверки часов. "
                      "Табель — дважды в месяц: за 1–15 число и за 16-е — конец месяца; "
                      "из него вычитаются уже выданные авансы.", html)

    def test_support_without_manager(self):
        db = self.Session()
        db.get(User, 1).tm_id = None
        db.commit()
        self._as(1)
        self.assertIn("Менеджер пока не назначен", self._page("/support"))

    # Правки по отчёту П5: руководитель получает напоминания о сроках и видит счётчик в шапке.
    def _expiring_patent(self):
        db = self.Session()
        db.get(DocumentType, 103).requires_expiry_date = True
        db.get(EmployeeDocument, 203).expiry_date = business_today() + timedelta(days=20)
        db.commit()
        return run_document_expiry_alerts(db)

    def test_hr_lead_receives_expiry_alerts(self):
        self._expiring_patent()
        recipients = {a.recipient_user_id for a in self.Session().query(DocumentExpiryAlert).all()}
        self.assertIn(30, recipients)  # руководитель
        self.assertIn(10, recipients)  # ТМ сотрудника
        self.assertIn(1, recipients)  # сам сотрудник

    def test_hr_lead_expiry_counter_is_tour_anchor(self):
        self._expiring_patent()
        db = self.Session()
        db.get(User, 30).password_hash = get_password_hash("demo123")
        db.commit()
        self.client.post("/login", data={"phone": "70000000030", "password": "demo123"}, follow_redirects=False)
        self._as(30)
        with patch("main.SessionLocal", self.Session):  # счётчик в шапке считает middleware по своей сессии
            html = self._page("/hr/documents")
        self.assertRegex(html, r'data-tour="docs-expiry-banner"[^>]*>Сроки документов: 1<')
        step = next(s for s in load_tour("hr_lead")["steps"] if s.get("title") == "Сроки патентов")
        self.assertEqual(step["anchor"][0], "docs-expiry-banner")

    # D3
    def test_vacancies_placeholder(self):
        self._as(1)
        html = self._page("/vacancies")
        self.assertIn("Открытые вакансии рядом с вами — списком и точками на карте. Раздел запускаем следующим.", html)
        self.assertIn("placeholder-icon", html)


class RoleLabelTests(unittest.TestCase):
    def test_hr_lead_label(self):
        self.assertEqual(ROLE_LABELS["hr_lead"], "Руководитель")


if __name__ == "__main__":
    unittest.main()

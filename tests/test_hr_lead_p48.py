"""П4.8 A: роль hr_lead — «HR-руководитель»: все права, кроме технических суперадмина;
роли superadmin/hr_lead трогает только суперадмин."""

import datetime
import os
import unittest
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base
from dependencies import current_user, get_db
from models import AuditLog, CitizenshipRegime, Country, PayrollRun, User
from navigation import build_navigation
from rbac import (HR_LEAD_EXCLUDED, PERMISSIONS, ROLE_LABELS, can_manage_role, has_permission,
                  role_choices_for)

HR_LEAD = SimpleNamespace(id=2, role="hr_lead", is_admin=False, employee_name="Петрова HR", phone="70000000002")
SUPERADMIN = SimpleNamespace(id=1, role="superadmin", is_admin=True, employee_name="Админ", phone="70000000001")
# Права кабинетов сотрудника и рекрутера — не «функции», а вход в свой кабинет.
CABINET_ONLY = {"profile.own", "documents.own", "schedules.own", "headhunter.dashboard"}
SUPERADMIN_ONLY = {"shifts.upload", "upload.auto", "admin.settings", "system.technical", "system.maintenance",
                   "payroll.delete", "rates.hard_delete",
                   "legal_entities.hard_delete", "tour.manage"}


class HrLeadPermissionTests(unittest.TestCase):
    def test_label(self):
        self.assertEqual(ROLE_LABELS["hr_lead"], "Руководитель")

    def test_has_every_role_permission_except_own_and_cabinets(self):
        everything = set().union(*(perms for role, perms in PERMISSIONS.items() if role != "hr_lead"))
        for permission in sorted(everything - HR_LEAD_EXCLUDED - CABINET_ONLY):
            with self.subTest(permission=permission):
                self.assertTrue(has_permission(HR_LEAD, permission))

    def test_extra_permissions(self):
        for permission in ("users.manage", "users.hard_delete", "rates.manage", "payroll.manage", "payroll.send",
                           "adjustments.manage", "lmk.manage", "legal_entities.manage", "email.manage",
                           "weekly.manage", "upload.view", "hr_team.manage", "audit.hr_view",
                           "audit.view", "stores.view", "stores.manage",
                           "payroll.close", "payroll.any_period"):
            with self.subTest(permission=permission):
                self.assertTrue(has_permission(HR_LEAD, permission))

    def test_superadmin_only_stays(self):
        for permission in sorted(SUPERADMIN_ONLY | HR_LEAD_EXCLUDED):
            with self.subTest(permission=permission):
                self.assertFalse(has_permission(HR_LEAD, permission))

    def test_any_period_for_hr_lead_not_economist(self):
        from routers.payroll import PERIOD_REFUSAL, period_comment_or_refusal

        start, end = datetime.date(2026, 10, 1), datetime.date(2026, 10, 7)
        for user in (HR_LEAD, SUPERADMIN):
            with self.subTest(role=user.role):
                self.assertEqual(period_comment_or_refusal(user, start, end, "к"), ("[произвольный период] к", None))
        economist = SimpleNamespace(id=5, role="economist", is_admin=False)
        self.assertEqual(period_comment_or_refusal(economist, start, end, "к"), ("к", PERIOD_REFUSAL))

    def test_protected_roles(self):
        self.assertFalse(can_manage_role(HR_LEAD, "superadmin"))
        self.assertFalse(can_manage_role(HR_LEAD, "admin"))
        self.assertFalse(can_manage_role(HR_LEAD, "hr_lead"))
        self.assertTrue(can_manage_role(HR_LEAD, "tm"))
        self.assertTrue(can_manage_role(SUPERADMIN, "hr_lead"))
        codes = [code for code, _ in role_choices_for(HR_LEAD)]
        self.assertNotIn("superadmin", codes)
        self.assertNotIn("hr_lead", codes)
        self.assertIn("economist", codes)

    def test_navigation(self):
        groups = build_navigation(HR_LEAD)  # П4.9: «Выплаты» — группа главного дашборда
        cards = {c["key"]: c for g in groups for c in g["cards"]}
        for key, url in (("users", "/admin/users"), ("rates", "/admin/rates"), ("adjustments", "/admin/adjustments"),
                         ("lmk", "/admin/lmk"), ("legal_entities", "/admin/legal-entities"),
                         ("email", "/admin/email/test"), ("upload", "/admin/upload"),
                         ("payroll_runs", "/admin/payroll/runs"), ("reports", "/admin/reports"),
                         ("analytics", "/admin/analytics"), ("employees", "/hr/employees"),
                         ("audit", "/admin/audit-log"), ("stores", "/admin/stores")):
            with self.subTest(card=key):
                self.assertTrue(cards[key]["available"])
                self.assertEqual(cards[key]["url"], url)


class HrLeadRoutesTests(unittest.TestCase):
    def setUp(self):
        import main

        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine)
        session = self.Session()
        session.add(CitizenshipRegime(id=1, code="rf", name="РФ"))
        session.add(Country(id=1, name="Россия", regime_id=1, is_active=True))
        session.add(User(id=1, employee_name="Админ", phone="70000000001", password_hash="x", role="superadmin",
                         is_admin=True))
        session.add(User(id=2, employee_name="Петрова HR", phone="70000000002", password_hash="x", role="hr_lead"))
        session.add(User(id=3, employee_name="Сидоров ТМ", phone="70000000003", password_hash="x", role="tm"))
        session.add(User(id=4, employee_name="Второй HR", phone="70000000004", password_hash="x", role="hr_lead"))
        session.commit()
        session.close()

        def override_db():
            db = self.Session()
            try:
                yield db
            finally:
                db.close()

        self.app = main.app
        self.app.dependency_overrides[get_db] = override_db
        self.app.dependency_overrides[current_user] = lambda: HR_LEAD
        self.client = TestClient(self.app)

    def tearDown(self):
        self.app.dependency_overrides.pop(get_db, None)
        self.app.dependency_overrides.pop(current_user, None)

    def _user(self, user_id):
        return self.Session().query(User).filter(User.id == user_id).first()

    def _denied(self):
        return self.Session().query(AuditLog).filter(AuditLog.action == "users.denied").count()

    def test_runs_close_open_delete_hidden(self):
        session = self.Session()
        session.add(PayrollRun(id=10, kind="period", status="fixed", date_from=datetime.date(2026, 9, 16),
                               date_to=datetime.date(2026, 9, 30)))
        session.add(PayrollRun(id=11, kind="period", status="sent", date_from=datetime.date(2026, 9, 1),
                               date_to=datetime.date(2026, 9, 15)))
        session.commit()
        session.close()
        page = self.client.get("/admin/payroll/runs").text
        self.assertIn("Закрыть период", page)
        self.assertNotIn("/admin/payroll/runs/delete", page)
        response = self.client.post("/admin/payroll/runs/delete", data={"run_id": "10"}, follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIsNotNone(self.Session().query(PayrollRun).filter(PayrollRun.id == 10).first())
        response = self.client.post("/admin/payroll/runs/close", data={"run_id": "11"}, follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.Session().query(PayrollRun).filter(PayrollRun.id == 11).first().status, "closed")
        self.app.dependency_overrides[current_user] = lambda: SUPERADMIN
        self.assertIn("/admin/payroll/runs/delete", self.client.get("/admin/payroll/runs").text)

    def test_upload_page_open_but_button_disabled(self):
        response = self.client.get("/admin/upload")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Загрузка timebook — право суперадмина", response.text)
        self.assertRegex(response.text, r'<button type="submit" class="btn btn-primary mt-14" disabled')
        response = self.client.post("/admin/upload", files={"file": ("t.xlsx", b"x")})
        self.assertEqual(response.status_code, 403)
        self.app.dependency_overrides[current_user] = lambda: SUPERADMIN
        self.assertNotIn("право суперадмина", self.client.get("/admin/upload").text)

    def test_create_user_page_and_protected_roles(self):
        page = self.client.get("/admin/create-user")
        self.assertEqual(page.status_code, 200)
        self.assertNotIn('value="superadmin"', page.text)
        self.assertNotIn('value="hr_lead"', page.text)
        form = {"employee_name": "Новый Админ", "role": "superadmin", "citizenship_country_id": "1"}
        self.assertEqual(self.client.post("/admin/create-user", data=form).status_code, 403)
        self.assertEqual(self._denied(), 1)
        form.update(employee_name="Новый ТМ", role="tm")
        self.assertIn("Пользователь создан", self.client.post("/admin/create-user", data=form).text)

    def test_delete(self):
        response = self.client.post("/admin/delete-user", data={"user_id": 4}, follow_redirects=False)
        self.assertEqual(response.status_code, 403)
        self.assertIsNotNone(self._user(4))
        response = self.client.post("/admin/delete-user", data={"user_id": 3}, follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIsNone(self._user(3))

    def test_role_change(self):
        base = {"citizenship_country_id": "1"}
        response = self.client.post("/admin/update-user", data={**base, "user_id": 3, "role": "hr_lead"},
                                    follow_redirects=False)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self._user(3).role, "tm")
        response = self.client.post("/admin/update-user", data={**base, "user_id": 2, "role": "economist"},
                                    follow_redirects=False)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self._user(2).role, "hr_lead")
        response = self.client.post("/admin/update-user", data={**base, "user_id": 3, "role": "economist"},
                                    follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self._user(3).role, "economist")
        self.assertEqual(self._denied(), 2)

    def test_email_page_renders(self):
        # Шаблон падал на {{ log.status }} в CSS-комментарии (с волны дизайна 1).
        self.assertEqual(self.client.get("/admin/email/test").status_code, 200)

    def test_password_reset_of_superadmin_denied(self):
        response = self.client.post("/admin/change-password", data={"user_id": 1, "new_password": "secret1"},
                                    follow_redirects=False)
        self.assertEqual(response.status_code, 403)

    def test_users_list_protected_cards_read_only(self):
        html = self.client.get("/admin/users").text
        self.assertIn('href="/admin/create-user"', html)
        # Формы правки — только у ТМ (#3); суперадмин, оба HR-руководителя — просмотр.
        self.assertEqual(html.count('action="/admin/update-user"'), 1)
        self.assertEqual(html.count('action="/admin/delete-user"'), 1)
        self.assertEqual(html.count("— только суперадмин."), 3)
        # superadmin/hr_lead в выпадающем списке — только в фильтре.
        self.assertEqual(html.count('value="superadmin"'), 1)
        self.assertEqual(html.count('value="hr_lead"'), 1)


class HrTeamPageTests(unittest.TestCase):
    """П4.8 B: /hr/team — компактные блоки ТМ, область раскрывается стрелкой, ?open= после сохранения."""

    def setUp(self):
        import main
        from datetime import timedelta

        from models import Shift
        from time_helpers import business_today

        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine)
        session = self.Session()
        session.add(User(id=10, employee_name="Альфа ТМ", phone="71110000010", password_hash="x", role="tm"))
        session.add(User(id=11, employee_name="Бета ТМ", role="hr_manager"))  # без кабинета, старая роль
        session.add(User(id=20, employee_name="Иванов Иван", role="employee", tm_id=10))
        session.add(User(id=21, employee_name="Петров Пётр", role="employee", tm_id=10))
        session.add(User(id=22, employee_name="Сидоров Сидор", role="employee", tm_id=11))
        today = business_today()
        for employee, store, days_ago in (("Иванов Иван", "ТК 1", 1), ("ИВАНОВ ИВАН", "ТК 2", 3),
                                          ("Петров Петр", "ТК 2", 5), ("Петров Пётр", "ТК 3", 40),
                                          ("Сидоров Сидор", "ТК 9", 2)):
            session.add(Shift(employee=employee, store=store, city="Москва", format="ГМ", service="Пекарь",
                              shift_date=today - timedelta(days=days_ago), hours=8,
                              request_type="Основные заказы"))
        session.commit()
        session.close()

        def override_db():
            db = self.Session()
            try:
                yield db
            finally:
                db.close()

        self.app = main.app
        self.app.dependency_overrides[get_db] = override_db
        self.app.dependency_overrides[current_user] = lambda: HR_LEAD
        self.client = TestClient(self.app)

    def tearDown(self):
        self.app.dependency_overrides.pop(get_db, None)
        self.app.dependency_overrides.pop(current_user, None)

    def test_blocks_collapsed_with_counters(self):
        html = self.client.get("/hr/team").text
        self.assertEqual(html.count('class="tm-block"'), 2)
        self.assertNotRegex(html, r'class="tm-block"[^>]*\bopen\b')
        self.assertIn("Области доступа сейчас выключены", html)
        alpha = html[html.index('id="tm-10"'):html.index('id="tm-11"')]
        self.assertIn("есть кабинет", alpha)
        self.assertIn("сотрудников: <b>2</b>", alpha)
        self.assertIn("магазинов за 4 недели: <b>2</b>", alpha)  # ТК 1, ТК 2; ТК 3 — старше 28 дней
        beta = html[html.index('id="tm-11"'):]
        self.assertIn("нет кабинета", beta)
        self.assertIn("сотрудников: <b>1</b>", beta)
        self.assertIn("магазинов за 4 недели: <b>1</b>", beta)

    def test_open_param_and_redirect_after_save(self):
        html = self.client.get("/hr/team?open=11").text
        self.assertRegex(html, r'<details class="tm-block" id="tm-11" open>')
        self.assertRegex(html, r'<details class="tm-block" id="tm-10"( data-tour="team-first")? >')  # П5: якорь тура
        response = self.client.post("/hr/team/scopes", data={"user_id": 11, "scope_cities": ["Москва"],
                                                             "scope_stores": ["ТК 9"]}, follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("open=11", response.headers["location"])
        html = self.client.get(response.headers["location"]).text
        self.assertIn("Область ТМ обновлена", html)
        block = html[html.index('id="tm-11"'):]
        self.assertRegex(block, r'<details class="folder" open>\s*<summary>Москва')
        self.assertIn("выбрано 1", block)


if __name__ == "__main__":
    unittest.main()

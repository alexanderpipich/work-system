"""П2: реестр навигации и единый дашборд."""

import os
import re
import unittest
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from navigation import (ICONS, NAV_GROUPS, PAYOUTS_GROUPS, all_cards, build_navigation,
                        employees_groups)
from rbac import PERMISSIONS, ROLE_LABELS, ROLES

ALL_GROUPS = {
    "main": NAV_GROUPS,
    "payouts": PAYOUTS_GROUPS,
    "employees_admin": employees_groups("/admin/employees"),
    "employees_hr": employees_groups("/hr/employees"),
    "employees_economist": employees_groups("/economist/employees"),
}


def _user(role):
    return SimpleNamespace(id=1, role=role, is_admin=role == "superadmin",
                           employee_name="Тест " + role, economist_stores="", phone="1")


def _cards(nav):
    return [card for group in nav for card in group["cards"]]


class BuildNavigationTests(unittest.TestCase):
    def test_every_role_sees_every_group_and_card(self):
        total = sum(1 for _ in all_cards())
        for role in ROLES:
            nav = build_navigation(_user(role))
            with self.subTest(role=role):
                self.assertEqual([g["key"] for g in nav], [g["key"] for g in NAV_GROUPS])
                self.assertEqual(len(_cards(nav)), total)

    def test_superadmin_has_nothing_locked_except_coming_soon(self):
        for name, groups in ALL_GROUPS.items():
            for card in _cards(build_navigation(_user("superadmin"), groups)):
                with self.subTest(group=name, card=card["key"]):
                    self.assertEqual(card["available"], not card["coming_soon"])

    def test_employee_only_gets_what_his_permissions_allow(self):
        for card in _cards(build_navigation(_user("employee"))):
            with self.subTest(card=card["key"]):
                expected = any(
                    perm in PERMISSIONS["employee"] and roles is None
                    for _href, perm, roles in card["variants"]
                )
                self.assertEqual(card["available"], expected)
        available = [c["key"] for c in _cards(build_navigation(_user("employee"))) if c["available"]]
        self.assertEqual(available, ["stores_directory"])

    def test_allowed_roles_nonempty_and_labelled(self):
        for name, groups in ALL_GROUPS.items():
            for card in _cards(build_navigation(_user("employee"), groups)):
                if card["coming_soon"]:
                    continue
                with self.subTest(group=name, card=card["key"]):
                    self.assertIn("superadmin", card["allowed_roles"])
                    self.assertTrue(card["roles_label"])
                    self.assertTrue(set(card["allowed_roles"]) <= set(ROLES))

    def test_available_iff_role_in_allowed_roles(self):
        for role in ROLES:
            for card in _cards(build_navigation(_user(role))):
                if card["coming_soon"]:
                    continue
                with self.subTest(role=role, card=card["key"]):
                    self.assertEqual(card["available"], role in card["allowed_roles"])

    def test_role_gets_its_own_prefix(self):
        urls = {role: {c["key"]: c["url"] for c in _cards(build_navigation(_user(role), PAYOUTS_GROUPS))}
                for role in ("superadmin", "tm", "economist")}
        self.assertEqual(urls["superadmin"]["payroll"], "/admin/payroll")
        self.assertEqual(urls["tm"]["payroll"], "/hr/payroll")
        self.assertEqual(urls["economist"]["payroll"], "/economist/payroll")

    def test_permissions_and_icons_are_known(self):
        known = set().union(*PERMISSIONS.values()) | {"email.manage", "upload.auto", "admin.settings",
                                                      "shifts.upload", "audit.view", "stores.view",
                                                      "schedules.admin_view", "users.manage"}
        for name, groups in ALL_GROUPS.items():
            for card in all_cards(groups):
                with self.subTest(group=name, card=card["key"]):
                    self.assertIn(card["icon"], ICONS)
                    for _href, perm, roles in card["variants"]:
                        self.assertIn(perm, known)
                        self.assertTrue(roles is None or set(roles) <= set(ROLES))

    def test_every_role_label_present(self):
        self.assertEqual(set(ROLE_LABELS), set(ROLES))


class HrefsExistTests(unittest.TestCase):
    """Каждый адрес реестра — существующий GET-маршрут приложения."""

    @classmethod
    def setUpClass(cls):
        import main

        cls.paths = {r.path for r in main.app.routes if isinstance(r, APIRoute) and "GET" in r.methods}

    def test_every_href_is_a_route(self):
        for name, groups in ALL_GROUPS.items():
            for card in all_cards(groups):
                if card["coming_soon"]:
                    continue
                for href, _perm, _roles in card["variants"]:
                    with self.subTest(group=name, card=card["key"], href=href):
                        self.assertIn(href.split("?")[0], self.paths)


class DashboardRendersTests(unittest.TestCase):
    """Дашборд и поддашборды рендерятся под каждой ролью; заблокированное приглушено."""

    @classmethod
    def setUpClass(cls):
        import main
        from dependencies import current_user

        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool

        from database import Base
        from dependencies import get_db

        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        from models import User

        seed = Session()
        seed.add(User(employee_name="Иванов Иван", phone="79990000001", password_hash="x", role="employee"))
        seed.commit()
        seed.close()

        def override_db():
            session = Session()
            try:
                yield session
            finally:
                session.close()

        cls.app = main.app
        cls.get_db = staticmethod(get_db)
        cls.app.dependency_overrides[get_db] = override_db
        cls.current_user = staticmethod(current_user)
        cls.client = TestClient(main.app)

    @classmethod
    def tearDownClass(cls):
        cls.app.dependency_overrides.pop(cls.get_db, None)

    def tearDown(self):
        self.app.dependency_overrides.pop(self.current_user, None)

    def _as(self, role):
        user = _user(role)
        self.app.dependency_overrides[self.current_user] = lambda: user

    def test_dashboard_for_every_role(self):
        total = sum(1 for _ in all_cards())
        for role in ROLES:
            self._as(role)
            with self.subTest(role=role):
                response = self.client.get("/admin", follow_redirects=False)
                self.assertEqual(response.status_code, 200)
                html = response.text
                self.assertEqual(len(re.findall(r'class="nav-card', html)), total)
                locked = len(re.findall(r'class="nav-card is-locked"', html))
                expected = sum(1 for c in _cards(build_navigation(_user(role))) if not c["available"])
                self.assertEqual(locked, expected)
                self.assertIn('id="nav-lock-modal"', html)
                for group in NAV_GROUPS:
                    self.assertIn(group["title"], html)

    def test_locked_card_carries_roles(self):
        self._as("tm")
        html = self.client.get("/admin").text
        self.assertIn('data-title="Audit Log" data-roles="Суперадмин"', html)

    def test_subdashboards(self):
        self._as("tm")
        self.assertEqual(self.client.get("/admin/payouts").status_code, 200)
        self.assertEqual(self.client.get("/hr/employees").status_code, 200)
        self._as("superadmin")
        self.assertEqual(self.client.get("/admin/contracts").status_code, 200)
        self.assertEqual(self.client.get("/admin/payouts/advances").status_code, 200)

    def test_old_planning_redirects(self):
        self._as("superadmin")
        for prefix in ("/admin", "/hr", "/economist"):
            with self.subTest(prefix=prefix):
                response = self.client.get(prefix + "/employees/planning", follow_redirects=False)
                self.assertEqual(response.status_code, 301)
                self.assertEqual(response.headers["location"], "/admin/planning-bp")

    def test_users_list_read_only_for_staff(self):
        for role in ("hr_lead", "tm", "hr_clerk", "economist"):
            self._as(role)
            with self.subTest(role=role):
                response = self.client.get("/admin/users", follow_redirects=False)
                self.assertEqual(response.status_code, 200)
                self.assertNotIn('action="/admin/update-user"', response.text)
                self.assertNotIn('action="/admin/change-password"', response.text)
                self.assertNotIn('action="/admin/delete-user"', response.text)
                self.assertNotIn('href="/admin/create-user"', response.text)
                self.assertIn("Иванов Иван", response.text)
                self.assertIn("Кабинет: <b>есть</b>", response.text)
        self._as("superadmin")
        html = self.client.get("/admin/users").text
        self.assertIn('action="/admin/update-user"', html)

    def test_users_list_closed_for_others(self):
        for role in ("brigadier", "headhunter", "employee"):
            self._as(role)
            with self.subTest(role=role):
                self.assertEqual(self.client.get("/admin/users", follow_redirects=False).status_code, 302)

    def test_users_view_does_not_allow_changes(self):
        self._as("tm")
        for path, data in (("/admin/update-user", {"user_id": 1, "role": "superadmin"}),
                           ("/admin/change-password", {"user_id": 1, "new_password": "x123456"}),
                           ("/admin/delete-user", {"user_id": 1})):
            with self.subTest(path=path):
                response = self.client.post(path, data=data, follow_redirects=False)
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.headers["location"], "/")

    def test_upload_auto_locked_for_non_superadmin(self):
        self._as("tm")
        html = self.client.get("/admin/upload/auto").text
        self.assertIn("Доступно только системному суперадмину", html)
        self._as("superadmin")
        html = self.client.get("/admin/upload/auto").text
        self.assertNotIn("Доступно только системному суперадмину", html)
        self.assertIn("Настройка автозагрузки", self.client.get("/admin/upload").text)


if __name__ == "__main__":
    unittest.main()

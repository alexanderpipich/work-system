"""П4.10: боковое меню на всех страницах офисных ролей."""

import os
import re
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from fastapi import Request
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import menu_context
from database import Base
from dependencies import current_user, get_db
from menu_context import build_menu_context, mark_current
from navigation import all_cards, dashboard_url, role_href

OFFICE_ROLES = ("hr_lead", "tm", "economist")
RAIL = '<aside class="rail"'


def _user(role):
    return SimpleNamespace(id=1, role=role, is_admin=role == "superadmin", employee_name="Иванова Мария",
                           economist_stores="", phone="70000000001", brigadier_store=None)


def _card_url(user, key):
    return role_href(user, next(card for card in all_cards() if card["key"] == key))


class PageTests(unittest.TestCase):
    def setUp(self):
        import main

        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine)

        def override_db():
            db = self.Session()
            try:
                yield db
            finally:
                db.close()

        self.app = main.app
        self.app.dependency_overrides[get_db] = override_db
        self.client = TestClient(self.app)

    def tearDown(self):
        self.app.dependency_overrides.pop(get_db, None)
        self.app.dependency_overrides.pop(current_user, None)

    def _as(self, user):
        # Как настоящий current_user: пользователь запроса — в request.state для меню.
        def override(request: Request):
            request.state.user = user
            return user

        self.app.dependency_overrides[current_user] = override

    def _get(self, path):
        response = self.client.get(path, follow_redirects=False)
        self.assertEqual(response.status_code, 200, path)
        return response.text

    def test_rail_on_office_pages(self):
        for role in OFFICE_ROLES:
            user = _user(role)
            self._as(user)
            paths = {"/admin/users", _card_url(user, "documents") or "/admin/users",
                     _card_url(user, "employees")}
            if role != "hr_clerk":
                paths.add("/admin/payouts/weekly")
            for path in sorted(paths):
                with self.subTest(role=role, path=path):
                    html = self._get(path)
                    self.assertIn(RAIL, html)
                    self.assertEqual(html.count('id="nav-lock-modal"'), 1)
        # Пути из ТЗ напрямую: /admin/documents у суперадмина, /hr/employees у HR-руководителя и ТМ.
        self._as(_user("superadmin"))
        self.assertIn(RAIL, self._get("/admin/documents"))
        for role in ("hr_lead", "tm"):
            self._as(_user(role))
            self.assertIn(RAIL, self._get("/hr/employees"))

    def test_short_page_rail_background(self):
        # Короткая страница: фон полосы — на липкой .rail-inner (100vh), а не на .rail-panel
        # (её высота = высота контента, фон обрывался и список шёл белым по белому).
        self._as(_user("hr_lead"))
        html = self._get("/admin/payouts")
        self.assertRegex(html, r'<aside class="rail"[^>]*>\s*<div class="rail-panel">\s*<div class="rail-inner">')
        with open(os.path.join(os.path.dirname(__file__), "..", "static", "app.css"), encoding="utf-8") as f:
            css = f.read()

        def rule(selector):
            match = re.search(r"(?m)^" + re.escape(selector) + r" \{([^}]*)\}", css)
            self.assertIsNotNone(match, selector)
            return match.group(1)

        self.assertIn("background: var(--brand-blue)", rule(".rail-inner"))
        self.assertIn("height: 100vh", rule(".rail-inner"))
        self.assertNotIn("background", rule(".rail-panel"))
        self.assertIn("min-height: 100vh", rule(".with-rail"))
        self.assertIn("width: 32px; height: 32px", rule(".rail-brand img"))
        self.assertIn("scrollbar-width: none", rule(".rail-groups"))

    def test_no_rail_in_cabinet_and_login(self):
        self._as(_user("hr_lead"))
        for path in ("/cabinet", "/cabinet/password"):
            with self.subTest(path=path):
                html = self._get(path)
                self.assertNotIn(RAIL, html)
                self.assertNotIn("data-drawer-open", html)
        self.app.dependency_overrides.pop(current_user, None)
        self.assertNotIn(RAIL, self._get("/login"))
        self._as(_user("employee"))
        self.assertNotIn(RAIL, self._get("/stores"))

    def test_current_section_and_group(self):
        self._as(_user("hr_lead"))
        html = self._get("/admin/payouts/weekly")
        self.assertRegex(html, r'class="menu-item is-current" aria-current="page">Еженедельный отчёт</a>')
        self.assertIn('class="rail-group is-active" data-rail-group="payouts"', html)
        self.assertEqual(len(re.findall(r'rail-group is-active', html)), 1)

    def test_group_links_go_to_own_dashboard(self):
        expected = {"superadmin": "/admin", "hr_lead": "/hr", "tm": "/hr", "economist": "/economist"}
        for role, home in expected.items():
            with self.subTest(role=role):
                self._as(_user(role))
                html = self._get("/admin/users")
                self.assertIn(f'href="{home}#payouts" class="rail-head" data-rail-anchor="payouts"', html)
        self._as(_user("superadmin"))
        dashboard = self._get("/admin")
        self.assertIn('href="#payouts" class="rail-head" data-rail-anchor="payouts"', dashboard)

    def test_burger_and_drawer_outside_dashboard(self):
        self._as(_user("tm"))
        page = self._get("/admin/payouts/weekly")
        self.assertRegex(page, r'<button type="button" class="burger[^"]*" aria-label="Меню" aria-expanded="false"')
        self.assertIn('class="drawer no-print" id="nav-drawer" hidden', page)
        self.assertIn('class="mmenu-btn">Еженедельный отчёт</a>', page)
        dashboard = self._get("/hr")
        self.assertNotIn("data-drawer-open", dashboard)
        self.assertNotIn('id="nav-drawer"', dashboard)
        self.assertEqual(dashboard.count('id="nav-lock-modal"'), 1)

    def test_menu_built_once_per_request(self):
        self._as(_user("hr_lead"))
        with patch("menu_context.build_menu", wraps=menu_context.build_menu) as build:
            self._get("/admin/payouts/weekly")
            self.assertEqual(build.call_count, 1)
            self._get("/admin/users")
            self.assertEqual(build.call_count, 2)


class MenuContextTests(unittest.TestCase):
    def test_who_gets_menu(self):
        self.assertIsNone(build_menu_context(None, "/admin/users"))
        self.assertIsNone(build_menu_context(_user("employee"), "/admin"))
        for path in ("/cabinet", "/cabinet/password", "/employee_docs", "/vacancies", "/support", "/login"):
            with self.subTest(path=path):
                self.assertIsNone(build_menu_context(_user("hr_lead"), path))
        self.assertIsNotNone(build_menu_context(_user("brigadier"), "/stores"))
        self.assertIsNotNone(build_menu_context(_user("hr_lead"), "/cabinetry"))  # не префикс /cabinet/

    def test_dashboard_mode(self):
        nav = build_menu_context(_user("tm"), "/hr")
        self.assertTrue(nav["on_dashboard"])
        self.assertEqual(nav["home"], "")
        self.assertFalse(any(item.get("current") for group in nav["menu"] for item in group["items"]))
        self.assertEqual(build_menu_context(_user("tm"), "/hr/employees")["home"], "/hr")

    def test_dashboard_url(self):
        self.assertEqual(dashboard_url(_user("superadmin")), "/admin")
        self.assertEqual(dashboard_url(_user("hr_clerk")), "/hr")
        self.assertEqual(dashboard_url(_user("economist")), "/economist")
        self.assertEqual(dashboard_url(_user("brigadier")), "/admin")

    def test_mark_current_longest_match_and_query(self):
        def item(key, url, available=True):
            return {"key": key, "url": url, "available": available}

        menu = [
            {"key": "a", "items": [item("users", "/admin/users"), item("list", "/admin/users?role=employee")]},
            {"key": "b", "items": [item("payouts", "/admin/payouts"), item("weekly", "/admin/payouts/weekly"),
                                   item("locked", "/admin/payouts/weekly/x", available=False)]},
        ]
        self.assertEqual(mark_current(menu, "/admin/payouts/weekly/x")[1]["key"], "weekly")
        self.assertTrue(menu[1]["active"])
        self.assertFalse(menu[0]["active"])
        self.assertEqual(mark_current(menu, "/admin/users", "role=employee")[1]["key"], "list")
        self.assertEqual(mark_current(menu, "/admin/users")[1]["key"], "users")
        self.assertEqual(mark_current(menu, "/admin/users/5/edit")[1]["key"], "users")
        self.assertIsNone(mark_current(menu, "/admin/payoutsx"))
        self.assertFalse(any(g["active"] for g in menu))

    def test_global_in_every_router_env(self):
        import main  # noqa: F401 — регистрирует глобал

        envs = [module.templates for name, module in list(sys.modules.items())
                if name.startswith("routers.") and isinstance(getattr(module, "templates", None), Jinja2Templates)]
        self.assertGreater(len(envs), 30)
        for templates in envs:
            self.assertIs(templates.env.globals.get("menu_context"), menu_context.menu_context)


if __name__ == "__main__":
    unittest.main()

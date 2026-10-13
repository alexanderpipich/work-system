"""П4.9: рабочий стол — меню из реестра, группа «Выплаты» на главном, сводка недели, мобильная версия."""

import datetime
import os
import re
import unittest
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base
from dependencies import current_user, get_db
from models import Shift, Store, User
from navigation import NAV_GROUPS, PAYOUTS_GROUPS, build_menu, build_navigation, role_href
from routers import dashboards
from routers.dashboards import compute_dashboard_summary, dashboard_summary, format_dynamics

GROUP_KEYS = ["people", "money", "payouts", "documents", "directories", "planning", "reports", "communications"]
WEEK = datetime.date(2026, 10, 5)  # пн; последняя полная неделя для «сегодня» 13.10.2026
TODAY = datetime.date(2026, 10, 13)


def _user(role, name=None):
    return SimpleNamespace(id=1, role=role, is_admin=role == "superadmin",
                           employee_name=name or "Иванова Мария", economist_stores="", phone="1")


def _engine():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return engine


def _shift(day, store, employee, hours, city="Москва", request_type="Основные заказы"):
    return Shift(store=store, format="ГМ", city=city, shift_date=day, service="Кассир", employee=employee,
                 hours=hours, request_type=request_type)


class MenuTests(unittest.TestCase):
    def test_groups_and_items_follow_registry(self):
        for role in ("superadmin", "tm"):
            user = _user(role)
            nav = build_navigation(user)
            menu = build_menu(nav)
            with self.subTest(role=role):
                self.assertEqual([g["key"] for g in menu], GROUP_KEYS)
                self.assertEqual([g["anchor"] for g in menu], GROUP_KEYS)
                for group, nav_group in zip(menu, nav):
                    self.assertTrue(group["icon_svg"].startswith("<svg"))
                    self.assertEqual([i["key"] for i in group["items"]], [c["key"] for c in nav_group["cards"]])
                    for item, entry in zip(group["items"], nav_group["cards"]):
                        if item["available"]:
                            self.assertEqual(item["url"], role_href(user, entry))

    def test_tm_communications_muted(self):
        menu = {g["key"]: g for g in build_menu(build_navigation(_user("tm")))}
        items = menu["communications"]["items"]
        self.assertEqual(len(items), 3)
        self.assertTrue(all(not i["available"] and i["coming_soon"] for i in items))

    def test_payouts_group_on_main(self):
        payouts = [g for g in NAV_GROUPS if g["key"] == "payouts"]
        self.assertEqual(len(payouts), 1)
        self.assertIs(payouts[0], PAYOUTS_GROUPS[0])
        self.assertEqual([c["key"] for c in payouts[0]["cards"]],
                         ["weekly_report", "payroll", "advances", "bonuses", "payroll_runs"])
        keys = [g["key"] for g in NAV_GROUPS]
        self.assertEqual(keys.index("payouts"), keys.index("money") + 1)
        money = next(g for g in NAV_GROUPS if g["key"] == "money")
        self.assertIn("payouts", [c["key"] for c in money["cards"]])  # карточка поддашборда остаётся


class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.Session = sessionmaker(bind=_engine())
        session = self.Session()
        session.add_all([
            Store(tk_number=660, city="Москва", rate_region="Московская область", format="ГМ"),
            Store(tk_number=521, city="Москва", rate_region="Москва", format="ГМ"),
        ])
        prev = WEEK - datetime.timedelta(days=7)
        session.add_all([
            # Неделя 05–11.10: 10 + 6 + 4 (без плана — тоже факт времени) = 20 ч, два человека.
            _shift(WEEK, "ТК 660 Лента", "Петров Пётр", 10),
            _shift(WEEK + datetime.timedelta(days=1), "ТК 521 Лента", "петров  петр", 6),
            _shift(WEEK + datetime.timedelta(days=6), "ТК 521 Лента", "Сидорова Анна", 4,
                   request_type="Смена без плана"),
            # Неделя раньше: 16 ч; позже (12.10) — не в сводке.
            _shift(prev, "ТК 521 Лента", "Петров Пётр", 16),
            _shift(WEEK + datetime.timedelta(days=7), "ТК 521 Лента", "Петров Пётр", 99),
        ])
        session.commit()
        session.close()
        dashboards._summary_cache.clear()

    def test_numbers(self):
        data = compute_dashboard_summary(self.Session(), WEEK)
        self.assertEqual(data["hours"], 20)
        self.assertEqual(data["employees"], 2)  # «петров  петр» = «Петров Пётр»
        self.assertEqual(data["previous_hours"], 16)
        self.assertEqual(data["dynamics"], "+25,0 % часов")
        self.assertEqual(data["week_end"], datetime.date(2026, 10, 11))
        # Регион — тарифный регион ТК, а не город смены.
        self.assertEqual([(r["label"], r["value"]) for r in data["cities"]],
                         [("Москва", 10), ("Московская область", 10)])
        self.assertEqual([(r["label"], r["value"]) for r in data["stores"]], [("Лента-521", 10), ("Лента-660", 10)])
        self.assertEqual(data["stores"][0]["pct"], 100)

    def test_other_regions_and_top_limit(self):
        session = self.Session()
        for tk, city in [(1, "Казань"), (2, "Самара"), (3, "Тверь"), (4, "Омск"), (5, "Пермь")]:
            session.add(_shift(WEEK, f"ТК {tk}", f"Сотрудник {tk}", tk, city=city))
        session.commit()
        data = compute_dashboard_summary(session, WEEK)
        self.assertEqual(len(data["cities"]), 5)
        self.assertEqual(data["cities"][-1]["label"], "Другие")
        self.assertEqual(sum(r["value"] for r in data["cities"]), data["hours"])
        self.assertEqual(len(data["stores"]), 5)

    def test_no_previous_week(self):
        self.assertIsNone(format_dynamics(20, 0))
        self.assertEqual(format_dynamics(98.6, 100), "−1,4 % часов")
        self.assertEqual(format_dynamics(103.2, 100), "+3,2 % часов")

    def test_visibility(self):
        session = self.Session()
        with patch("time_helpers.business_today", return_value=TODAY):
            self.assertIsNone(dashboard_summary(session, _user("hr_clerk")))
            self.assertIsNone(dashboard_summary(session, _user("employee")))
            self.assertEqual(dashboard_summary(session, _user("tm"))["week_start"], WEEK)

    def test_cache(self):
        session = self.Session()
        with patch("routers.dashboards.compute_dashboard_summary", return_value={"x": 1}) as compute, \
                patch("routers.dashboards.time.monotonic", side_effect=[1000.0, 1300.0, 1700.0]):
            for _ in range(3):
                dashboard_summary(session, _user("superadmin"), today=TODAY)
        self.assertEqual(compute.call_count, 2)  # 2-й вызов — из кэша, 3-й — через 700 с > 10 мин


class DashboardRenderTests(unittest.TestCase):
    def setUp(self):
        import main

        self.Session = sessionmaker(bind=_engine())
        session = self.Session()
        session.add(User(id=7, employee_name="Сотрудник Тест", phone="70000000007", password_hash="x",
                         role="employee"))
        session.add(_shift(WEEK, "ТК 521 Лента", "Петров Пётр", 8))
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
        self.client = TestClient(self.app)
        dashboards._summary_cache.clear()

    def tearDown(self):
        self.app.dependency_overrides.pop(get_db, None)
        self.app.dependency_overrides.pop(current_user, None)
        dashboards._summary_cache.clear()

    def _as(self, user):
        self.app.dependency_overrides[current_user] = lambda: user

    def test_rail_sections_and_summary(self):
        self._as(_user("superadmin"))
        response = self.client.get("/admin")
        self.assertEqual(response.status_code, 200)
        html = response.text
        self.assertIn('<aside class="rail"', html)
        positions = [html.index(f'id="{key}"') for key in GROUP_KEYS]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('aria-label="Сводка"', html)
        self.assertIn('class="mmenu"', html)
        self.assertEqual(len(re.findall(r'data-rail-anchor="', html)), 8)
        # Мобильное меню: «Выплаты» раскрыта тем, у кого есть недельный отчёт.
        self.assertRegex(html, r'<details class="mmenu-group" open>\s*<summary>\s*<span class="icon amber">'
                               r'[\s\S]*?<span class="mmenu-title">Выплаты</span>')
        self.assertEqual(self.client.get("/admin/payouts").status_code, 200)

    def test_tm_quick_buttons_and_muted_items(self):
        self._as(_user("tm"))
        html = self.client.get("/admin").text
        self.assertIn('class="mmenu-btn">Еженедельный отчёт</a>', html)
        self.assertRegex(html, r'class="menu-item is-locked"[^>]*data-title="Сообщения"[^>]*data-coming-soon="1"')

    def test_hr_clerk_without_summary(self):
        self._as(_user("hr_clerk"))
        response = self.client.get("/hr")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('aria-label="Сводка"', response.text)
        self.assertIn('<aside class="rail"', response.text)

    def test_employee_and_cabinet_without_rail(self):
        employee = SimpleNamespace(id=7, role="employee", is_admin=False, employee_name="Сотрудник Тест",
                                   economist_stores="", phone="70000000007")
        self._as(employee)
        self.assertNotIn('class="rail"', self.client.get("/admin").text)
        response = self.client.get("/cabinet")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('class="rail"', response.text)


if __name__ == "__main__":
    unittest.main()

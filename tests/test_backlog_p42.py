"""П4.2: город из timebook, услуги, ТК из смен, БП только ГМ, снятие закреплений,
пагинация пользователей, банки импорта."""

import json
import os
import unittest
from datetime import date, timedelta
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base
from models import EmployeeMonitoringRecommendation, EmployeeStoreAssignment, Requisite, Shift, Store, User
from monitoring_helpers import recompute_recommendations
from scripts.normalize_shift_cities import normalize_shift_cities
from store_helpers import allows_bp, populate_stores_from_shifts, store_formats
from time_helpers import business_today
from tools.import_employees_cards import canonical_bank
from utils import normalize_city

ROOT = Path(__file__).resolve().parent.parent


def _sessionmaker():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def _shift(employee, store, fmt, city, days_ago=1):
    return Shift(employee=employee, store=store, format=fmt, city=city, service="Выкладка", hours=8,
                 shift_date=business_today() - timedelta(days=days_ago), request_type="Основные заказы")


class CityTests(unittest.TestCase):
    def test_normalize_city(self):
        for raw, expected in [("г. Москва", "Москва"), ("г.Москва", "Москва"), ("город  Москва", "Москва"),
                              (" Санкт-Петербург ", "Санкт-Петербург"), ("nan", ""), (float("nan"), ""),
                              (None, ""), ("Гатчина", "Гатчина")]:
            with self.subTest(raw=raw):
                self.assertEqual(normalize_city(raw), expected)

    def test_script_normalizes_existing_shifts(self):
        session = _sessionmaker()()
        session.add_all([_shift("А", "Лента-1", "ГМ", "г. Москва"), _shift("Б", "Лента-1", "ГМ", "nan"),
                         _shift("В", "Лента-1", "ГМ", "Москва")])
        session.commit()
        changes = normalize_shift_cities(session, apply=True)
        session.commit()
        self.assertEqual(sum(changes.values()), 2)
        self.assertEqual(sorted((s.city or "") for s in session.query(Shift).all()), ["", "Москва", "Москва"])


class ReferenceTests(unittest.TestCase):
    def test_three_lenta_services_in_reference(self):
        names = {s["name"] for s in json.loads((ROOT / "data/reference/services.json").read_text(encoding="utf-8"))}
        for name in ("Комплексные услуги по комплектации заказов Маркетплейса и Дарксторов",
                     "Услуги по разгрузке без применения специальной техники",
                     "Услуги по погрузке-разгрузке СОФ без применения специальной техники"):
            self.assertIn(name, names)

    def test_rare_bank_aliases(self):
        for raw, canon in [("псб", "ПСБ"), ("ренесанс", "Ренессанс Банк"), ("Халва", "Совкомбанк"),
                           ("Санкт-Петербург", "Банк «Санкт-Петербург»"), ("МТСБанк", "МТС Банк"), ("ВБРР", "ВБРР")]:
            with self.subTest(raw=raw):
                self.assertEqual(canonical_bank(raw), (canon, True))


class StoresAndPlanningTests(unittest.TestCase):
    def setUp(self):
        self.session = _sessionmaker()()
        self.session.add_all([
            _shift("Иванов", "Лента-124 (г. Москва)", "ГМ", "г. Москва"),
            _shift("Иванов", "Лента-124 (г. Москва)", "ГМ", "nan", days_ago=2),
            _shift("Петров", "Лента-0705 СМ", "СМ", "Москва"),
            _shift("Петров", "Лента-0705 СМ", "СМ", "Москва", days_ago=2),
            _shift("Петров", "Лента-0705 СМ", "СМ", "Москва", days_ago=3),
            _shift("Сидоров", "ООО «Лента»", "ГМ", "Москва"),
        ])
        self.session.commit()

    def test_populate_stores_normalizes(self):
        report = populate_stores_from_shifts(self.session)
        self.assertEqual(report["created"], 2)
        self.assertEqual(report["unrecognized"], ["ООО «Лента»"])
        store = self.session.query(Store).filter(Store.tk_number == 124).one()
        self.assertEqual((store.city, store.format), ("Москва", "ГМ"))

    def test_bp_only_for_gm(self):
        formats = store_formats(self.session)
        self.assertTrue(allows_bp(formats["Лента-124 (г. Москва)"]))
        self.assertFalse(allows_bp(formats["Лента-0705 СМ"]))
        self.assertTrue(allows_bp(None))  # неизвестный формат не отсекается
        self.session.add(EmployeeStoreAssignment(employee_name="Петров", store="Лента-0705 СМ", is_active=True))
        self.session.commit()
        recompute_recommendations(self.session)
        stores = {r.store for r in self.session.query(EmployeeMonitoringRecommendation).all()}
        self.assertNotIn("Лента-0705 СМ", stores)


class RoutesTests(unittest.TestCase):
    def setUp(self):
        import main
        from dependencies import current_user, get_db

        self.Session = _sessionmaker()
        session = self.Session()
        session.add(User(id=1, employee_name="ТМ Тест", role="tm", phone="70000000001", password_hash="x"))
        session.add(User(id=2, employee_name="Админ", role="superadmin", is_admin=True, phone="70000000002",
                         password_hash="x"))
        for i in range(130):
            session.add(User(id=100 + i, employee_name=f"Сотрудник {i:03d}", role="employee",
                             tm_id=1 if i < 5 else None))
        session.add(Requisite(user_id=100, employee_name="Сотрудник 000", is_active=True))
        session.add(Store(tk_number=124, display_name="Лента-124", format="ГМ", city="Москва"))
        session.add(EmployeeStoreAssignment(id=1, employee_name="Сотрудник 001", store="Лента-124", is_active=True))
        session.commit()

        def override_db():
            db = self.Session()
            try:
                yield db
            finally:
                db.close()

        self.app, self.get_db, self.current_user = main.app, get_db, current_user
        self.app.dependency_overrides[get_db] = override_db
        self.client = TestClient(main.app)

    def tearDown(self):
        self.app.dependency_overrides.pop(self.get_db, None)
        self.app.dependency_overrides.pop(self.current_user, None)

    def _as(self, user_id):
        db = self.Session()
        user = db.get(User, user_id)
        db.expunge(user)
        self.app.dependency_overrides[self.current_user] = lambda: user

    def test_tm_deactivates_assignment(self):
        self._as(1)
        self.assertEqual(self.client.get("/admin/planning-bp", follow_redirects=False).status_code, 200)
        response = self.client.post("/admin/planning-bp/assignment/deactivate",
                                    data={"assignment_id": 1, "store": "Лента-124"}, follow_redirects=False)
        self.assertIn("message=", response.headers["location"])
        self.assertFalse(self.Session().get(EmployeeStoreAssignment, 1).is_active)
        # Глобальные пороги мониторинга — только суперадмин.
        response = self.client.post("/admin/planning-bp/monitoring/settings",
                                    data={"inactive_days": 5, "minimum_shifts": 1, "analysis_days": 5},
                                    follow_redirects=False)
        self.assertEqual(response.headers["location"], "/")

    def test_users_pagination_and_filters(self):
        self._as(2)
        html = self.client.get("/admin/users").text
        self.assertIn("Страница 1 из 2 · всего 132", html)
        self.assertEqual(html.count('class="uitem"'), 100)
        self.assertEqual(self.client.get("/admin/users?page=2").text.count('class="uitem"'), 32)
        self.assertEqual(self.client.get("/admin/users?tm=1").text.count('class="uitem"'), 5)
        self.assertEqual(self.client.get("/admin/users?role=employee&no_cabinet=1").text.count('class="uitem"'), 100)
        no_req = self.client.get("/admin/users?role=employee&no_requisites=1&page=2").text
        self.assertIn("всего 129", no_req)

    def test_old_planning_still_redirects(self):
        self._as(2)
        response = self.client.get("/admin/employees/planning", follow_redirects=False)
        self.assertEqual((response.status_code, response.headers["location"]), (301, "/admin/planning-bp"))


if __name__ == "__main__":
    unittest.main()

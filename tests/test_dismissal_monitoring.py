import os
import unittest
from datetime import timedelta
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import EmployeeDismissalDecision, Shift, User
from routers.employees import _dismissal_candidates
from time_helpers import business_today


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _shift(session, employee, day, store="Лента-1", city="ЛО"):
    session.add(Shift(employee=employee, store=store, city=city, format="ГМ",
                      service="1ур_Услуга", shift_date=day, hours=8, request_type="Основные заказы"))


def _admin():
    return SimpleNamespace(id=1, role="superadmin", is_admin=True)


class DismissalCandidatesTests(unittest.TestCase):
    def setUp(self):
        self.s = _session()
        self.today = business_today()

    def test_disappeared_listed_active_not(self):
        _shift(self.s, "Пропавший", self.today - timedelta(days=40))   # давно
        _shift(self.s, "Активный", self.today - timedelta(days=1))     # недавно
        self.s.commit()
        rows, settings = _dismissal_candidates(self.s, _admin())
        names = [r["employee_name"] for r in rows]
        self.assertIn("Пропавший", names)
        self.assertNotIn("Активный", names)
        row = next(r for r in rows if r["employee_name"] == "Пропавший")
        self.assertEqual(row["last_date"], self.today - timedelta(days=40))
        self.assertEqual(row["store"], "Лента-1")
        self.assertGreaterEqual(row["days_ago"], 40)
        self.assertIsNone(row["decision"])

    def test_last_shift_is_most_recent_store(self):
        _shift(self.s, "Икс", self.today - timedelta(days=50), store="Старый")
        _shift(self.s, "Икс", self.today - timedelta(days=30), store="Новый")  # позже, но всё ещё пропал
        self.s.commit()
        rows, _ = _dismissal_candidates(self.s, _admin())
        row = next(r for r in rows if r["employee_name"] == "Икс")
        self.assertEqual(row["store"], "Новый")
        self.assertEqual(row["last_date"], self.today - timedelta(days=30))

    def test_decision_surfaced(self):
        _shift(self.s, "Пропавший", self.today - timedelta(days=40))
        self.s.add(EmployeeDismissalDecision(employee_name="Пропавший", decision="dismiss", comment="мигрант"))
        self.s.commit()
        rows, _ = _dismissal_candidates(self.s, _admin())
        row = next(r for r in rows if r["employee_name"] == "Пропавший")
        self.assertEqual(row["decision"], "dismiss")
        self.assertEqual(row["decision_comment"], "мигрант")


if __name__ == "__main__":
    unittest.main()

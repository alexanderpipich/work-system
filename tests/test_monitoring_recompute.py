import os
import unittest
from datetime import timedelta

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import EmployeeMonitoringRecommendation, EmployeeStoreAssignment, Shift
from monitoring_helpers import recompute_recommendations
from time_helpers import business_today


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _shift(session, employee, store, day, city="ЛО"):
    session.add(Shift(employee=employee, store=store, city=city, format="ГМ",
                      service="1ур_Услуга", shift_date=day, hours=8,
                      request_type="Основные заказы"))


class RecomputeTests(unittest.TestCase):
    def setUp(self):
        self.s = _session()
        self.today = business_today()

    def _recs(self, kind):
        return self.s.query(EmployeeMonitoringRecommendation).filter(
            EmployeeMonitoringRecommendation.recommendation_type == kind,
            EmployeeMonitoringRecommendation.status == "new",
        ).all()

    def test_assigned_without_shifts_gets_remove(self):
        self.s.add(EmployeeStoreAssignment(employee_name="Иванов", store="Лента-1",
                                           city="ЛО", is_active=True))
        self.s.commit()
        created = recompute_recommendations(self.s)
        self.assertGreaterEqual(created, 1)
        remove = self._recs("remove_from_planning")
        self.assertTrue(any(r.employee_name == "Иванов" for r in remove))

    def test_worked_but_not_assigned_gets_add(self):
        for d in range(3):
            _shift(self.s, "Петров", "Лента-1", self.today - timedelta(days=d))
        self.s.commit()
        recompute_recommendations(self.s)
        add = self._recs("add_to_planning")
        self.assertTrue(any(r.employee_name == "Петров" for r in add))

    def test_assigned_and_active_no_recs(self):
        self.s.add(EmployeeStoreAssignment(employee_name="Сидоров", store="Лента-2",
                                           city="ЛО", is_active=True))
        for d in range(3):
            _shift(self.s, "Сидоров", "Лента-2", self.today - timedelta(days=d))
        self.s.commit()
        recompute_recommendations(self.s)
        self.assertEqual(self._recs("remove_from_planning"), [])
        # закреплён и работает — не add (он уже в планировании) и не remove
        add = [r for r in self._recs("add_to_planning") if r.employee_name == "Сидоров"]
        self.assertEqual(add, [])

    def test_idempotent(self):
        self.s.add(EmployeeStoreAssignment(employee_name="Иванов", store="Лента-1",
                                           city="ЛО", is_active=True))
        self.s.commit()
        recompute_recommendations(self.s)
        again = recompute_recommendations(self.s)
        self.assertEqual(again, 0)
        self.assertEqual(len(self._recs("remove_from_planning")), 1)


if __name__ == "__main__":
    unittest.main()

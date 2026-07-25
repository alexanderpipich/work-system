import os
import unittest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import Rate
from routers.rates import _BASE, _HAS_EMPLOYEE, _HAS_STORE, _INDIVIDUAL, and_, or_


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _rate(session, hourly, store=None, employee_name=None):
    session.add(Rate(service="1ур_X", format="ГМ", city="ЛО", store=store,
                     employee_name=employee_name, hourly_rate=hourly))


class RatesFilterTests(unittest.TestCase):
    def setUp(self):
        self.s = _session()
        _rate(self.s, 100)                                   # база (NULL/NULL)
        _rate(self.s, 110, store="", employee_name="")       # база (пустые строки)
        _rate(self.s, 200, store="Лента-1")                  # по ТК
        _rate(self.s, 300, employee_name="Иванов")           # по сотруднику
        _rate(self.s, 400, store="Лента-2", employee_name="Петров")  # индивид. (оба)
        self.s.commit()

    def _rates(self, cond):
        return {r.hourly_rate for r in self.s.query(Rate).filter(cond).all()}

    def test_individual_excludes_base(self):
        self.assertEqual(self._rates(_INDIVIDUAL), {200, 300, 400})

    def test_base_includes_empty_strings(self):
        # Пустая строка store/employee считается «не задан» → база.
        self.assertEqual(self._rates(_BASE), {100, 110})

    def test_store_layer(self):
        cond = and_(_HAS_STORE, or_(Rate.employee_name == None, Rate.employee_name == ""))
        self.assertEqual(self._rates(cond), {200})  # только чистая ТК-ставка

    def test_employee_layer(self):
        self.assertEqual(self._rates(_HAS_EMPLOYEE), {300, 400})

    def test_counts_partition(self):
        total = self.s.query(Rate).count()
        individual = self.s.query(Rate).filter(_INDIVIDUAL).count()
        base = self.s.query(Rate).filter(_BASE).count()
        self.assertEqual(total, 5)
        self.assertEqual(individual, 3)
        self.assertEqual(base, 2)
        self.assertEqual(individual + base, total)


if __name__ == "__main__":
    unittest.main()

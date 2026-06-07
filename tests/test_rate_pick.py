import os
import unittest
from datetime import date
from types import SimpleNamespace


os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from models import Rate
from utils import get_rate_for_shift, pick_rate


def make_rate(hourly_rate, service="service", format=None, store=None, employee_name=None, active_from=None, active_to=None):
    return Rate(
        service=service,
        format=format,
        store=store,
        employee_name=employee_name,
        hourly_rate=hourly_rate,
        active_from=active_from,
        active_to=active_to,
    )


def make_shift(service="service", format="GM", store="Store-1", employee="Employee", shift_date=date(2026, 6, 1)):
    return SimpleNamespace(
        service=service,
        format=format,
        store=store,
        employee=employee,
        shift_date=shift_date,
    )


class PickRateTests(unittest.TestCase):
    def test_employee_rate_has_highest_priority(self):
        rates = [
            make_rate(100),
            make_rate(110, format="GM"),
            make_rate(120, store="Store-1"),
            make_rate(130, employee_name="Employee"),
        ]
        self.assertEqual(pick_rate(rates, make_shift()).hourly_rate, 130)

    def test_store_rate_beats_format_rate(self):
        rates = [make_rate(100), make_rate(110, format="GM"), make_rate(120, store="Store-1")]
        self.assertEqual(pick_rate(rates, make_shift()).hourly_rate, 120)

    def test_rate_outside_active_window_is_ignored(self):
        rates = [
            make_rate(200, active_to=date(2026, 5, 31)),
            make_rate(100, active_from=date(2026, 6, 1), active_to=date(2026, 6, 30)),
        ]
        self.assertEqual(pick_rate(rates, make_shift()).hourly_rate, 100)

    def test_non_matching_dimensions_are_ignored(self):
        rates = [
            make_rate(200, format="SM"),
            make_rate(210, store="Store-2"),
            make_rate(220, employee_name="Other"),
            make_rate(100),
        ]
        self.assertEqual(pick_rate(rates, make_shift()).hourly_rate, 100)

    def test_returns_none_for_unknown_service(self):
        self.assertIsNone(pick_rate([make_rate(100)], make_shift(service="other")))

    def test_get_rate_wrapper_loads_rates_once(self):
        class Query:
            def __init__(self, rates):
                self.rates = rates

            def all(self):
                return self.rates

        class Session:
            def __init__(self, rates):
                self.rates = rates
                self.query_count = 0

            def query(self, model):
                self.query_count += 1
                return Query(self.rates)

        session = Session([make_rate(100)])
        self.assertEqual(get_rate_for_shift(session, make_shift()).hourly_rate, 100)
        self.assertEqual(session.query_count, 1)


if __name__ == "__main__":
    unittest.main()

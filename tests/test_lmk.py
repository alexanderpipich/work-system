import os
import unittest
from datetime import date
from types import SimpleNamespace


os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from lmk_charges import lmk_amount_for_charge, months_between


class LmkChargeTests(unittest.TestCase):
    def test_months_between_across_year_boundary(self):
        self.assertEqual(months_between(date(2025, 12, 1), date(2026, 2, 1)), 2)

    def test_charge_is_limited_by_remaining_amount(self):
        charge = SimpleNamespace(
            status="active",
            remaining_amount=1500,
            start_month=date(2026, 5, 1),
            months_count=3,
            monthly_amount=1000,
        )
        self.assertEqual(lmk_amount_for_charge(charge, date(2026, 5, 1), date(2026, 6, 30)), 1500)

    def test_inactive_or_future_charge_is_not_applied(self):
        inactive = SimpleNamespace(
            status="completed",
            remaining_amount=1000,
            start_month=date(2026, 5, 1),
            months_count=1,
            monthly_amount=1000,
        )
        future = SimpleNamespace(
            status="active",
            remaining_amount=1000,
            start_month=date(2026, 7, 1),
            months_count=1,
            monthly_amount=1000,
        )
        self.assertEqual(lmk_amount_for_charge(inactive, date(2026, 5, 1), date(2026, 5, 31)), 0)
        self.assertEqual(lmk_amount_for_charge(future, date(2026, 5, 1), date(2026, 5, 31)), 0)


if __name__ == "__main__":
    unittest.main()

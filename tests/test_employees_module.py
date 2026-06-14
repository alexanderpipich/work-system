import os
import unittest
from datetime import date


os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from routers.employees import _filename_part, is_fixed_reconciliation_period, reconciliation_ready_date


class ReconciliationPeriodTests(unittest.TestCase):
    def test_accepts_fixed_half_month_periods(self):
        self.assertTrue(is_fixed_reconciliation_period(date(2026, 6, 1), date(2026, 6, 15)))
        self.assertTrue(is_fixed_reconciliation_period(date(2026, 6, 16), date(2026, 6, 30)))
        self.assertTrue(is_fixed_reconciliation_period(date(2026, 2, 16), date(2026, 2, 28)))

    def test_rejects_arbitrary_period(self):
        self.assertFalse(is_fixed_reconciliation_period(date(2026, 6, 2), date(2026, 6, 15)))
        self.assertFalse(is_fixed_reconciliation_period(date(2026, 6, 16), date(2026, 7, 1)))

    def test_ready_date_skips_weekend(self):
        self.assertEqual(reconciliation_ready_date(date(2026, 6, 12)), date(2026, 6, 17))
        self.assertEqual(reconciliation_ready_date(date(2026, 6, 15)), date(2026, 6, 18))
    def test_filename_part_is_windows_safe(self):
        value = _filename_part("Иванов Иван / Лента-263", "employee")
        self.assertNotIn("?", value)
        self.assertNotIn("/", value)
        self.assertTrue(value)


if __name__ == "__main__":
    unittest.main()
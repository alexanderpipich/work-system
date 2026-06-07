import os
import unittest
from types import SimpleNamespace


os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from payroll_closing import close_payroll_run


class ClosedRunSession:
    def query(self, model):
        raise AssertionError("A closed run must return before any financial query")

    def commit(self):
        raise AssertionError("A closed run must not be committed again")


class CloseIdempotentTests(unittest.TestCase):
    def test_second_close_does_not_apply_financials(self):
        run = SimpleNamespace(status="closed")
        result = close_payroll_run(ClosedRunSession(), run, SimpleNamespace(id=1))
        self.assertFalse(result["closed"])
        self.assertEqual(result["auto_adjustments_applied"], 0)
        self.assertEqual(result["manual_adjustments_applied"], 0)
        self.assertEqual(result["lmk_payments_created"], 0)
        self.assertEqual(result["lmk_total_amount"], 0)


if __name__ == "__main__":
    unittest.main()

import os
import unittest
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from routers.payroll_runs import _all_items_accessible_to_cities


class PayrollRunCityAccessTests(unittest.TestCase):
    def test_rejects_empty_items_or_empty_scope(self):
        self.assertFalse(_all_items_accessible_to_cities(MagicMock(), [], ["Москва"]))
        self.assertFalse(_all_items_accessible_to_cities(MagicMock(), [object()], []))

    @patch("routers.payroll_runs._filter_items_by_cities")
    def test_accepts_only_when_every_item_is_accessible(self, filter_items):
        items = [object(), object()]
        filter_items.return_value = items
        self.assertTrue(_all_items_accessible_to_cities(MagicMock(), items, ["Москва"]))

        filter_items.return_value = items[:1]
        self.assertFalse(_all_items_accessible_to_cities(MagicMock(), items, ["Москва"]))


if __name__ == "__main__":
    unittest.main()

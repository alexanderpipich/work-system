import os
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from routers.reports import _scope_allowed_cities

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from access_scope_helpers import parse_scope_values, sync_access_scopes
from rbac import canonical_role, has_permission


class HrRbacTests(unittest.TestCase):
    def test_hr_lead_permissions_exclude_financial_and_technical_actions(self):
        user = SimpleNamespace(role="hr_lead", is_admin=False)
        self.assertTrue(has_permission(user, "employees.manage"))
        self.assertTrue(has_permission(user, "hr_team.manage"))
        self.assertFalse(has_permission(user, "payroll.manage"))
        self.assertFalse(has_permission(user, "system.technical"))

    def test_hr_manager_permissions_are_regional_hr_only(self):
        user = SimpleNamespace(role="hr_manager", is_admin=False)
        self.assertTrue(has_permission(user, "employees.manage"))
        self.assertTrue(has_permission(user, "documents.manage"))
        self.assertFalse(has_permission(user, "hr_team.manage"))
        self.assertTrue(has_permission(user, "payroll.view"))
        self.assertFalse(has_permission(user, "payroll.manage"))
        self.assertTrue(has_permission(user, "password.reset_limited"))

    def test_scope_parser_deduplicates_and_trims(self):
        self.assertEqual(parse_scope_values(" Москва,Казань, Москва "), ["Казань", "Москва"])

    @patch("access_scope_helpers.create_audit_log")
    def test_scope_sync_audits_changes(self, audit):
        session = MagicMock()
        session.query.return_value.filter.return_value.all.return_value = []
        actor = SimpleNamespace(id=1)
        target = SimpleNamespace(id=2, employee_name="Менеджер")
        values = sync_access_scopes(session, None, actor, target, "city", "Москва, Казань")
        self.assertEqual(values, ["Казань", "Москва"])
        self.assertEqual(session.add.call_count, 2)
        audit.assert_called_once()


    @patch("routers.reports.get_economist_cities", return_value=["Москва"])
    def test_hr_manager_reports_use_assigned_cities(self, get_cities):
        user = SimpleNamespace(role="hr_manager", is_admin=False)
        self.assertEqual(_scope_allowed_cities(user, economist=True), ["Москва"])
        get_cities.assert_called_once_with(user)

    def test_hr_lead_reports_are_unrestricted(self):
        user = SimpleNamespace(role="hr_lead", is_admin=False)
        self.assertIsNone(_scope_allowed_cities(user, economist=True))
if __name__ == "__main__":
    unittest.main()

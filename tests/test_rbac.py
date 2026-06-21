import os
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from rbac import canonical_role, can_access_city, can_access_store, get_scope_values, has_permission


class RbacRoleTests(unittest.TestCase):
    def test_old_admin_and_is_admin_are_superadmin(self):
        self.assertEqual(canonical_role(SimpleNamespace(role="admin", is_admin=False)), "superadmin")
        self.assertEqual(canonical_role(SimpleNamespace(role="employee", is_admin=True)), "superadmin")

    def test_unknown_role_falls_back_to_employee(self):
        self.assertEqual(canonical_role(SimpleNamespace(role="unknown", is_admin=False)), "employee")

    def test_permissions_are_explicit(self):
        economist = SimpleNamespace(role="economist", is_admin=False)
        self.assertTrue(has_permission(economist, "payroll.send"))
        self.assertFalse(has_permission(economist, "system.settings"))


class RbacScopeTests(unittest.TestCase):
    def _session_without_scopes(self):
        session = MagicMock()
        session.query.return_value.filter.return_value.all.return_value = []
        return session

    def test_economist_with_no_scope_returns_empty_set(self):
        # No UserAccessScope rows = empty set; legacy field is not read
        user = SimpleNamespace(id=1, role="economist", is_admin=False, economist_stores="Москва, Казань")
        self.assertEqual(get_scope_values(self._session_without_scopes(), user, "city"), set())

    def test_hr_manager_with_no_scope_returns_empty_set(self):
        user = SimpleNamespace(id=2, role="hr_manager", is_admin=False, economist_stores="Москва, Казань")
        self.assertEqual(get_scope_values(self._session_without_scopes(), user, "city"), set())
    def test_hr_manager_city_scope_is_enforced(self):
        session = MagicMock()
        session.query.return_value.filter.return_value.all.return_value = [("Москва",)]
        user = SimpleNamespace(id=2, role="hr_manager", is_admin=False)
        self.assertTrue(can_access_city(session, user, "Москва"))
        self.assertFalse(can_access_city(session, user, "Казань"))

    def test_superadmin_scope_is_unrestricted(self):
        user = SimpleNamespace(id=3, role="admin", is_admin=True)
        self.assertIsNone(get_scope_values(MagicMock(), user, "city"))

    def test_hr_manager_without_store_scope_gets_no_access(self):
        # After Step 5: empty scope = denied, not unrestricted
        user = SimpleNamespace(id=4, role="hr_manager", is_admin=False)
        self.assertFalse(can_access_store(self._session_without_scopes(), user, "Store-01"))

    def test_hr_manager_explicit_store_scope_is_enforced(self):
        session = MagicMock()
        session.query.return_value.filter.return_value.all.return_value = [("Store-01",)]
        user = SimpleNamespace(id=5, role="hr_manager", is_admin=False)
        self.assertTrue(can_access_store(session, user, "Store-01"))
        self.assertFalse(can_access_store(session, user, "Store-02"))


if __name__ == "__main__":
    unittest.main()

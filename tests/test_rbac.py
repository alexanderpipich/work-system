import os
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from access import get_economist_cities
from rbac import canonical_role, can_access_city, can_access_store, get_scope_values, has_permission, role_label


class RbacRoleTests(unittest.TestCase):
    def test_old_admin_and_is_admin_are_superadmin(self):
        self.assertEqual(canonical_role(SimpleNamespace(role="admin", is_admin=False)), "superadmin")
        self.assertEqual(canonical_role(SimpleNamespace(role="employee", is_admin=True)), "superadmin")

    def test_hr_manager_is_alias_of_tm(self):
        self.assertEqual(canonical_role(SimpleNamespace(role="hr_manager", is_admin=False)), "tm")
        self.assertEqual(canonical_role(SimpleNamespace(role="tm", is_admin=False)), "tm")
        self.assertEqual(canonical_role(SimpleNamespace(role="hr_clerk", is_admin=False)), "hr_clerk")

    def test_role_labels(self):
        self.assertEqual(role_label("hr_manager"), "ТМ (территориальный менеджер)")
        self.assertEqual(role_label("hr_clerk"), "Кадровик")

    def test_every_role_has_label(self):
        from rbac import ROLE_LABELS, ROLES
        self.assertEqual(set(ROLE_LABELS), set(ROLES))
        self.assertTrue(all(ROLE_LABELS.values()))
        self.assertEqual(ROLE_LABELS["hr_lead"], "HR-руководитель")
        self.assertEqual(ROLE_LABELS["headhunter"], "Рекрутер")

    def test_hr_clerk_permissions(self):
        clerk = SimpleNamespace(role="hr_clerk", is_admin=False)
        for perm in ("documents.manage", "citizenship.manage", "employees.view",
                     "services.view", "stores.directory.view"):
            self.assertTrue(has_permission(clerk, perm), perm)
        for perm in ("payroll.view", "payroll.manage", "rates.view", "rates.manage",
                     "requisites.view", "email.manage", "lmk.view", "reports.view"):
            self.assertFalse(has_permission(clerk, perm), perm)

    def test_unknown_role_falls_back_to_employee(self):
        self.assertEqual(canonical_role(SimpleNamespace(role="unknown", is_admin=False)), "employee")

    def test_permissions_are_explicit(self):
        economist = SimpleNamespace(role="economist", is_admin=False)
        self.assertTrue(has_permission(economist, "payroll.send"))
        self.assertFalse(has_permission(economist, "system.settings"))


class ScopesDisabledByDefaultTests(unittest.TestCase):
    """П1-В: скоупы выключены — ТМ и экономист видят всё."""

    def setUp(self):
        patcher = patch.dict(os.environ, {}, clear=False)
        patcher.start()
        os.environ.pop("SCOPES_ENABLED", None)
        self.addCleanup(patcher.stop)

    def test_tm_and_economist_unrestricted(self):
        for role in ("tm", "hr_manager", "economist", "hr_clerk"):
            user = SimpleNamespace(id=2, role=role, is_admin=False, economist_stores="Москва")
            self.assertIsNone(get_scope_values(MagicMock(), user, "city"), role)
            self.assertTrue(can_access_city(MagicMock(), user, "Казань"), role)

    def test_legacy_economist_cities_unrestricted(self):
        user = SimpleNamespace(role="economist", economist_stores="Москва")
        self.assertIsNone(get_economist_cities(user))


class RbacScopeTests(unittest.TestCase):
    """Прежняя логика скоупов — при SCOPES_ENABLED=true."""

    def setUp(self):
        patcher = patch.dict(os.environ, {"SCOPES_ENABLED": "true"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_legacy_economist_cities_read_when_enabled(self):
        user = SimpleNamespace(role="economist", economist_stores="Москва, Казань")
        self.assertEqual(get_economist_cities(user), ["Москва", "Казань"])

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

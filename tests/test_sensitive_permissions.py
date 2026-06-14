import os
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from dependencies import RedirectException
from rbac import has_permission, record_denied_action, require_permission


class SensitivePermissionTests(unittest.TestCase):
    def test_only_superadmin_has_implicit_sensitive_permissions(self):
        superadmin = SimpleNamespace(role="admin", is_admin=True)
        economist = SimpleNamespace(role="economist", is_admin=False)
        for permission in {
            "system.technical", "system.maintenance", "users.manage",
            "users.hard_delete", "payroll.close", "payroll.delete",
            "legal_entities.hard_delete", "rates.hard_delete",
        }:
            self.assertTrue(has_permission(superadmin, permission))
            self.assertFalse(has_permission(economist, permission))

    @patch("rbac.create_audit_log")
    def test_denied_sensitive_dependency_is_audited(self, create_log):
        session = MagicMock()
        request = SimpleNamespace(url=SimpleNamespace(path="/docs"))
        user = SimpleNamespace(id=7, role="economist", is_admin=False)
        dependency = require_permission("system.technical", audit_denied=True)

        with self.assertRaises(RedirectException):
            dependency(request=request, session=session, user=user)

        create_log.assert_called_once()
        self.assertEqual(create_log.call_args.args[3], "permission_denied")
        self.assertEqual(create_log.call_args.kwargs["entity_name"], "system.technical")
        session.commit.assert_called_once()

    @patch("rbac.create_audit_log")
    def test_record_denied_action_commits_audit(self, create_log):
        session = MagicMock()
        request = SimpleNamespace(url=SimpleNamespace(path="/admin/delete-user"))
        user = SimpleNamespace(id=8, role="hr_manager", is_admin=False)
        record_denied_action(session, request, user, "users.hard_delete")
        create_log.assert_called_once()
        session.commit.assert_called_once()


if __name__ == "__main__":
    unittest.main()

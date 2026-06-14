import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch


os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from audit_helpers import create_audit_log


class FakeSavepoint:
    def __init__(self):
        self.is_active = True
        self.committed = False
        self.rolled_back = False

    def commit(self):
        self.committed = True
        self.is_active = False

    def rollback(self):
        self.rolled_back = True
        self.is_active = False


class FakeConnection:
    def __init__(self, *, fail_execute=False):
        self.fail_execute = fail_execute
        self.savepoint = FakeSavepoint()
        self.executed = []

    def begin_nested(self):
        return self.savepoint

    def execute(self, statement):
        if self.fail_execute:
            raise RuntimeError("audit table unavailable")
        self.executed.append(statement)


class FakeBusinessSession:
    def __init__(self, connection):
        self._connection = connection
        self.committed = False
        self.rolled_back = False

    def connection(self):
        return self._connection

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True


class AuditHelperTests(unittest.TestCase):
    def test_audit_uses_savepoint_without_committing_business_transaction(self):
        connection = FakeConnection()
        business_session = FakeBusinessSession(connection)

        result = create_audit_log(
            business_session,
            None,
            SimpleNamespace(id=7, role="admin"),
            "test_action",
            "test_entity",
            entity_id=42,
        )

        self.assertTrue(result)
        self.assertTrue(connection.savepoint.committed)
        self.assertEqual(len(connection.executed), 1)
        self.assertFalse(business_session.committed)
        self.assertFalse(business_session.rolled_back)

    def test_audit_failure_rolls_back_only_savepoint(self):
        connection = FakeConnection(fail_execute=True)
        business_session = FakeBusinessSession(connection)

        with patch("audit_helpers.logger.exception"):
            result = create_audit_log(
                business_session,
                None,
                SimpleNamespace(id=7, role="admin"),
                "test_action",
                "test_entity",
            )

        self.assertFalse(result)
        self.assertTrue(connection.savepoint.rolled_back)
        self.assertFalse(business_session.committed)
        self.assertFalse(business_session.rolled_back)


if __name__ == "__main__":
    unittest.main()

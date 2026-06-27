import os
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from dependencies import RedirectException
from rbac import require_permission


def _user(role):
    return SimpleNamespace(
        id=1,
        role=role,
        is_admin=(role == "superadmin"),
        economist_stores="",
    )


def _allowed(perm, role):
    dep = require_permission(perm)
    req = SimpleNamespace(url=SimpleNamespace(path="/test"))
    try:
        dep(request=req, session=MagicMock(), user=_user(role))
        return True
    except RedirectException:
        return False


# (permission, roles_that_pass, roles_that_are_denied)
# Derived from the agreed audit table for RBAC-5 Step 2.
ROUTE_PERMISSION_MATRIX = [
    # reports
    ("reports.view",
        ["superadmin", "hr_lead", "hr_manager", "economist"],
        ["brigadier", "employee"]),

    # schedules
    ("schedules.view",
        ["superadmin", "economist", "hr_lead", "hr_manager", "brigadier"],
        ["employee"]),
    # bypass-only: admin schedules page shows all stores unfiltered
    ("schedules.admin_view",
        ["superadmin"],
        ["economist", "hr_lead", "hr_manager", "brigadier", "employee"]),

    # bypass-only: audit log, shift upload
    ("audit.view",
        ["superadmin"],
        ["economist", "hr_lead", "hr_manager", "brigadier", "employee"]),
    ("shifts.upload",
        ["superadmin"],
        ["economist", "hr_lead", "hr_manager", "brigadier", "employee"]),

    # lmk
    ("lmk.manage",
        ["superadmin", "economist"],
        ["hr_lead", "hr_manager", "brigadier", "employee"]),
    ("lmk.view",
        ["superadmin", "hr_lead", "hr_manager"],
        ["economist", "brigadier", "employee"]),

    # adjustments
    ("adjustments.manage",
        ["superadmin", "economist"],
        ["hr_lead", "hr_manager", "brigadier", "employee"]),

    # legal entities
    ("legal_entities.manage",
        ["superadmin", "economist"],
        ["hr_lead", "hr_manager", "brigadier", "employee"]),

    # documents
    # documents.manage goes to hr_lead/hr_manager; economist gets verify-only
    ("documents.manage",
        ["superadmin", "hr_lead", "hr_manager"],
        ["economist", "brigadier", "employee"]),
    ("documents.verify",
        ["superadmin", "economist"],
        ["hr_lead", "hr_manager", "brigadier", "employee"]),

    # payroll
    # payroll.manage: economist can create/fix runs (not just view)
    ("payroll.manage",
        ["superadmin", "economist"],
        ["hr_lead", "hr_manager", "brigadier", "employee"]),
    ("payroll.view",
        ["superadmin", "hr_lead", "hr_manager", "economist"],
        ["brigadier", "employee"]),

    # rates
    ("rates.manage",
        ["superadmin", "economist"],
        ["hr_lead", "hr_manager", "brigadier", "employee"]),
    ("rates.view",
        ["superadmin", "hr_lead", "hr_manager", "economist"],
        ["brigadier", "employee"]),

    # requisites: hr roles can manage; economist gets view-only
    ("requisites.manage",
        ["superadmin", "hr_lead", "hr_manager"],
        ["economist", "brigadier", "employee"]),

    # dashboards
    ("admin.dashboard",
        ["superadmin"],
        ["economist", "hr_lead", "hr_manager", "brigadier", "employee"]),
    ("economist.dashboard",
        ["superadmin", "economist"],
        ["hr_lead", "hr_manager", "brigadier", "employee"]),
    # bypass-only: planning scenarios, monitoring settings
    ("admin.settings",
        ["superadmin"],
        ["economist", "hr_lead", "hr_manager", "brigadier", "employee"]),
]


class RoutePermissionMatrixTests(unittest.TestCase):
    """Проверяет полную матрицу разрешений для всех мигрированных маршрутов."""

    def test_permission_grants_and_denials(self):
        for perm, allowed_roles, denied_roles in ROUTE_PERMISSION_MATRIX:
            for role in allowed_roles:
                with self.subTest(perm=perm, role=role, expect="allow"):
                    self.assertTrue(
                        _allowed(perm, role),
                        f"role '{role}' should have permission '{perm}'",
                    )
            for role in denied_roles:
                with self.subTest(perm=perm, role=role, expect="deny"):
                    self.assertFalse(
                        _allowed(perm, role),
                        f"role '{role}' should NOT have permission '{perm}'",
                    )


class SuperadminBypassTests(unittest.TestCase):
    """Superadmin проходит через любой require_permission, включая несуществующие права."""

    BYPASS_PERMS = [
        "audit.view",
        "shifts.upload",
        "schedules.admin_view",
        "admin.dashboard",
        "admin.settings",
        "some.completely.made_up.permission",
    ]

    def test_superadmin_passes_all_permissions(self):
        for perm in self.BYPASS_PERMS:
            with self.subTest(perm=perm):
                self.assertTrue(
                    _allowed(perm, "superadmin"),
                    f"superadmin should not be blocked by '{perm}'",
                )


class BrigadierBoundaryTests(unittest.TestCase):
    """Бригадир видит расписание, но не попадает в admin-раздел и финансы."""

    def test_brigadier_has_schedules_view(self):
        self.assertTrue(_allowed("schedules.view", "brigadier"))

    def test_brigadier_blocked_from_schedules_admin_view(self):
        self.assertFalse(_allowed("schedules.admin_view", "brigadier"))

    def test_brigadier_blocked_from_payroll(self):
        self.assertFalse(_allowed("payroll.view", "brigadier"))
        self.assertFalse(_allowed("payroll.manage", "brigadier"))

    def test_brigadier_blocked_from_reports(self):
        self.assertFalse(_allowed("reports.view", "brigadier"))


class EconomistBoundaryTests(unittest.TestCase):
    """Экономист имеет управление, но не bypass-права суперадмина."""

    def test_economist_has_payroll_manage_not_export(self):
        self.assertTrue(_allowed("payroll.manage", "economist"))
        self.assertFalse(_allowed("payroll.export", "economist"))

    def test_economist_has_documents_verify_not_manage(self):
        self.assertTrue(_allowed("documents.verify", "economist"))
        self.assertFalse(_allowed("documents.manage", "economist"))

    def test_economist_has_lmk_manage_not_view(self):
        # lmk.manage и lmk.view — разные права; economist имеет только manage
        self.assertTrue(_allowed("lmk.manage", "economist"))
        self.assertFalse(_allowed("lmk.view", "economist"))

    def test_economist_has_economist_dashboard_not_admin(self):
        self.assertTrue(_allowed("economist.dashboard", "economist"))
        self.assertFalse(_allowed("admin.dashboard", "economist"))
        self.assertFalse(_allowed("admin.settings", "economist"))

    def test_economist_has_requisites_view_not_manage(self):
        # Управление реквизитами — только у HR-ролей
        self.assertFalse(_allowed("requisites.manage", "economist"))


class HrPayrollBoundaryTests(unittest.TestCase):
    """HR-роли видят выплаты, но не управляют ими."""

    def test_hr_lead_has_payroll_view_not_manage(self):
        self.assertTrue(_allowed("payroll.view", "hr_lead"))
        self.assertFalse(_allowed("payroll.manage", "hr_lead"))

    def test_hr_manager_has_payroll_view_not_manage(self):
        self.assertTrue(_allowed("payroll.view", "hr_manager"))
        self.assertFalse(_allowed("payroll.manage", "hr_manager"))

    def test_hr_roles_have_lmk_view_not_manage(self):
        for role in ("hr_lead", "hr_manager"):
            with self.subTest(role=role):
                self.assertTrue(_allowed("lmk.view", role))
                self.assertFalse(_allowed("lmk.manage", role))

    def test_hr_roles_have_requisites_manage(self):
        for role in ("hr_lead", "hr_manager"):
            with self.subTest(role=role):
                self.assertTrue(_allowed("requisites.manage", role))

    def test_hr_roles_blocked_from_admin_settings(self):
        for role in ("hr_lead", "hr_manager"):
            with self.subTest(role=role):
                self.assertFalse(_allowed("admin.settings", role))
                self.assertFalse(_allowed("admin.dashboard", role))


if __name__ == "__main__":
    unittest.main()

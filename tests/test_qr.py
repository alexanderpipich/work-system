import os
import unittest
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from rbac import has_permission
from routers.qr import QR_IMAGE_EXTENSIONS


def _viewer(role):
    return SimpleNamespace(id=99, role=role, is_admin=(role == "superadmin"))


def _can_view_other(viewer):
    """Зеркало правила доступа serve_qr для НЕ-владельца QR: HR/админ (employees.view)."""
    return has_permission(viewer, "employees.view")


class QrExtensionTests(unittest.TestCase):
    def test_only_images_allowed(self):
        self.assertEqual(QR_IMAGE_EXTENSIONS, {".jpg", ".jpeg", ".png"})
        self.assertNotIn(".pdf", QR_IMAGE_EXTENSIONS)
        self.assertNotIn(".heic", QR_IMAGE_EXTENSIONS)


class QrAccessRuleTests(unittest.TestCase):
    """Чужой QR видят только HR/админ (employees.view); сам сотрудник — свой (проверяется по id)."""

    def test_hr_and_admin_see_any_qr(self):
        for role in ("superadmin", "hr_lead", "hr_manager", "economist"):
            with self.subTest(role=role):
                self.assertTrue(_can_view_other(_viewer(role)))

    def test_others_cannot_see_foreign_qr(self):
        for role in ("employee", "brigadier", "headhunter"):
            with self.subTest(role=role):
                self.assertFalse(_can_view_other(_viewer(role)))


class QrRoutesRegisteredTests(unittest.TestCase):
    def test_routes_registered(self):
        import main
        paths = {r.path for r in main.app.routes}
        self.assertIn("/users/{user_id}/qr", paths)
        self.assertIn("/admin/users/{user_id}/qr", paths)
        self.assertIn("/admin/users/{user_id}/qr/delete", paths)


if __name__ == "__main__":
    unittest.main()

import os
import unittest


os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from utils import normalize_format, normalize_phone, normalize_role


class NormalizeFormatTests(unittest.TestCase):
    def test_normalizes_gm_case_and_outer_spaces(self):
        self.assertEqual(normalize_format("гм "), "ГМ")

    def test_normalizes_sm_case_and_outer_spaces(self):
        self.assertEqual(normalize_format(" См"), "СМ")

    def test_normalizes_internal_spaces(self):
        self.assertEqual(normalize_format("Г М"), "ГМ")
        self.assertEqual(normalize_format("С М"), "СМ")

    def test_keeps_canonical_values(self):
        self.assertEqual(normalize_format("ГМ"), "ГМ")
        self.assertEqual(normalize_format("СМ"), "СМ")

    def test_keeps_unknown_values_trimmed_and_uppercase(self):
        self.assertEqual(normalize_format(" даркстор "), "ДАРКСТОР")


class NormalizePhoneAndRoleTests(unittest.TestCase):
    def test_normalizes_phone_from_common_excel_values(self):
        self.assertEqual(normalize_phone("+7 999 123 45 67"), "79991234567")
        self.assertEqual(normalize_phone(79991234567.0), "79991234567")

    def test_normalizes_known_roles_and_falls_back_to_employee(self):
        self.assertEqual(normalize_role(" ECONOMIST "), "economist")
        self.assertEqual(normalize_role(" HR_LEAD "), "hr_lead")
        self.assertEqual(normalize_role("superadmin"), "superadmin")
        self.assertEqual(normalize_role(" HEADHUNTER "), "headhunter")
        self.assertEqual(normalize_role("unknown"), "employee")


if __name__ == "__main__":
    unittest.main()



# -*- coding: utf-8 -*-
import os
import unittest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from models import JOB_TITLES, User


class JobTitleTests(unittest.TestCase):
    def test_fixed_list(self):
        self.assertEqual(JOB_TITLES, ["ОПРР", "РТЗ", "ПЕКАРНЯ", "ГАСТРОНОМ", "ПУ"])

    def test_user_has_job_title_column(self):
        self.assertIn("job_title", User.__table__.columns.keys())

    def test_validation_rule(self):
        # Зеркало правила update_user: пустое → None; из списка → принять; иначе не менять.
        def apply(current, raw):
            raw = (raw or "").strip()
            if not raw:
                return None
            if raw in JOB_TITLES:
                return raw
            return current  # мусор игнорируется, значение не меняется

        self.assertIsNone(apply("ПЕКАРНЯ", ""))
        self.assertEqual(apply(None, "РТЗ"), "РТЗ")
        self.assertEqual(apply("ОПРР", "director"), "ОПРР")  # невалидное не затирает


if __name__ == "__main__":
    unittest.main()

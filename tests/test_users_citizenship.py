import json
import os
import unittest
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import AuditLog, CitizenshipRegime, Country, User
from routers.users import update_user_citizenship


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _payload(response):
    return json.loads(bytes(response.body).decode("utf-8"))


class UpdateUserCitizenshipTests(unittest.TestCase):
    """Точечное сохранение гражданства: тот же механизм, что update_user (citizenship_country_id)."""

    def setUp(self):
        self.s = _session()
        self.admin = SimpleNamespace(id=1, role="superadmin", is_admin=True)
        self.s.add(CitizenshipRegime(id=1, code="visa_free", name="Безвизовый", is_active=True))
        self.s.add(Country(id=10, name="Узбекистан", regime_id=1, is_active=True))
        self.s.add(Country(id=11, name="Таджикистан", regime_id=1, is_active=True))
        self.s.add(Country(id=12, name="Архивная", regime_id=1, is_active=False))
        self.user = User(phone="+70000000001", password_hash="x", employee_name="Иванов И.И.", role="employee")
        self.s.add(self.user)
        self.s.commit()

    def tearDown(self):
        self.s.close()

    def _save(self, country_id, user_id=None):
        return _payload(update_user_citizenship(
            request=None,
            user_id=user_id if user_id is not None else self.user.id,
            citizenship_country_id=country_id,
            session=self.s,
            admin=self.admin,
        ))

    def test_sets_citizenship(self):
        data = self._save(10)
        self.assertTrue(data["ok"])
        self.assertEqual(data["citizenship_country_id"], 10)
        self.assertEqual(data["citizenship_name"], "Узбекистан")
        self.assertEqual(self.user.citizenship_country_id, 10)

    def test_zero_clears_citizenship(self):
        self._save(10)
        data = self._save(0)
        self.assertTrue(data["ok"])
        self.assertIsNone(data["citizenship_country_id"])
        self.assertEqual(data["citizenship_name"], "")
        # Канон: пустое значение → None, как в update_user (`... or None`).
        self.assertIsNone(self.user.citizenship_country_id)

    def test_unknown_or_inactive_country_is_refused(self):
        for country_id in (999, 12):
            with self.subTest(country_id=country_id):
                data = self._save(country_id)
                self.assertFalse(data["ok"])
                self.assertIsNone(self.user.citizenship_country_id)

    def test_unknown_user_is_refused(self):
        self.assertFalse(self._save(10, user_id=4242)["ok"])

    def test_change_is_audited_with_old_and_new(self):
        self._save(10)
        self._save(11)
        logs = self.s.query(AuditLog).filter(AuditLog.action == "user_citizenship_updated").all()
        self.assertEqual(len(logs), 2)
        self.assertEqual(json.loads(logs[1].old_value)["citizenship_country_id"], 10)
        self.assertEqual(json.loads(logs[1].new_value)["citizenship_country_id"], 11)

    def test_other_user_fields_are_untouched(self):
        self.user.role = "brigadier"
        self.user.legal_entity = "ООО Тест"
        self.s.commit()
        self._save(10)
        self.assertEqual(self.user.role, "brigadier")
        self.assertEqual(self.user.legal_entity, "ООО Тест")
        self.assertEqual(self.user.phone, "+70000000001")


class CitizenshipPageRoutesTests(unittest.TestCase):
    def test_routes_registered(self):
        import main
        paths = {r.path for r in main.app.routes}
        self.assertIn("/admin/users/citizenship", paths)
        self.assertIn("/admin/users/{user_id}/citizenship", paths)

    def test_static_path_wins_over_pending_and_id_routes(self):
        """/admin/users/citizenship — статический путь, его не должен перехватывать
        параметризованный роут."""
        import main
        ordered = [r.path for r in main.app.routes if r.path.startswith("/admin/users")]
        self.assertLess(
            ordered.index("/admin/users/citizenship"),
            ordered.index("/admin/users/{user_id}/citizenship"),
        )


if __name__ == "__main__":
    unittest.main()

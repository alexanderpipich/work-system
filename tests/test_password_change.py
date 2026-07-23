# -*- coding: utf-8 -*-
import os
import unittest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import User
from routers.employee import validate_password_change
from utils import get_password_hash, verify_password


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _user(password="obshiy123", temporary=True):
    return User(
        phone="79990001122",
        password_hash=get_password_hash(password),
        employee_name="Иванов И.И.",
        role="employee",
        password_is_temporary=temporary,
    )


class ValidatePasswordChangeTests(unittest.TestCase):
    def test_wrong_current_rejected(self):
        u = _user(password="obshiy123")
        err = validate_password_change(u, "wrongpass", "newpass1", "newpass1")
        self.assertEqual(err, "Текущий пароль неверный")

    def test_short_new_rejected(self):
        u = _user(password="obshiy123")
        err = validate_password_change(u, "obshiy123", "abc", "abc")
        self.assertIn("минимум 6", err)

    def test_repeat_mismatch_rejected(self):
        u = _user(password="obshiy123")
        err = validate_password_change(u, "obshiy123", "newpass1", "newpass2")
        self.assertIn("не совпадают", err)

    def test_new_equals_current_rejected(self):
        u = _user(password="obshiy123")
        err = validate_password_change(u, "obshiy123", "obshiy123", "obshiy123")
        self.assertIn("совпадает с текущим", err)

    def test_valid_change_passes(self):
        u = _user(password="obshiy123")
        err = validate_password_change(u, "obshiy123", "mynewpass9", "mynewpass9")
        self.assertIsNone(err)


class FlagAndPersistenceTests(unittest.TestCase):
    def test_change_clears_temporary_and_updates_hash(self):
        s = _session()
        u = _user(password="obshiy123", temporary=True)
        s.add(u)
        s.commit()

        # Валидация проходит, затем применяем как эндпоинт.
        self.assertIsNone(validate_password_change(u, "obshiy123", "mynewpass9", "mynewpass9"))
        u.password_hash = get_password_hash("mynewpass9")
        u.password_is_temporary = False
        s.commit()

        reloaded = s.query(User).filter(User.id == u.id).first()
        self.assertFalse(reloaded.password_is_temporary)
        self.assertTrue(verify_password("mynewpass9", reloaded.password_hash))
        self.assertFalse(verify_password("obshiy123", reloaded.password_hash))

    def test_new_user_default_flag_is_false(self):
        s = _session()
        u = User(phone="79990002233", password_hash=get_password_hash("x123456"),
                 employee_name="Петров П.П.", role="employee")
        s.add(u)
        s.commit()
        self.assertFalse(bool(s.query(User).filter(User.id == u.id).first().password_is_temporary))

    def test_can_flag_temporary_true(self):
        s = _session()
        u = _user(temporary=True)
        s.add(u)
        s.commit()
        self.assertTrue(bool(s.query(User).filter(User.id == u.id).first().password_is_temporary))


if __name__ == "__main__":
    unittest.main()

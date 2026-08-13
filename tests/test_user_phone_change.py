"""Смена телефона сотруднику (п.007). Телефон — это логин, цена ошибки — потеря доступа."""

import os
import unittest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

import inspect

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import User
from routers.users import _user_payload, update_user
from utils import normalize_phone


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


class PhoneFieldWiringTests(unittest.TestCase):
    """Поле обязано доехать до роута и попасть в аудит."""

    def test_route_accepts_phone(self):
        self.assertIn("phone", inspect.signature(update_user).parameters)

    def test_phone_is_in_audit_payload(self):
        # Без этого смена логина не будет видна в журнале.
        user = User(id=1, phone="79990000001", employee_name="Иванова Т.М.",
                    password_hash="x", role="employee")
        self.assertIn("phone", _user_payload(user))
        self.assertEqual(_user_payload(user)["phone"], "79990000001")


class PhoneUniquenessTests(unittest.TestCase):
    """Уникальность телефона — не украшение: два одинаковых логина ломают вход."""

    def setUp(self):
        self.session = _session()
        self.session.add(User(id=1, phone="79990000001", employee_name="Иванова Т.М.",
                              password_hash="x", role="employee"))
        self.session.add(User(id=2, phone="79990000002", employee_name="Петров П.П.",
                              password_hash="x", role="employee"))
        self.session.commit()

    def _taken_by_other(self, phone, user_id):
        """Тот же запрос, что делает роут перед сменой номера."""
        return self.session.query(User).filter(
            User.phone == normalize_phone(phone), User.id != user_id
        ).first()

    def test_phone_of_another_user_is_detected(self):
        taken = self._taken_by_other("79990000002", user_id=1)
        self.assertIsNotNone(taken)
        self.assertEqual(taken.employee_name, "Петров П.П.")

    def test_own_phone_is_not_a_conflict(self):
        # Сохранение формы без смены номера не должно упираться в самого себя.
        self.assertIsNone(self._taken_by_other("79990000001", user_id=1))

    def test_free_phone_is_allowed(self):
        self.assertIsNone(self._taken_by_other("79995550000", user_id=1))

    def test_spaces_and_plus_are_ignored_when_comparing(self):
        # «+7 999 000 00 02» и «79990000002» — один и тот же логин.
        self.assertIsNotNone(self._taken_by_other("+7 999 000 00 02", user_id=1))


class PhoneNormalizationTests(unittest.TestCase):
    """Что normalize_phone умеет на самом деле — и почему форма требует цифры."""

    def test_spaces_and_plus_are_stripped(self):
        for raw in ("79990000001", "+7 999 000 00 01", " 79990000001 "):
            with self.subTest(raw=raw):
                self.assertEqual(normalize_phone(raw), "79990000001")

    def test_brackets_and_dashes_survive(self):
        """Зафиксировано намеренно: normalize_phone их НЕ убирает.

        Поэтому «7(999)000-00-01» и «79990000001» для системы — разные логины.
        Чинить саму функцию нельзя: по ней работает вход, и пользователи с уже
        сохранённым «грязным» номером потеряют доступ. Вместо этого форма смены
        телефона требует чистые цифры — см. update_user.
        """
        self.assertEqual(normalize_phone("+7 (999) 000-00-01"), "7(999)000-00-01")
        self.assertFalse(normalize_phone("+7 (999) 000-00-01").isdigit())

    def test_excel_float_tail_is_stripped(self):
        # Телефон из Excel приезжает как 79990000001.0
        self.assertEqual(normalize_phone("79990000001.0"), "79990000001")
        self.assertEqual(normalize_phone(79990000001.0), "79990000001")

    def test_empty_stays_empty(self):
        # Пустое поле в форме означает «не менять», а не «стереть номер».
        self.assertFalse(normalize_phone(""))


if __name__ == "__main__":
    unittest.main()

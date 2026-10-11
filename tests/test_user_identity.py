"""П1-Б: уникальность ФИО и сотрудник без кабинета."""

import os
import unittest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.middleware.sessions import SessionMiddleware

from database import Base
from dependencies import current_user, get_db
from models import User
from routers.auth import router as auth_router
from routers.users import router as users_router
from utils import find_user_by_name, get_password_hash, normalize_person_name, verify_password


def _sessionmaker():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


class NormalizePersonNameTests(unittest.TestCase):
    def test_case_yo_and_spaces_collapse(self):
        self.assertEqual(
            normalize_person_name("  Сёмин   Пётр  Иванович "),
            normalize_person_name("семин петр иванович"),
        )

    def test_empty(self):
        self.assertEqual(normalize_person_name(None), "")


class UniqueNameTests(unittest.TestCase):
    def setUp(self):
        self.session = _sessionmaker()()
        self.session.add(User(employee_name="Сёмин Пётр", role="employee"))
        self.session.commit()

    def test_norm_filled_by_orm_event(self):
        user = self.session.query(User).one()
        self.assertEqual(user.employee_name_norm, "семин петр")
        user.employee_name = "Сёмин  Пётр Ильич"
        self.session.commit()
        self.assertEqual(user.employee_name_norm, "семин петр ильич")

    def test_second_user_with_same_name_other_case_and_yo_rejected(self):
        self.session.add(User(employee_name="СЕМИН ПЕТР", role="employee"))
        with self.assertRaises(IntegrityError):
            self.session.commit()

    def test_find_user_by_name(self):
        self.assertIsNotNone(find_user_by_name(self.session, "семин  петр"))
        self.assertIsNone(find_user_by_name(self.session, "Другой"))
        self.assertIsNone(find_user_by_name(self.session, ""))

    def test_many_users_without_phone_allowed(self):
        self.session.add(User(employee_name="Без Телефона Два", role="employee"))
        self.session.commit()
        self.assertEqual(self.session.query(User).filter(User.phone == None).count(), 2)


def _client(Session, admin_role="superadmin"):
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test")
    app.include_router(auth_router)
    app.include_router(users_router)

    def override_db():
        session = Session()
        try:
            yield session
        finally:
            session.close()

    def override_user():
        session = Session()
        admin = session.query(User).filter(User.role == admin_role).first()
        session.close()
        return admin

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[current_user] = override_user
    return TestClient(app)


class LoginWithoutCabinetTests(unittest.TestCase):
    def setUp(self):
        self.Session = _sessionmaker()
        session = self.Session()
        # Телефон вписан в карточку, пароль ещё не выдан — кабинета нет.
        session.add(User(employee_name="Без Кабинета", phone="79990000002", role="employee"))
        session.add(User(employee_name="С Кабинетом", phone="79990000001",
                         password_hash=get_password_hash("secret1"), role="employee"))
        session.commit()
        session.close()
        self.client = _client(self.Session)

    def test_verify_password_none_hash(self):
        self.assertFalse(verify_password("anything", None))

    def test_login_without_password_hash_refused_like_wrong_password(self):
        response = self.client.post("/login", data={"phone": "79990000002", "password": "x"},
                                    follow_redirects=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Неверный телефон или пароль", response.text)

    def test_login_with_cabinet_works(self):
        response = self.client.post("/login", data={"phone": "79990000001", "password": "secret1"},
                                    follow_redirects=False)
        self.assertEqual(response.status_code, 302)


class CreateUserContractTests(unittest.TestCase):
    def setUp(self):
        self.Session = _sessionmaker()
        session = self.Session()
        session.add(User(employee_name="Админ", phone="70000000000", password_hash="x", role="superadmin"))
        session.add(User(employee_name="Ёлкин Иван", role="employee"))  # без кабинета
        session.add(User(employee_name="Занятый Кабинет", phone="79990000009",
                         password_hash="x", role="employee"))
        session.commit()
        session.close()
        self.client = _client(self.Session)

    def _create(self, **fields):
        data = {"phone": "", "password": "", "employee_name": "", "role": "employee",
                "citizenship_country_id": "1"}
        data.update(fields)
        return self.client.post("/admin/create-user", data=data)

    def test_without_cabinet_creates_user_with_null_login(self):
        response = self._create(employee_name="Новый Сотрудник")
        self.assertIn("Пользователь создан", response.text)
        user = find_user_by_name(self.Session(), "Новый Сотрудник")
        self.assertIsNone(user.phone)
        self.assertIsNone(user.password_hash)

    def test_phone_without_password_refused(self):
        response = self._create(employee_name="Новый Сотрудник", phone="79990000002")
        self.assertIn("и телефон, и пароль", response.text)
        self.assertIsNone(find_user_by_name(self.Session(), "Новый Сотрудник"))

    def test_existing_without_cabinet_gets_cabinet(self):
        response = self._create(employee_name="ЕЛКИН ИВАН", phone="79990000003", password="secret1")
        self.assertIn("выдан кабинет", response.text)
        session = self.Session()
        self.assertEqual(session.query(User).filter(User.employee_name_norm == "елкин иван").count(), 1)
        user = find_user_by_name(session, "Ёлкин Иван")
        self.assertEqual(user.phone, "79990000003")
        self.assertTrue(verify_password("secret1", user.password_hash))

    def test_existing_with_cabinet_refused(self):
        response = self._create(employee_name="занятый кабинет", phone="79990000004", password="secret1")
        self.assertIn("уже есть", response.text)
        self.assertEqual(find_user_by_name(self.Session(), "Занятый Кабинет").phone, "79990000009")

    def test_change_password_requires_phone(self):
        session = self.Session()
        user_id = find_user_by_name(session, "Ёлкин Иван").id
        session.close()
        response = self.client.post("/admin/change-password", data={"user_id": user_id, "new_password": "p1"})
        self.assertIn("нет телефона", response.text)
        self.assertIsNone(find_user_by_name(self.Session(), "Ёлкин Иван").password_hash)


class CreateAdminTests(unittest.TestCase):
    def test_existing_employee_without_cabinet_becomes_admin(self):
        from create_admin import ensure_admin

        session = _sessionmaker()()
        session.add(User(employee_name="Пипич Александр Владимирович", role="employee"))
        session.commit()
        user, created = ensure_admin(session, "79990000000", "пипич александр владимирович", "pass123")
        session.commit()
        self.assertFalse(created)
        self.assertEqual(session.query(User).count(), 1)
        self.assertEqual((user.role, user.phone), ("superadmin", "79990000000"))
        self.assertTrue(verify_password("pass123", user.password_hash))

    def test_creates_when_absent(self):
        from create_admin import ensure_admin

        session = _sessionmaker()()
        user, created = ensure_admin(session, "79990000000", "Новый Админ", "pass123")
        session.commit()
        self.assertTrue(created)
        self.assertTrue(user.is_admin)


if __name__ == "__main__":
    unittest.main()

"""П1-Г: реквизиты под карты, валидация способов выплаты, импорт из файла авансов."""

import os
import tempfile
import unittest
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

import openpyxl
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base
from dependencies import current_user, get_db
from models import Requisite, User
from requisite_validation import WARNING, is_payable, requisite_problems
from routers.requisites import router as requisites_router
from tools.import_employees_cards import canonical_bank, import_rows, payout_method_from, read_rows
from utils import (card_number_issues, card_phone_issues, find_user_by_name, format_card_number,
                   luhn_valid, normalize_card_expiry, normalize_card_number, normalize_card_phone)

VALID_CARD = "2202206716673921"  # проходит Luhn
BAD_LUHN = "2202206716673922"


def _req(**fields):
    base = dict(is_active=True, is_verified=True, inn="", account_number="", bik="", bank_name="",
                payout_method="card_phone", card_number=None, card_phone=None)
    base.update(fields)
    return SimpleNamespace(**base)


def _sessionmaker():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


class CardUtilsTests(unittest.TestCase):
    def test_card_input_with_spaces_and_dashes(self):
        self.assertEqual(normalize_card_number("2202 2067-1667 3921"), VALID_CARD)
        self.assertEqual(normalize_card_number(2202206716673921.0), VALID_CARD)

    def test_card_format(self):
        self.assertEqual(format_card_number(VALID_CARD), "2202 2067 1667 3921")
        self.assertEqual(format_card_number("1234567890123456789"), "1234 5678 9012 3456 789")

    def test_card_length(self):
        self.assertEqual(card_number_issues(VALID_CARD), [])
        self.assertEqual(card_number_issues("1234567890123456789"), [])  # 19 цифр — бывает
        self.assertIn("8 цифр", card_number_issues("22022067")[0])
        self.assertTrue(card_number_issues("2202abcd16673921"))

    def test_luhn(self):
        self.assertTrue(luhn_valid(VALID_CARD))
        self.assertFalse(luhn_valid(BAD_LUHN))

    def test_card_phone(self):
        self.assertEqual(normalize_card_phone("8 (911) 123-45-67"), "79111234567")
        self.assertEqual(normalize_card_phone("9111234567"), "79111234567")
        self.assertEqual(card_phone_issues("79111234567"), [])
        self.assertTrue(card_phone_issues("12345"))

    def test_expiry(self):
        self.assertEqual(normalize_card_expiry("3/27"), "03/27")
        self.assertEqual(normalize_card_expiry("11", "2035"), "11/35")
        self.assertEqual(normalize_card_expiry("13", "27"), "")
        self.assertEqual(normalize_card_expiry("скоро"), "")


class PayabilityTests(unittest.TestCase):
    def test_card_alone_is_payable_even_for_card_phone_method(self):
        self.assertTrue(is_payable(_req(card_number=VALID_CARD)))

    def test_bank_and_phone_is_payable(self):
        self.assertTrue(is_payable(_req(bank_name="Сбербанк", card_phone="79111234567")))

    def test_phone_without_bank_is_not(self):
        problems = [text for _, text in requisite_problems(_req(card_phone="79111234567"))]
        self.assertIn("Банк не указан", problems)

    def test_cash_needs_nothing(self):
        self.assertTrue(is_payable(_req(payout_method="cash")))

    def test_legacy_account_still_payable(self):
        req = _req(payout_method="card", inn="7707083893", account_number="40817810099910004312",
                   bik="044525225")
        self.assertTrue(is_payable(req))

    def test_nothing_filled_not_payable_and_no_legacy_noise(self):
        texts = [text for _, text in requisite_problems(_req())]
        self.assertFalse(is_payable(_req()))
        self.assertFalse(any("ИНН" in t or "БИК" in t for t in texts), texts)

    def test_luhn_is_warning_only(self):
        req = _req(card_number=BAD_LUHN)
        self.assertIn(WARNING, [kind for kind, _ in requisite_problems(req)])
        self.assertTrue(is_payable(req))

    def test_unverified_still_blocks(self):
        self.assertFalse(is_payable(_req(card_number=VALID_CARD, is_verified=False)))


class RequisiteFormTests(unittest.TestCase):
    def setUp(self):
        self.Session = _sessionmaker()
        session = self.Session()
        session.add(User(employee_name="Админ", phone="70000000000", password_hash="x", role="superadmin"))
        session.add(Requisite(employee_name="Иванов Иван", card_number=VALID_CARD, card_phone="79111234567",
                              card_expiry="03/27", payout_method="card", bank_name="Сбербанк", is_active=True))
        session.commit()
        session.close()

        app = FastAPI()
        app.include_router(requisites_router)

        def override_db():
            db = self.Session()
            try:
                yield db
            finally:
                db.close()

        def override_user():
            db = self.Session()
            user = db.query(User).first()
            db.close()
            return user

        app.dependency_overrides[get_db] = override_db
        app.dependency_overrides[current_user] = override_user
        self.client = TestClient(app)

    def _req(self):
        return self.Session().query(Requisite).one()

    def test_update_from_form_without_card_fields_keeps_card(self):
        # /hr/requisites шлёт форму без полей карты — карта не должна стереться.
        self.client.post("/admin/requisites/update", data={
            "requisite_id": self._req().id, "employee_name": "Иванов Иван", "bank_name": "Сбербанк",
            "is_active": "on"}, follow_redirects=False)
        req = self._req()
        self.assertEqual((req.card_number, req.card_phone, req.card_expiry), (VALID_CARD, "79111234567", "03/27"))

    def test_update_card_fields_normalized(self):
        self.client.post("/admin/requisites/update", data={
            "requisite_id": self._req().id, "employee_name": "Иванов Иван", "payout_method": "card_phone",
            "card_number": "2202 2067 1667 3921", "card_phone": "8 911 765-43-21", "card_expiry": "4/28",
            "is_active": "on"}, follow_redirects=False)
        req = self._req()
        self.assertEqual((req.payout_method, req.card_number, req.card_phone, req.card_expiry),
                         ("card_phone", VALID_CARD, "79117654321", "04/28"))

    def test_bad_expiry_refused(self):
        response = self.client.post("/admin/requisites/update", data={
            "requisite_id": self._req().id, "employee_name": "Иванов Иван", "payout_method": "card",
            "card_number": VALID_CARD, "card_expiry": "когда-нибудь", "is_active": "on"}, follow_redirects=False)
        self.assertIn("error=", response.headers["location"])
        self.assertEqual(self._req().card_expiry, "03/27")

    def test_registry_shows_formatted_card(self):
        html = self.client.get("/admin/requisites").text
        self.assertIn("2202 2067 1667 3921", html)


HEADER = ["Сотрудник", "Номер карты", "Месяц", "Год", "Телефон", "Адрес эл. почты", "Получатель ФИО",
          "Банк получателя", "Итого к выплате", "Проект", "Менеджер", "Назначение", "Способ выплаты"]


def _xlsx(rows):
    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet.append(HEADER)
    for row in rows:
        sheet.append(row)
    handle = tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False)
    workbook.save(handle.name)
    return handle.name


class ImportEmployeesCardsTests(unittest.TestCase):
    ROWS = [
        ["Иванов Иван", VALID_CARD, "11", "35", "9111234567", None, "Иванов Иван", "сбер", 100, "П",
         "Андрей Пиунов", "Аванс", "Карта/номер телефона"],
        ["Петров Пётр", "22022067", None, None, None, None, "Петрова Анна", "Т банк", 100, "П",
         "Пиунов Андрей", "Аванс", "Карта/телефон"],
        ["Сидоров Сидор", "наличные", None, None, None, None, "Сидоров Сидор", None, 100, "П",
         "Пипич", "Аванс", "Карта/номер телефона"],
        ["Ёлкин Олег", VALID_CARD, None, None, None, None, "Ёлкин Олег", "НеизвестныйБанк", 100, "П",
         None, "Аванс", "Карта"],
    ]

    def setUp(self):
        self.path = _xlsx(self.ROWS)
        self.addCleanup(os.unlink, self.path)
        self.session = _sessionmaker()()
        self.session.add(User(employee_name="Пипич Александр Владимирович", phone="79110000000",
                              password_hash="x", role="superadmin", is_admin=True))
        self.session.add(User(employee_name="елкин олег", role="employee"))  # уже есть, другой регистр/ё
        self.session.commit()

    def test_helpers(self):
        self.assertEqual(canonical_bank("Т банк"), ("Т-Банк", True))
        self.assertEqual(canonical_bank("Тинькоф"), ("Т-Банк", True))
        self.assertEqual(canonical_bank("ФораБанк"), ("ФораБанк", False))
        self.assertEqual(payout_method_from("Карта", None, None), "card")
        self.assertEqual(payout_method_from("Карта/телефон", "Наличные", None), "cash")

    def test_import(self):
        report = import_rows(self.session, read_rows(self.path), apply=True)
        self.session.commit()
        stats = report["stats"]

        self.assertEqual(stats["employees_created"], 3)  # Ёлкин найден по ключу ФИО
        self.assertEqual(self.session.query(User).filter(User.employee_name_norm == "елкин олег").count(), 1)
        # «Андрей Пиунов» и «Пиунов Андрей» — один ТМ; «Пипич» — существующий superadmin.
        self.assertEqual(report["tm_created"], ["Андрей Пиунов"])
        pipich = find_user_by_name(self.session, "Пипич Александр Владимирович")
        self.assertEqual(pipich.role, "superadmin")
        self.assertEqual(find_user_by_name(self.session, "Сидоров Сидор").tm_id, pipich.id)
        tm = find_user_by_name(self.session, "Андрей Пиунов")
        self.assertEqual(tm.role, "tm")
        self.assertIsNone(tm.phone)
        self.assertEqual(find_user_by_name(self.session, "Петров Пётр").tm_id, tm.id)

        ivanov = self.session.query(Requisite).filter(Requisite.employee_name == "Иванов Иван").one()
        self.assertEqual((ivanov.card_number, ivanov.card_phone, ivanov.card_expiry, ivanov.bank_name),
                         (VALID_CARD, "79111234567", "11/35", "Сбербанк"))
        self.assertTrue(is_payable(ivanov))

        petrov = self.session.query(Requisite).filter(Requisite.employee_name == "Петров Пётр").one()
        self.assertIsNone(petrov.card_number)  # 8 цифр — не сохранена
        self.assertEqual((petrov.is_third_party, petrov.recipient_name, petrov.bank_name),
                         (True, "Петрова Анна", "Т-Банк"))
        self.assertEqual(len(report["problems"]), 1)

        sidorov = self.session.query(Requisite).filter(Requisite.employee_name == "Сидоров Сидор").one()
        self.assertEqual(sidorov.payout_method, "cash")
        self.assertIsNone(sidorov.card_number)
        self.assertEqual(report["unknown_banks"]["НеизвестныйБанк"], 1)

    def test_second_run_changes_nothing(self):
        rows = read_rows(self.path)
        import_rows(self.session, rows, apply=True)
        self.session.commit()
        report = import_rows(self.session, rows, apply=True)
        self.assertEqual(report["stats"]["employees_created"], 0)
        self.assertEqual(report["stats"]["requisites_created"], 0)
        self.assertEqual(report["stats"]["requisites_updated"], 0)
        self.assertEqual(report["tm_created"], [])


if __name__ == "__main__":
    unittest.main()

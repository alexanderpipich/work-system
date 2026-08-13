"""ИНН/счёт/БИК не должны портиться ни на входе, ни на выгрузке в реестр."""

import os
import unittest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from io import BytesIO

from openpyxl import Workbook, load_workbook
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import PayrollRunItem, Requisite, User
from routers.payroll_runs import _build_payroll_run_workbook
from routers.requisites import _clean_identifiers
from utils import is_valid_requisite, requisite_issues

# Реальные значения из разбора порчи реестра: у Ивановой в базе всё целое,
# у тестового Хисрова — уже испорчено ручным вводом.
IVANOVA = ("471605460681", "40817810055192444131", "044030653")
HISROV = ("780000000000.0", "4e+19", "40000013.0")


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


class ValidatorTests(unittest.TestCase):
    """Единый критерий годности — общий с экраном невалидных реквизитов (002)."""

    def test_correct_requisites_pass(self):
        self.assertTrue(is_valid_requisite(*IVANOVA))
        self.assertEqual(requisite_issues(*IVANOVA), [])

    def test_inn_of_legal_entity_is_ten_digits(self):
        self.assertTrue(is_valid_requisite("7710140679", IVANOVA[1], IVANOVA[2]))

    def test_lengths_are_checked(self):
        self.assertIn("Номер счёта: 15 цифр, ожидалось 20",
                      requisite_issues(IVANOVA[0], "408178100551924", IVANOVA[2]))
        self.assertIn("БИК: 8 цифр, ожидалось 9",
                      requisite_issues(IVANOVA[0], IVANOVA[1], "04403065"))

    def test_non_digits_rejected(self):
        self.assertFalse(is_valid_requisite("47160546068X", IVANOVA[1], IVANOVA[2]))

    def test_empty_reported(self):
        self.assertIn("БИК не заполнен", requisite_issues(IVANOVA[0], IVANOVA[1], ""))

    def test_scientific_notation_is_lost_data(self):
        issues = requisite_issues(IVANOVA[0], "4.08e+19", IVANOVA[2])
        self.assertTrue(any("утеряны" in i for i in issues), issues)

    def test_float_tail_is_recoverable_and_accepted(self):
        # "780000000000.0" — хвост от Excel, цифры целы; после нормализации годен.
        self.assertTrue(is_valid_requisite("780000000000.0", IVANOVA[1], IVANOVA[2]))

    def test_surrounding_spaces_tolerated(self):
        self.assertTrue(is_valid_requisite(*(" %s " % v for v in IVANOVA)))


class InputCleaningTests(unittest.TestCase):
    """Вход ручных форм: хвост отрезаем, заведомо утерянное не сохраняем."""

    def test_float_tail_stripped(self):
        values, refusal = _clean_identifiers("780000000000.0", IVANOVA[1], "044030653.0")
        self.assertIsNone(refusal)
        self.assertEqual(values[0], "780000000000")
        self.assertEqual(values[2], "044030653")

    def test_leading_zeros_survive(self):
        values, _ = _clean_identifiers(IVANOVA[0], IVANOVA[1], "044030653")
        self.assertEqual(values[2], "044030653")

    def test_scientific_notation_refused(self):
        _, refusal = _clean_identifiers(IVANOVA[0], "4.08e+19", IVANOVA[2])
        self.assertIsNotNone(refusal)
        self.assertIn("номер счёта", refusal)

    def test_partial_requisite_still_saves(self):
        # Реквизит бывает заполнен частично — блокировать сохранение нельзя.
        _, refusal = _clean_identifiers("", "", "")
        self.assertIsNone(refusal)


class OpenpyxlRoundTripTests(unittest.TestCase):
    """Строка-из-цифр обязана пережить запись и чтение без искажения.

    Ловит регресс, если openpyxl когда-нибудь вернёт угадывание типов: тогда
    20-значный счёт схлопнется во float и младшие цифры пропадут.
    """

    def test_digit_strings_survive_round_trip(self):
        workbook = Workbook()
        sheet = workbook.active
        values = ["40817810055192444131", "471605460681", "044030653", "00000000000000000001"]
        for index, value in enumerate(values, start=1):
            sheet.cell(index, 1, value)
        for cell in sheet["A"]:
            cell.number_format = "@"

        buffer = BytesIO()
        workbook.save(buffer)
        buffer.seek(0)
        reread = load_workbook(buffer).active

        for index, value in enumerate(values, start=1):
            with self.subTest(value=value):
                cell = reread.cell(index, 1)
                self.assertEqual(cell.value, value)
                self.assertEqual(cell.data_type, "s", "значение перестало быть текстом")


class RegistryExportTests(unittest.TestCase):
    """Реестр выплат обязан выдавать ровно то, что лежит в базе."""

    def setUp(self):
        self.session = _session()
        for name, (inn, account, bik) in (("Иванова Т.М.", IVANOVA), ("Хисров Х.", HISROV)):
            self.session.add(User(employee_name=name, phone="7999%s" % len(name),
                                  password_hash="x"))
            self.session.add(Requisite(employee_name=name, inn=inn, account_number=account,
                                       bik=bik, bank_name="Банк", is_active=True))
        self.session.commit()

    def _export(self):
        class Run:
            id = 1
            legal_entity = "ООО"
            period_start = period_end = None
            status = "draft"

        items = [PayrollRunItem(employee_name="Иванова Т.М.", total_amount=1000),
                 PayrollRunItem(employee_name="Хисров Х.", total_amount=2000)]
        return load_workbook(_build_payroll_run_workbook(self.session, Run(), items)).active

    def test_intact_requisites_export_intact(self):
        sheet = self._export()
        self.assertEqual(sheet.cell(3, 2).value, "Иванова Т.М.")
        self.assertEqual(sheet.cell(3, 4).value, IVANOVA[0])
        self.assertEqual(sheet.cell(3, 5).value, IVANOVA[1], "20-значный счёт исказился")
        self.assertEqual(sheet.cell(3, 6).value, IVANOVA[2])

    def test_identifier_cells_stay_text(self):
        sheet = self._export()
        for column in (4, 5, 6):
            with self.subTest(column=column):
                self.assertEqual(sheet.cell(3, column).data_type, "s")

    def test_no_scientific_notation_for_intact_data(self):
        sheet = self._export()
        self.assertNotIn("e+", str(sheet.cell(3, 5).value))
        self.assertFalse(str(sheet.cell(3, 4).value).endswith(".0"))


if __name__ == "__main__":
    unittest.main()

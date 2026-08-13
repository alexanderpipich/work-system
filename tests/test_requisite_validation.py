"""Единый критерий пригодности реквизитов (п.002).

Критерия было два, и они не пересекались: фиксация табеля смотрела только на
флаги, проверка формата — только на поля. Тесты фиксируют, что теперь оба
слоя учтены и что последствия у них РАЗНЫЕ.
"""

import os
import unittest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from models import Requisite
from requisite_validation import (BAD_FOR_BANK, BLOCKS_PAYROLL, blocks_payroll,
                                  is_payable, requisite_problems, split_by_validity)

GOOD = dict(inn="471605460681", account_number="40817810055192444131", bik="044030653")


def _req(name="Иванова Т.М.", active=True, verified=True, **fields):
    values = dict(GOOD)
    values.update(fields)
    return Requisite(employee_name=name, is_active=active, is_verified=verified, **values)


class PayrollLayerTests(unittest.TestCase):
    """Слой фиксации табеля — ровно то, что проверяет routers/payroll.py."""

    def test_inactive_blocks_payroll(self):
        problems = requisite_problems(_req(active=False))
        self.assertTrue(any(kind == BLOCKS_PAYROLL for kind, _ in problems))
        self.assertTrue(blocks_payroll(_req(active=False)))

    def test_unverified_blocks_payroll(self):
        self.assertTrue(blocks_payroll(_req(verified=False)))

    def test_good_requisite_does_not_block(self):
        self.assertFalse(blocks_payroll(_req()))
        self.assertTrue(is_payable(_req()))


class BankLayerTests(unittest.TestCase):
    """Слой формата: фиксацию пропустит, но в платёжку уйдёт мусор."""

    def test_empty_fields_are_bad_for_bank_but_do_not_block(self):
        # Это и есть дыра, ради которой критерии сведены: реквизит с пустым
        # ИНН и счётом проходит фиксацию и уходит в реестр пустыми ячейками.
        requisite = _req(inn=None, account_number="", bik=None)
        kinds = {kind for kind, _ in requisite_problems(requisite)}
        self.assertEqual(kinds, {BAD_FOR_BANK})
        self.assertFalse(blocks_payroll(requisite), "пустые поля не блокируют табель")
        self.assertFalse(is_payable(requisite), "но выплачивать по ним нельзя")

    def test_scientific_notation_is_bad_for_bank(self):
        requisite = _req(account_number="4.08e+19")
        self.assertTrue(any(kind == BAD_FOR_BANK for kind, _ in requisite_problems(requisite)))

    def test_wrong_length_is_bad_for_bank(self):
        self.assertFalse(is_payable(_req(bik="04403065")))


class BothLayersTests(unittest.TestCase):
    def test_problems_from_both_layers_are_reported_together(self):
        requisite = _req(verified=False, inn=None)
        kinds = {kind for kind, _ in requisite_problems(requisite)}
        self.assertEqual(kinds, {BLOCKS_PAYROLL, BAD_FOR_BANK})


class SplitTests(unittest.TestCase):
    def test_problematic_first_alphabetical_inside(self):
        rows = [
            _req("Яковлев Годный"),
            _req("Абрамов Годный"),
            _req("Пустой Пётр", inn=None, account_number="", bik=None),
            _req("Архивный", active=False),
        ]
        problematic, clean = split_by_validity(rows)
        self.assertEqual([r.employee_name for r in problematic], ["Архивный", "Пустой Пётр"])
        self.assertEqual([r.employee_name for r in clean], ["Абрамов Годный", "Яковлев Годный"])

    def test_empty_input(self):
        self.assertEqual(split_by_validity([]), ([], []))


if __name__ == "__main__":
    unittest.main()

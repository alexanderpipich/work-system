# -*- coding: utf-8 -*-
import os
import unittest
from datetime import date

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import Shift, TimebookEmployee, User
from routers.upload import (
    _extract_timebook_contacts,
    _resolve_col,
    _upsert_timebook_contacts,
)
from routers.users import pending_employees


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


class ResolveColTests(unittest.TestCase):
    def test_matches_by_header_even_when_shifted(self):
        # Телефон НЕ на индексе 15, а по заголовку — должен найтись по заголовку.
        df = pd.DataFrame({"Магазин": ["A"], "Номер телефона": [79990001122]})
        col = _resolve_col(df, ["номер телефона", "телефон"], 15)
        self.assertIsNotNone(col)
        self.assertEqual(col.iloc[0], 79990001122)

    def test_falls_back_to_index_when_no_header(self):
        df = pd.DataFrame([[f"v{i}" for i in range(17)]], columns=[f"c{i}" for i in range(17)])
        col = _resolve_col(df, ["телефон"], 15)
        self.assertEqual(col.iloc[0], "v15")


class ExtractContactsTests(unittest.TestCase):
    def test_header_priority(self):
        df = pd.DataFrame({
            "Магазин": ["A"],
            "ФИО сотрудника Исполнителя": ["Иванов И.И."],
            "Номер телефона": [79990001122],
            "ИНН сотрудника": ["500100200300"],
            "Табельный номер": ["42"],
        })
        contacts = _extract_timebook_contacts(df)
        self.assertIn("Иванов И.И.", contacts)
        rec = contacts["Иванов И.И."]
        self.assertEqual(rec["phone"], "79990001122")
        self.assertEqual(rec["inn"], "500100200300")
        self.assertEqual(rec["tab"], "42")

    def test_index_fallback(self):
        # 17 безымянных колонок: ФИО=13, табельный=14, телефон=15, ИНН=16.
        row = [None] * 17
        row[13] = "Петров П.П."
        row[14] = "77"
        row[15] = 79995556677
        row[16] = "111222333"
        df = pd.DataFrame([row], columns=[f"c{i}" for i in range(17)])
        contacts = _extract_timebook_contacts(df)
        self.assertIn("Петров П.П.", contacts)
        rec = contacts["Петров П.П."]
        self.assertEqual(rec["phone"], "79995556677")
        self.assertEqual(rec["inn"], "111222333")
        self.assertEqual(rec["tab"], "77")


class UpsertTests(unittest.TestCase):
    def test_insert_then_update_non_empty_only(self):
        s = _session()
        _upsert_timebook_contacts(s, {"Иванов И.И.": {"phone": "79990001122", "inn": "", "tab": "42"}})
        s.commit()
        row = s.query(TimebookEmployee).filter_by(employee_name="Иванов И.И.").one()
        self.assertEqual(row.phone, "79990001122")
        self.assertIsNone(row.inn)
        self.assertEqual(row.tab_number, "42")

        # Повторная загрузка: непустое обновляет, пустое НЕ затирает.
        _upsert_timebook_contacts(s, {"Иванов И.И.": {"phone": "", "inn": "500100", "tab": ""}})
        s.commit()
        row = s.query(TimebookEmployee).filter_by(employee_name="Иванов И.И.").one()
        self.assertEqual(row.phone, "79990001122")  # не затёрт
        self.assertEqual(row.inn, "500100")          # добавлен
        s.close()


class PendingEmployeesTests(unittest.TestCase):
    def test_lists_only_uncreated_with_staged_contacts(self):
        s = _session()
        # Смены двух сотрудников; для Петрова есть User. Даты разные (uniqueness).
        s.add(Shift(employee="Иванов И.И.", store="Лента-7", city="Москва", service="усл",
                    format="ГМ", shift_date=date(2026, 7, 1), hours=8, request_type="Основные заказы"))
        s.add(Shift(employee="Иванов И.И.", store="Лента-7", city="Москва", service="усл",
                    format="ГМ", shift_date=date(2026, 7, 2), hours=8, request_type="Основные заказы"))
        s.add(Shift(employee="Петров П.П.", store="Лента-3", city="Москва", service="усл",
                    format="ГМ", shift_date=date(2026, 7, 1), hours=8, request_type="Основные заказы"))
        s.add(User(phone="+70000000009", password_hash="x", employee_name="Петров П.П."))
        s.add(TimebookEmployee(employee_name="Иванов И.И.", phone="79990001122", inn="500100", tab_number="42"))
        s.commit()

        pending = pending_employees(s)
        names = [p["name"] for p in pending]
        self.assertIn("Иванов И.И.", names)
        self.assertNotIn("Петров П.П.", names)  # уже есть User

        ivan = next(p for p in pending if p["name"] == "Иванов И.И.")
        self.assertEqual(ivan["phone"], "79990001122")
        self.assertEqual(ivan["inn"], "500100")
        self.assertTrue(ivan["has_phone"])
        self.assertEqual(ivan["count"], 2)
        self.assertEqual(ivan["last_store"], "Лента-7")
        s.close()


if __name__ == "__main__":
    unittest.main()

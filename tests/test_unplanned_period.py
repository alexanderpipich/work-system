"""Рассылка «смена без плана»: редактируемый период (п.006) и переход по магазину (п.005)."""

import os
import unittest
from datetime import date, timedelta

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from routers.email_unplanned import _resolve_tk
from routers.upload import _is_editable_month, _previous_month
from time_helpers import editable_period_start, is_editable_month, previous_month


class EditableMonthTests(unittest.TestCase):
    """Текущий месяц правится всегда, прошлый — только до 7 числа включительно."""

    def test_current_month_is_always_editable(self):
        self.assertTrue(is_editable_month(date(2026, 8, 1), date(2026, 8, 14)))
        self.assertTrue(is_editable_month(date(2026, 8, 31), date(2026, 8, 1)))

    def test_previous_month_open_until_the_seventh(self):
        self.assertTrue(is_editable_month(date(2026, 7, 31), date(2026, 8, 5)))
        # Ровно 7 — ещё открыт, 8 — уже закрыт. Граница включительная.
        self.assertTrue(is_editable_month(date(2026, 7, 15), date(2026, 8, 7)))
        self.assertFalse(is_editable_month(date(2026, 7, 15), date(2026, 8, 8)))

    def test_older_months_are_never_editable(self):
        self.assertFalse(is_editable_month(date(2026, 6, 1), date(2026, 8, 5)))

    def test_year_rollover(self):
        self.assertEqual(previous_month(date(2026, 1, 9)), (12, 2025))
        self.assertTrue(is_editable_month(date(2025, 12, 20), date(2026, 1, 3)))
        self.assertFalse(is_editable_month(date(2025, 12, 20), date(2026, 1, 10)))


class EditablePeriodStartTests(unittest.TestCase):
    """Граница периода обязана совпадать с поштучной проверкой — иначе запрос
    в БД и фильтр в Python разойдутся, и смены будут «терятья» по-разному."""

    def test_start_agrees_with_is_editable_month(self):
        for today in (date(2026, 8, 1), date(2026, 8, 7), date(2026, 8, 8),
                      date(2026, 1, 3), date(2026, 1, 10), date(2026, 3, 31)):
            with self.subTest(today=today):
                start = editable_period_start(today)
                self.assertTrue(
                    is_editable_month(start, today),
                    "начало периода само обязано быть редактируемым",
                )
                self.assertFalse(
                    is_editable_month(start - timedelta(days=1), today),
                    "день перед началом периода уже должен быть закрыт",
                )

    def test_before_the_seventh_period_starts_in_previous_month(self):
        self.assertEqual(editable_period_start(date(2026, 8, 5)), date(2026, 7, 1))
        self.assertEqual(editable_period_start(date(2026, 1, 3)), date(2025, 12, 1))

    def test_after_the_seventh_period_starts_in_current_month(self):
        self.assertEqual(editable_period_start(date(2026, 8, 14)), date(2026, 8, 1))


class UploadStillUsesTheSameRuleTests(unittest.TestCase):
    """Правило вынесено в time_helpers — загрузчик обязан брать его оттуда,
    иначе две копии со временем разойдутся."""

    def test_upload_reuses_shared_helpers(self):
        self.assertIs(_is_editable_month, is_editable_month)
        self.assertIs(_previous_month, previous_month)


class StoreToTkTests(unittest.TestCase):
    """Клик по смене передаёт название магазина — роут достаёт из него номер ТК."""

    def test_tk_extracted_from_store_name(self):
        self.assertEqual(_resolve_tk("", "ТК-7 Мурино"), (7, "7"))
        self.assertEqual(_resolve_tk("", "1234 Лента"), (1234, "1234"))

    def test_explicit_tk_wins(self):
        # Форма на самой странице шлёт tk — её контракт не должен меняться.
        self.assertEqual(_resolve_tk("55", "ТК-7 Мурино"), (55, "55"))

    def test_unrecognized_store_gives_no_filter(self):
        # Лучше показать всё и сказать об этом, чем молча отфильтровать не то.
        self.assertEqual(_resolve_tk("", "Склад без номера"), (None, ""))

    def test_no_parameters_means_no_filter(self):
        self.assertEqual(_resolve_tk("", ""), (None, ""))


if __name__ == "__main__":
    unittest.main()

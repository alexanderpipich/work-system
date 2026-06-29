import os
import unittest
from datetime import date
from types import SimpleNamespace


os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from models import Rate
from utils import pick_rate


def make_rate(hourly_rate, service="service", format=None, city=None,
              store=None, employee_name=None, active_from=None, active_to=None):
    return Rate(
        service=service,
        format=format,
        city=city,
        store=store,
        employee_name=employee_name,
        hourly_rate=hourly_rate,
        active_from=active_from,
        active_to=active_to,
    )


def make_shift(service="service", format="ГМ", city="Санкт-Петербург",
               store="Store-1", employee="Employee", shift_date=date(2026, 6, 1)):
    return SimpleNamespace(
        service=service,
        format=format,
        city=city,
        store=store,
        employee=employee,
        shift_date=shift_date,
    )


class CityMatchingTests(unittest.TestCase):
    def test_city_must_match_when_set(self):
        rates = [
            make_rate(300, city="Санкт-Петербург", format="ГМ"),
            make_rate(250, city="Ленинградская область", format="ГМ"),
        ]
        shift = make_shift(city="Санкт-Петербург", format="ГМ")
        self.assertEqual(pick_rate(rates, shift).hourly_rate, 300)

    def test_empty_city_matches_any(self):
        rates = [make_rate(280, city=None, format="ГМ")]
        shift = make_shift(city="Москва", format="ГМ")
        self.assertEqual(pick_rate(rates, shift).hourly_rate, 280)

    def test_city_specific_beats_city_agnostic(self):
        rates = [
            make_rate(280, city=None, format="ГМ"),
            make_rate(300, city="Санкт-Петербург", format="ГМ"),
        ]
        shift = make_shift(city="Санкт-Петербург", format="ГМ")
        self.assertEqual(pick_rate(rates, shift).hourly_rate, 300)

    def test_no_match_when_city_differs_and_no_fallback(self):
        rates = [make_rate(300, city="Санкт-Петербург", format="ГМ")]
        shift = make_shift(city="Брянск", format="ГМ")
        self.assertIsNone(pick_rate(rates, shift))


class FormatHardConditionTests(unittest.TestCase):
    def test_format_must_match_across_layers(self):
        # ГМ и СМ стоят по-разному; смена ГМ не должна получить СМ-ставку
        rates = [
            make_rate(246, city="Санкт-Петербург", format="ГМ"),
            make_rate(267, city="Санкт-Петербург", format="СМ"),
        ]
        shift = make_shift(city="Санкт-Петербург", format="ГМ")
        self.assertEqual(pick_rate(rates, shift).hourly_rate, 246)

    def test_format_enforced_even_for_store_rate(self):
        # индивидуальная ставка по ТК с форматом СМ не применяется к смене ГМ
        rates = [
            make_rate(300, city="Санкт-Петербург", format="ГМ"),
            make_rate(999, city="Санкт-Петербург", format="СМ", store="Store-1"),
        ]
        shift = make_shift(city="Санкт-Петербург", format="ГМ", store="Store-1")
        self.assertEqual(pick_rate(rates, shift).hourly_rate, 300)


class LayerPriorityTests(unittest.TestCase):
    def test_employee_beats_store_beats_grid(self):
        rates = [
            make_rate(200, city="Санкт-Петербург", format="ГМ"),                       # слой 0
            make_rate(300, city="Санкт-Петербург", format="ГМ", store="Store-1"),       # слой 1
            make_rate(400, city="Санкт-Петербург", format="ГМ",
                      store="Store-1", employee_name="Employee"),                       # слой 2
        ]
        shift = make_shift(city="Санкт-Петербург", format="ГМ",
                           store="Store-1", employee="Employee")
        self.assertEqual(pick_rate(rates, shift).hourly_rate, 400)

    def test_store_beats_grid(self):
        rates = [
            make_rate(200, city="Санкт-Петербург", format="ГМ"),
            make_rate(300, city="Санкт-Петербург", format="ГМ", store="Store-1"),
        ]
        shift = make_shift(city="Санкт-Петербург", format="ГМ", store="Store-1")
        self.assertEqual(pick_rate(rates, shift).hourly_rate, 300)


if __name__ == "__main__":
    unittest.main()

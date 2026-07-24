import os
import unittest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from service_matrix import (
    build_service_matrix,
    normalize_service_base,
    parse_service_name,
    levenshtein,
)


class ParseServiceNameTests(unittest.TestCase):
    def test_with_level_prefix(self):
        self.assertEqual(parse_service_name("2ур_Услуги по выкладке"), (2, "Услуги по выкладке"))

    def test_without_prefix(self):
        self.assertEqual(parse_service_name("Вингараж Универсальные услуги"),
                         (None, "Вингараж Универсальные услуги"))

    def test_separator_variants(self):
        self.assertEqual(parse_service_name("2ур Услуги")[0], 2)
        self.assertEqual(parse_service_name("2 ур_Услуги")[0], 2)
        self.assertEqual(parse_service_name("3УР_Услуги")[0], 3)

    def test_does_not_false_match(self):
        # "ур" не как префикс уровня — не разбирать.
        self.assertEqual(parse_service_name("1урок_чтения"), (None, "1урок_чтения"))

    def test_empty(self):
        self.assertEqual(parse_service_name(""), (None, ""))
        self.assertEqual(parse_service_name(None), (None, ""))


class NormalizeBaseTests(unittest.TestCase):
    def test_separator_duplicate_collapses(self):
        a = normalize_service_base("Вингараж Универсальные услуги")
        b = normalize_service_base("Вингараж_Универсальные услуги")
        self.assertEqual(a, b)

    def test_case_and_yo(self):
        self.assertEqual(normalize_service_base("Заморозка Ё"), normalize_service_base("заморозка е"))


class LevenshteinTests(unittest.TestCase):
    def test_typo_distance(self):
        self.assertEqual(levenshtein("торговго", "торгового"), 1)
        self.assertTrue(1 <= levenshtein("обслуживаню", "обслуживанию") <= 2)


class BuildMatrixTests(unittest.TestCase):
    def test_groups_by_base_and_level(self):
        rates = [
            {"service": "2ур_Услуги по выкладке", "city": "Москва", "format": "ГМ",
             "store": None, "employee_name": None, "hourly_rate": 306},
            {"service": "3ур_Услуги по выкладке", "city": "Москва", "format": "ГМ",
             "store": None, "employee_name": None, "hourly_rate": 400},
        ]
        shifts = [{"service": "2ур_Услуги по выкладке"}]
        matrix = build_service_matrix(rates, shifts)

        self.assertEqual(len(matrix["rows"]), 1)
        row = matrix["rows"][0]
        self.assertEqual(row["cells"][2]["count"], 1)
        self.assertEqual(row["cells"][2]["min"], 306)
        self.assertEqual(row["cells"][3]["min"], 400)
        self.assertEqual(row["cells"][1]["count"], 0)

    def test_spelling_duplicate_flagged_and_grouped(self):
        rates = [
            {"service": "Вингараж Универсальные услуги", "city": "Москва", "format": "ГМ",
             "store": None, "employee_name": None, "hourly_rate": 250},
            {"service": "Вингараж_Универсальные услуги", "city": "Москва", "format": "ГМ",
             "store": None, "employee_name": None, "hourly_rate": 250},
        ]
        matrix = build_service_matrix(rates, [])
        self.assertEqual(len(matrix["rows"]), 1)
        row = matrix["rows"][0]
        self.assertTrue(row["is_duplicate"])
        self.assertEqual(len(row["variants"]), 2)
        self.assertEqual(matrix["counters"]["duplicates"], 1)

    def test_shift_without_rate_counted_and_marked(self):
        rates = [
            {"service": "2ур_Выкладка", "city": "Москва", "format": "ГМ",
             "store": None, "employee_name": None, "hourly_rate": 300},
        ]
        # Смена с ДРУГИМ написанием — точного Rate нет → подбор даст 0.
        shifts = [{"service": "2ур_Выкладка"}, {"service": "2ур_Выкладка_особая"}]
        matrix = build_service_matrix(rates, shifts)

        self.assertEqual(matrix["counters"]["no_rate_services"], 1)
        self.assertIn("2ур_Выкладка_особая", matrix["no_rate_services"])
        # Строка «Выкладка особая» имеет клетку-сироту (есть смена, нет тарифа).
        orphan_rows = [r for r in matrix["rows"] if r["has_no_rate"]]
        self.assertEqual(len(orphan_rows), 1)

    def test_rate_without_shift_counted(self):
        rates = [
            {"service": "2ур_Старьё", "city": "Москва", "format": "ГМ",
             "store": None, "employee_name": None, "hourly_rate": 300},
        ]
        matrix = build_service_matrix(rates, [])
        self.assertEqual(matrix["counters"]["rate_no_shift_services"], 1)
        self.assertIn("2ур_Старьё", matrix["rate_no_shift_services"])

    def test_multi_rate_cell_range(self):
        rates = [
            {"service": "1ур_Услуга", "city": "Москва", "format": "ГМ",
             "store": None, "employee_name": None, "hourly_rate": 246},
            {"service": "1ур_Услуга", "city": "Казань", "format": "СМ",
             "store": None, "employee_name": None, "hourly_rate": 408},
        ]
        matrix = build_service_matrix(rates, [])
        cell = matrix["rows"][0]["cells"][1]
        self.assertEqual(cell["count"], 2)
        self.assertEqual(cell["min"], 246)
        self.assertEqual(cell["max"], 408)


if __name__ == "__main__":
    unittest.main()

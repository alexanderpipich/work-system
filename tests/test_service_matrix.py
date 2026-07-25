import os
import unittest
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from service_matrix import (
    build_service_matrix,
    normalize_service_base,
    parse_service_name,
    levenshtein,
)


def _svc(sid, name, aliases=None, is_active=True):
    return SimpleNamespace(id=sid, name=name, aliases=aliases, is_active=is_active)


def _rate(service_id, level, hourly_rate, city="ЛО", fmt="ГМ", store=None, employee_name=None):
    return {"service_id": service_id, "level": level, "city": city, "format": fmt,
            "store": store, "employee_name": employee_name, "hourly_rate": hourly_rate}


class KeyInvariantCellTests(unittest.TestCase):
    """Регион/формат — измерения сетки; дубль КЛЮЧА (та же регион+формат дважды) — ошибка."""

    def test_two_regions_not_key_error(self):
        svc = _svc(1, "Табакошоп")
        rates = [_rate(1, 2, 240, city="ЛО"), _rate(1, 2, 240, city="СПб")]
        row = build_service_matrix([svc], rates, [])["rows"][0]
        cell = row["cells"][2]
        self.assertEqual(cell["count"], 2)
        self.assertEqual(cell["region_format_count"], 2)
        self.assertFalse(cell["has_real_dup"])
        self.assertFalse(row["has_key_error"])

    def test_same_region_format_is_key_error(self):
        svc = _svc(1, "Табакошоп")
        rates = [_rate(1, 2, 240, city="ЛО"), _rate(1, 2, 250, city="ЛО")]
        matrix = build_service_matrix([svc], rates, [])
        cell = matrix["rows"][0]["cells"][2]
        self.assertEqual(cell["region_format_count"], 1)
        self.assertTrue(cell["has_real_dup"])
        self.assertTrue(matrix["rows"][0]["has_key_error"])
        self.assertEqual(matrix["counters"]["key_errors"], 1)

    def test_two_formats_same_region_not_error(self):
        svc = _svc(1, "Табакошоп")
        rates = [_rate(1, 2, 240, fmt="ГМ"), _rate(1, 2, 260, fmt="СМ")]
        cell = build_service_matrix([svc], rates, [])["rows"][0]["cells"][2]
        self.assertEqual(cell["region_format_count"], 2)
        self.assertFalse(cell["has_real_dup"])


class BuildFromModelTests(unittest.TestCase):
    def test_rows_from_service_records(self):
        services = [_svc(1, "Уборка"), _svc(2, "Продавец")]
        rates = [_rate(1, 2, 306), _rate(1, 3, 400)]
        matrix = build_service_matrix(services, rates, [])
        by = {r["name"]: r for r in matrix["rows"]}
        self.assertEqual(set(by), {"Уборка", "Продавец"})
        self.assertEqual(by["Уборка"]["cells"][2]["min"], 306)
        self.assertEqual(by["Уборка"]["cells"][3]["min"], 400)
        self.assertEqual(by["Уборка"]["cells"][1]["count"], 0)

    def test_level_from_field_not_text(self):
        # Уровень берётся из rate.level (этап 1/3), не из текста.
        svc = _svc(1, "Услуга")
        rates = [_rate(1, 1, 246, city="ЛО", fmt="ГМ"), _rate(1, 1, 408, city="Казань", fmt="СМ")]
        cell = build_service_matrix([svc], rates, [])["rows"][0]["cells"][1]
        self.assertEqual(cell["count"], 2)
        self.assertEqual(cell["min"], 246)
        self.assertEqual(cell["max"], 408)

    def test_no_tariff_service(self):
        services = [_svc(1, "Уборка"), _svc(2, "БезТарифа")]
        rates = [_rate(1, 2, 300)]
        matrix = build_service_matrix(services, rates, [])
        self.assertIn("БезТарифа", matrix["no_tariff_services"])
        self.assertNotIn("Уборка", matrix["no_tariff_services"])
        self.assertEqual(matrix["counters"]["no_tariff_services"], 1)
        by = {r["name"]: r for r in matrix["rows"]}
        self.assertTrue(by["Уборка"]["in_rates"])
        self.assertFalse(by["БезТарифа"]["in_rates"])

    def test_unmatched_shift_service(self):
        services = [_svc(1, "Уборка", aliases="Клининг")]
        rates = [_rate(1, 2, 300)]
        shifts = ["2ур_Уборка", "2ур_Клининг", "5ур_НетТакой"]
        matrix = build_service_matrix(services, rates, shifts)
        # Уборка и её алиас Клининг — сматчены; НетТакой — нет.
        self.assertEqual(matrix["unmatched_shift_services"], ["5ур_НетТакой"])
        self.assertEqual(matrix["counters"]["unmatched_shift_services"], 1)


class BaseGridFilterTests(unittest.TestCase):
    """В клетки — только базовая сетка (store и employee_name пусты)."""

    def test_store_rate_excluded_from_cells(self):
        svc = _svc(1, "Услуга")
        rates = [_rate(1, 2, 350, store="Лента-1")]
        matrix = build_service_matrix([svc], rates, [])
        row = matrix["rows"][0]
        self.assertEqual(row["cells"][2]["count"], 0)
        self.assertEqual(row["individual_count"], 1)
        self.assertEqual(matrix["counters"]["individual_rates"], 1)

    def test_employee_rate_excluded_from_cells(self):
        svc = _svc(1, "Услуга")
        rates = [_rate(1, 2, 500, employee_name="Иванов")]
        row = build_service_matrix([svc], rates, [])["rows"][0]
        self.assertEqual(row["cells"][2]["count"], 0)
        self.assertEqual(row["individual_count"], 1)

    def test_format_filled_still_base(self):
        svc = _svc(1, "Услуга")
        rates = [_rate(1, 2, 280, fmt="СМ")]
        matrix = build_service_matrix([svc], rates, [])
        cell = matrix["rows"][0]["cells"][2]
        self.assertEqual(cell["count"], 1)
        self.assertEqual(cell["min"], 280)
        self.assertEqual(matrix["counters"]["individual_rates"], 0)

    def test_individual_counter_sums_layers_1_and_2(self):
        svc = _svc(1, "Услуга")
        rates = [
            _rate(1, 2, 300),                                   # базовая
            _rate(1, 2, 300, store="Лента-1"),                 # слой 1
            _rate(1, 2, 300, employee_name="Иванов"),          # слой 2
            _rate(1, 2, 300, store="Лента-2", employee_name="Петров"),
        ]
        matrix = build_service_matrix([svc], rates, [])
        self.assertEqual(matrix["counters"]["individual_rates"], 3)
        self.assertEqual(matrix["rows"][0]["cells"][2]["count"], 1)


class SpellingDuplicateTests(unittest.TestCase):
    def test_spelling_duplicate_grouped(self):
        # Разные Service с одним base_key — дубль написания (для слияния).
        services = [_svc(1, "Вингараж Универсальные услуги"),
                    _svc(2, "Вингараж_Универсальные услуги")]
        rates = [_rate(1, None, 100)]  # у первого есть тариф
        matrix = build_service_matrix(services, rates, [])
        rows = matrix["rows"]
        self.assertTrue(all(r["is_duplicate"] for r in rows))
        self.assertEqual(matrix["counters"]["duplicates"], 1)
        group = rows[0]["dup_group"]
        self.assertEqual(len(group), 2)
        in_rates = {g["name"]: g["in_rates"] for g in group}
        self.assertTrue(in_rates["Вингараж Универсальные услуги"])
        self.assertFalse(in_rates["Вингараж_Универсальные услуги"])


class SimilarNamesTests(unittest.TestCase):
    def test_ne_prefix_not_flagged_as_typo(self):
        services = [_svc(1, "Квалифицированные услуги в столовой"),
                    _svc(2, "Неквалифицированные услуги в столовой")]
        matrix = build_service_matrix(services, [], [])
        for row in matrix["rows"]:
            self.assertEqual(row["similar_to"], [])
        self.assertEqual(matrix["counters"]["typos"], 0)

    def test_real_typo_flagged(self):
        services = [_svc(1, "торговго зала"), _svc(2, "торгового зала")]
        matrix = build_service_matrix(services, [], [])
        self.assertEqual(matrix["counters"]["typos"], 2)
        self.assertTrue(all(r["similar_to"] for r in matrix["rows"]))


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


if __name__ == "__main__":
    unittest.main()

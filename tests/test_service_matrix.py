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


def _r(service, hourly_rate, city="ЛО", fmt="ГМ", store=None, employee_name=None):
    return {"service": service, "city": city, "format": fmt,
            "store": store, "employee_name": employee_name, "hourly_rate": hourly_rate}


class RegionCellTests(unittest.TestCase):
    """Фикс: регион/формат — измерения сетки, а не мнимый дубль."""

    def test_same_service_two_regions_not_duplicate(self):
        # Табакошоп: ЛО 240 + СПб 240 — две легитимные базовые ставки, НЕ дубль.
        rates = [_r("2ур_Табакошоп", 240, city="ЛО"), _r("2ур_Табакошоп", 240, city="СПб")]
        matrix = build_service_matrix(rates, [])
        row = matrix["rows"][0]
        cell = row["cells"][2]
        self.assertEqual(cell["count"], 2)
        self.assertEqual(cell["region_format_count"], 2)  # две разные (регион,формат)
        self.assertFalse(cell["has_real_dup"])            # НЕ реальный дубль
        self.assertFalse(row["is_duplicate"])             # НЕ дубль написания

    def test_real_duplicate_same_region_format(self):
        # Одна и та же (услуга, уровень, регион, формат) дважды → реальный дубль.
        rates = [_r("2ур_Табакошоп", 240, city="ЛО"), _r("2ур_Табакошоп", 250, city="ЛО")]
        matrix = build_service_matrix(rates, [])
        cell = matrix["rows"][0]["cells"][2]
        self.assertEqual(cell["count"], 2)
        self.assertEqual(cell["region_format_count"], 1)
        self.assertTrue(cell["has_real_dup"])

    def test_two_formats_same_region_not_dup(self):
        # ГМ + СМ в одном регионе — тоже измерение, не дубль.
        rates = [_r("2ур_Табакошоп", 240, city="ЛО", fmt="ГМ"),
                 _r("2ур_Табакошоп", 260, city="ЛО", fmt="СМ")]
        cell = build_service_matrix(rates, [])["rows"][0]["cells"][2]
        self.assertEqual(cell["region_format_count"], 2)
        self.assertFalse(cell["has_real_dup"])

    def test_spelling_duplicate_still_flagged_region_independent(self):
        # Вингараж пробел/подчёрк в одном регионе → настоящий дубль написания.
        rates = [_r("Вингараж Универсальные услуги", 100, city="ЛО"),
                 _r("Вингараж_Универсальные услуги", 100, city="ЛО")]
        row = build_service_matrix(rates, [])["rows"][0]
        self.assertTrue(row["is_duplicate"])
        self.assertEqual(len(row["variants"]), 2)


class SimilarNamesTests(unittest.TestCase):
    """Приставка «не» — разные услуги (квалиф./неквалиф.), НЕ опечатка."""

    def test_ne_prefix_not_flagged_as_typo(self):
        rates = [
            _r("2ур_Квалифицированные услуги в столовой", 300),
            _r("2ур_Неквалифицированные услуги в столовой", 250),
        ]
        matrix = build_service_matrix(rates, [])
        by = {r["base_display"]: r for r in matrix["rows"]}
        self.assertEqual(by["Квалифицированные услуги в столовой"]["similar_to"], [])
        self.assertEqual(by["Неквалифицированные услуги в столовой"]["similar_to"], [])
        self.assertEqual(matrix["counters"]["typos"], 0)

    def test_real_typo_still_flagged(self):
        # Настоящая опечатка (расстояние 1, без префикса «не») — помечается.
        rates = [_r("2ур_торговго зала", 300), _r("2ур_торгового зала", 300)]
        matrix = build_service_matrix(rates, [])
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


class BaseGridFilterTests(unittest.TestCase):
    """Матрица показывает ТОЛЬКО базовую сетку (store и employee_name пусты)."""

    def _base(self, **kw):
        row = {"service": "2ур_Услуга", "city": "Москва", "format": "ГМ",
               "store": None, "employee_name": None, "hourly_rate": 300}
        row.update(kw)
        return row

    def test_store_rate_excluded_from_cells(self):
        rates = [self._base(store="Лента-1", hourly_rate=350)]
        matrix = build_service_matrix(rates, [])
        row = matrix["rows"][0]
        self.assertEqual(row["cells"][2]["count"], 0)  # в клетку не попала
        self.assertEqual(row["individual_count"], 1)
        self.assertEqual(matrix["counters"]["individual_rates"], 1)

    def test_employee_rate_excluded_from_cells(self):
        rates = [self._base(employee_name="Иванов", hourly_rate=500)]
        matrix = build_service_matrix(rates, [])
        row = matrix["rows"][0]
        self.assertEqual(row["cells"][2]["count"], 0)
        self.assertEqual(row["individual_count"], 1)

    def test_format_filled_still_base(self):
        # Заполненный format при пустых store/employee — это БАЗОВАЯ ставка.
        rates = [self._base(format="СМ", hourly_rate=280)]
        matrix = build_service_matrix(rates, [])
        cell = matrix["rows"][0]["cells"][2]
        self.assertEqual(cell["count"], 1)
        self.assertEqual(cell["min"], 280)
        self.assertEqual(matrix["counters"]["individual_rates"], 0)

    def test_individual_counter_sums_layers_1_and_2(self):
        rates = [
            self._base(),                              # базовая
            self._base(store="Лента-1"),               # слой 1
            self._base(employee_name="Иванов"),        # слой 2
            self._base(store="Лента-2", employee_name="Петров"),  # слой 2
        ]
        matrix = build_service_matrix(rates, [])
        self.assertEqual(matrix["counters"]["individual_rates"], 3)
        self.assertEqual(matrix["rows"][0]["cells"][2]["count"], 1)  # только базовая в клетке

    def test_rate_no_shift_uses_base_only(self):
        # Индивидуальная ставка НЕ должна раздувать «тарифы без смен».
        rates = [
            {"service": "2ур_БазаБезСмен", "city": "Москва", "format": "ГМ",
             "store": None, "employee_name": None, "hourly_rate": 300},
            {"service": "2ур_ИндивБезСмен", "city": "Москва", "format": "ГМ",
             "store": "Лента-1", "employee_name": None, "hourly_rate": 350},
        ]
        matrix = build_service_matrix(rates, [])
        self.assertEqual(matrix["counters"]["rate_no_shift_services"], 1)
        self.assertEqual(matrix["rate_no_shift_services"], ["2ур_БазаБезСмен"])


if __name__ == "__main__":
    unittest.main()

import io
import os
import unittest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

import pandas as pd

from utils import is_scientific_notation, normalize_digits


class NormalizeDigitsTests(unittest.TestCase):
    def test_strips_float_tail(self):
        # ИНН/БИК, прочитанные как float, теряют .0 — вернуть без хвоста.
        self.assertEqual(normalize_digits("780000000000.0"), "780000000000")
        self.assertEqual(normalize_digits("40000002.0"), "40000002")

    def test_keeps_leading_zeros(self):
        # БИК бывает с ведущим нулём — не терять.
        self.assertEqual(normalize_digits("040000002"), "040000002")
        self.assertEqual(normalize_digits("04452387"), "04452387")

    def test_keeps_exact_20_digit_account(self):
        account = "40817810099910004312"
        self.assertEqual(normalize_digits(account), account)
        self.assertEqual(len(normalize_digits(account)), 20)

    def test_scientific_notation_returned_as_is(self):
        # Данные утеряны — не пытаемся восстановить, возвращаем как есть.
        self.assertEqual(
            normalize_digits("4.0820810900009206e+19"),
            "4.0820810900009206e+19",
        )

    def test_none_and_nan_become_empty(self):
        self.assertEqual(normalize_digits(None), "")
        self.assertEqual(normalize_digits(float("nan")), "")
        self.assertEqual(normalize_digits(""), "")
        self.assertEqual(normalize_digits("   "), "")

    def test_plain_string_trimmed(self):
        self.assertEqual(normalize_digits("  123456  "), "123456")


class IsScientificNotationTests(unittest.TestCase):
    def test_detects_scientific(self):
        self.assertTrue(is_scientific_notation("4.0820810900009206e+19"))
        self.assertTrue(is_scientific_notation("4.08E+19"))
        self.assertTrue(is_scientific_notation("1e10"))

    def test_plain_numbers_not_flagged(self):
        self.assertFalse(is_scientific_notation("40817810099910004312"))
        self.assertFalse(is_scientific_notation("780000000000.0"))
        self.assertFalse(is_scientific_notation("040000002"))

    def test_none_nan_empty_not_flagged(self):
        self.assertFalse(is_scientific_notation(None))
        self.assertFalse(is_scientific_notation(float("nan")))
        self.assertFalse(is_scientific_notation(""))


class ExcelReadPrecisionTests(unittest.TestCase):
    """Точность на реальном чтении Excel: dtype=str сохраняет длинные номера."""

    def _read(self, frame):
        buffer = io.BytesIO()
        frame.to_excel(buffer, index=False)
        buffer.seek(0)
        return pd.read_excel(buffer, dtype=str)

    def test_dtype_str_preserves_account_and_leading_zeros(self):
        # Номер счёта хранится в файле как ТЕКСТ (как должно быть при верном вводе).
        frame = pd.DataFrame(
            {
                "inn": ["780000000000"],
                "account_number": ["40817810099910004312"],
                "bik": ["040000002"],
            }
        )
        df = self._read(frame)
        self.assertEqual(normalize_digits(df.iloc[0]["account_number"]), "40817810099910004312")
        self.assertEqual(normalize_digits(df.iloc[0]["inn"]), "780000000000")
        self.assertEqual(normalize_digits(df.iloc[0]["bik"]), "040000002")

    def test_numeric_cell_gets_float_tail_stripped(self):
        # Если ячейка хранится числом — dtype=str даёт "…​.0", normalize_digits срезает.
        frame = pd.DataFrame({"inn": [780000000000], "bik": [40000002]})
        df = self._read(frame)
        self.assertEqual(normalize_digits(df.iloc[0]["inn"]), "780000000000")
        self.assertEqual(normalize_digits(df.iloc[0]["bik"]), "40000002")

    def test_boolean_columns_still_parse_as_strings(self):
        # is_active/is_verified парсятся через truthy/falsy от строки — dtype=str не мешает.
        truthy = ["да", "yes", "true", "1", "on"]
        falsy = ["нет", "no", "false", "0", "off"]
        frame = pd.DataFrame(
            {"is_active": ["Да", "нет", 1, 0], "is_verified": ["true", "false", "Да", "Нет"]}
        )
        df = self._read(frame)
        actives = [str(v).strip().lower() for v in df["is_active"]]
        self.assertEqual([a not in falsy for a in actives], [True, False, True, False])
        verifieds = [str(v).strip().lower() for v in df["is_verified"]]
        self.assertEqual([v in truthy for v in verifieds], [True, False, True, False])


class ThirdPartyDerivationTests(unittest.TestCase):
    """is_third_party выводится из recipient_name, а не из колонки."""

    @staticmethod
    def _derive(recipient_name):
        return bool((recipient_name or "").strip())

    def test_filled_recipient_is_third_party(self):
        self.assertTrue(self._derive("Иванова Мария"))

    def test_empty_recipient_not_third_party(self):
        self.assertFalse(self._derive(""))
        self.assertFalse(self._derive("   "))
        self.assertFalse(self._derive(None))


if __name__ == "__main__":
    unittest.main()

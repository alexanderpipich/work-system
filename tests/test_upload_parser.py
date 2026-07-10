import io
import os
import unittest
from datetime import timedelta

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

import pandas as pd

from routers.upload import (
    TIMEBOOK_HEADER_ROW,
    _extract_timebook_contacts,
    _normalize_upload_dataframe,
    _resolve_col,
)


NEW_HEADERS = [
    "Магазин", "Номер ТК", "Формат", "Дивизион", "Город", "Секции", "Типовые секции",
    "Дата", "Поставщик (Исполнитель)", "Тип заявки", "Статус заявки у заказчика",
    "Статус заявки у подрядчика", "Инициатор назначения", "Услуга",
    "ФИО сотрудника Исполнителя", "Табельный номер сотрудника", "Номер телефона",
    "ИНН сотрудника", "Отработано, сотрудники", "Время начала смены (заказ)",
    "Время окончания смены (заказ)", "Время прихода (факт)", "Время ухода (факт)",
    "Время нахождения на объекте, часы", "Обед (перерыв по плану), часы",
    "Обед (перерыв по факту), часы", "ПланФакт минус неоплач. обед, чч:мм",
    "ПланФакт минус неоплач. обед (в числовом формате), часы",
]

# Старый формат: на одну колонку меньше до «Услуги» → услуга 12, ФИО 13, часы 26.
OLD_HEADERS = [
    "Магазин", "Номер ТК", "Формат", "Дивизион", "Город", "Секции", "Типовые секции",
    "Дата", "Поставщик (Исполнитель)", "Тип заявки", "Статус заявки у заказчика",
    "Статус заявки у подрядчика", "Услуга", "ФИО сотрудника Исполнителя",
    "Табельный номер сотрудника", "Номер телефона", "ИНН сотрудника",
    "Отработано, сотрудники", "Время начала смены (заказ)", "Время окончания смены (заказ)",
    "Время прихода (факт)", "Время ухода (факт)", "Время нахождения на объекте, часы",
    "Обед (перерыв по плану), часы", "Обед (перерыв по факту), часы",
    "ПланФакт минус неоплач. обед, чч:мм",
    "ПланФакт минус неоплач. обед (в числовом формате), часы",
]


def _new_row():
    return {
        "Магазин": "Лента-263 (г. Кингисепп)", "Номер ТК": 263, "Формат": "ГМ",
        "Дивизион": "СЗ", "Город": "Санкт-Петербург", "Секции": "-", "Типовые секции": "-",
        "Дата": "01.07.2026", "Поставщик (Исполнитель)": "ООО Поставщик",
        "Тип заявки": "Основные заказы", "Статус заявки у заказчика": "выполнена",
        "Статус заявки у подрядчика": "выполнена", "Инициатор назначения": "Петров П.П.",
        "Услуга": "2ур_Услуги по разработке планограмм",
        "ФИО сотрудника Исполнителя": "Мирзокулова Рушана Шухрат Кизи",
        "Табельный номер сотрудника": "12345", "Номер телефона": "79990050445",
        "ИНН сотрудника": " 780115292688", "Отработано, сотрудники": 1,
        "Время начала смены (заказ)": "09:00", "Время окончания смены (заказ)": "18:00",
        "Время прихода (факт)": "09:00", "Время ухода (факт)": "18:00",
        "Время нахождения на объекте, часы": 9, "Обед (перерыв по плану), часы": 1,
        "Обед (перерыв по факту), часы": 1,
        "ПланФакт минус неоплач. обед, чч:мм": timedelta(seconds=28800),
        "ПланФакт минус неоплач. обед (в числовом формате), часы": 8,
    }


def _new_df(rows=1):
    data = []
    for i in range(rows):
        row = _new_row()
        row["Дата"] = f"0{i + 1}.07.2026"
        data.append(row)
    return pd.DataFrame(data, columns=NEW_HEADERS)


class NewFormatParsingTests(unittest.TestCase):
    """Новый вид отчёта: добавленные колонки сдвинули всё — спасает привязка к заголовкам."""

    def test_fields_land_in_right_columns(self):
        rows, skipped, contacts = _normalize_upload_dataframe(_new_df(2))
        self.assertEqual(len(rows), 2)
        self.assertEqual(skipped, 0)
        row = rows.iloc[0]
        self.assertEqual(row["service"], "2ур_Услуги по разработке планограмм")
        self.assertEqual(row["employee"], "Мирзокулова Рушана Шухрат Кизи")
        self.assertEqual(row["store"], "Лента-263 (г. Кингисепп)")
        self.assertEqual(row["city"], "Санкт-Петербург")
        self.assertEqual(row["request_type"], "Основные заказы")

    def test_hours_taken_from_numeric_column_not_timedelta(self):
        rows, _skipped, _contacts = _normalize_upload_dataframe(_new_df(1))
        self.assertEqual(float(rows.iloc[0]["hours"]), 8.0)
        self.assertTrue(pd.api.types.is_numeric_dtype(rows["hours"]))

    def test_contacts_extracted(self):
        _rows, _skipped, contacts = _normalize_upload_dataframe(_new_df(1))
        rec = contacts["Мирзокулова Рушана Шухрат Кизи"]
        self.assertEqual(rec["phone"], "79990050445")
        self.assertEqual(rec["inn"], "780115292688")
        self.assertEqual(rec["tab"], "12345")

    def test_header_row_is_second_row_of_file(self):
        """Первая строка файла — агрегаты «Итого:», заголовки во второй."""
        buffer = io.BytesIO()
        frame = _new_df(1)
        total = ["Итого:"] + [""] * (len(NEW_HEADERS) - 1)
        with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
            pd.DataFrame([total, NEW_HEADERS] + frame.values.tolist()).to_excel(
                writer, index=False, header=False
            )
        buffer.seek(0)
        df = pd.read_excel(buffer, header=TIMEBOOK_HEADER_ROW)
        self.assertIn("ФИО сотрудника Исполнителя", df.columns)
        rows, _skipped, _contacts = _normalize_upload_dataframe(df)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows.iloc[0]["service"], "2ур_Услуги по разработке планограмм")


class OldFormatParsingTests(unittest.TestCase):
    """Старый формат: те же заголовки на других позициях — находятся по имени."""

    def test_old_layout_still_parses(self):
        row = _new_row()
        row.pop("Инициатор назначения")
        df = pd.DataFrame([row], columns=OLD_HEADERS)
        rows, _skipped, contacts = _normalize_upload_dataframe(df)
        self.assertEqual(rows.iloc[0]["service"], "2ур_Услуги по разработке планограмм")
        self.assertEqual(rows.iloc[0]["employee"], "Мирзокулова Рушана Шухрат Кизи")
        self.assertEqual(float(rows.iloc[0]["hours"]), 8.0)
        self.assertEqual(contacts["Мирзокулова Рушана Шухрат Кизи"]["inn"], "780115292688")

    def test_extra_columns_prepended_do_not_shift_result(self):
        df = _new_df(1)
        df.insert(0, "Новая колонка заказчика", "мусор")
        rows, _skipped, _contacts = _normalize_upload_dataframe(df)
        self.assertEqual(rows.iloc[0]["store"], "Лента-263 (г. Кингисепп)")
        self.assertEqual(rows.iloc[0]["service"], "2ур_Услуги по разработке планограмм")
        self.assertEqual(float(rows.iloc[0]["hours"]), 8.0)


class ResolveColTests(unittest.TestCase):
    def test_exact_header_wins_over_substring(self):
        """«Формат» не должен матчиться в «…(в числовом формате), часы»."""
        df = pd.DataFrame({
            "ПланФакт минус неоплач. обед (в числовом формате), часы": [8],
            "Формат": ["ГМ"],
        })
        series, by_header = _resolve_col(df, ["формат"], 99)
        self.assertTrue(by_header)
        self.assertEqual(series.iloc[0], "ГМ")

    def test_falls_back_to_index_when_header_absent(self):
        df = pd.DataFrame({0: ["a"], 1: ["b"]})
        series, by_header = _resolve_col(df, ["нет такой"], 1)
        self.assertFalse(by_header)
        self.assertEqual(series.iloc[0], "b")

    def test_returns_none_when_index_out_of_range(self):
        df = pd.DataFrame({"Магазин": ["a"]})
        series, by_header = _resolve_col(df, ["нет такой"], 5)
        self.assertIsNone(series)
        self.assertFalse(by_header)


class BadFileTests(unittest.TestCase):
    def test_missing_required_header_raises_named_error(self):
        df = pd.DataFrame([{
            "Магазин": "Лента-1", "Формат": "ГМ", "Город": "СПб", "Дата": "01.07.2026",
        }])
        with self.assertRaises(ValueError) as ctx:
            _normalize_upload_dataframe(df)
        message = str(ctx.exception)
        self.assertIn("Не найдена колонка", message)
        self.assertIn("Услуга", message)

    def test_headerless_file_raises_instead_of_silent_garbage(self):
        """Все колонки только по индексу → раскладывать по позициям опасно."""
        df = pd.DataFrame([[f"v{i}" for i in range(28)]])
        with self.assertRaises(ValueError) as ctx:
            _normalize_upload_dataframe(df)
        self.assertIn("заголовки", str(ctx.exception))

    def test_contacts_empty_when_employee_column_absent(self):
        df = pd.DataFrame({"Магазин": ["a"]})
        self.assertEqual(_extract_timebook_contacts(df), {})


if __name__ == "__main__":
    unittest.main()

import io
import os
import unittest
from datetime import date

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from openpyxl import Workbook
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from types import SimpleNamespace

from database import Base
from models import Rate, Service
from routers.rates import _duplicate_spelling, parse_tariff_grid
from service_catalog import build_service_resolver, get_or_create_service
from utils import pick_rate


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _new_format_file():
    """Excel по структуре Тарифы_по_уровням.xlsx: лист «ставки», заголовки в строке 1."""
    wb = Workbook()
    ws = wb.active
    ws.title = "ставки"
    ws.append(["РЕГИОН", "ТК", "УСЛУГА", "1 уровень", "2 уровень", "3 уровень", "4 уровень", "5 уровень"])
    ws.append(["Ленинградская область", "ГМ", "Уборка", 200, 250, 300, 350, 400])
    ws.append(["Ленинградская область", "СМ", "Уборка", 210, 260, 310, 360, 410])
    ws.append(["Санкт-Петербург", "ГМ", "Вингараж Универсальные услуги", 100, None, None, None, None])
    ws.append(["Санкт-Петербург", "ГМ", "Вингараж_Универсальные услуги", 100, None, None, None, None])
    buffer = io.BytesIO()
    wb.save(buffer)
    buffer.seek(0)
    return buffer


class ParseTariffGridTests(unittest.TestCase):
    def setUp(self):
        self.rows, self.conflicts = parse_tariff_grid(_new_format_file())

    def test_row_count_and_levels(self):
        # Уборка ГМ (5) + Уборка СМ (5) + Вингараж×2 (по 1) = 12
        self.assertEqual(len(self.rows), 12)
        uborka_gm = [r for r in self.rows if r["service_name"] == "Уборка" and r["format"] == "ГМ"]
        self.assertEqual(sorted(r["level"] for r in uborka_gm), [1, 2, 3, 4, 5])

    def test_service_name_and_text(self):
        row = next(r for r in self.rows
                   if r["service_name"] == "Уборка" and r["format"] == "ГМ" and r["level"] == 2)
        self.assertEqual(row["service"], "2ур_Уборка")   # текст для фолбэка
        self.assertEqual(row["service_name"], "Уборка")  # базовое имя без префикса
        self.assertEqual(row["level"], 2)
        self.assertEqual(row["hourly_rate"], 250)
        self.assertEqual(row["city"], "Ленинградская область")

    def test_rates_read_by_level_column(self):
        by = {(r["format"], r["level"]): r["hourly_rate"]
              for r in self.rows if r["service_name"] == "Уборка"}
        self.assertEqual(by[("ГМ", 1)], 200)
        self.assertEqual(by[("СМ", 5)], 410)

    def test_no_conflicts(self):
        self.assertEqual(self.conflicts, [])

    def test_duplicate_spelling_detected(self):
        pairs = _duplicate_spelling(self.rows)
        self.assertEqual(len(pairs), 1)
        self.assertEqual(pairs[0],
                         ["Вингараж Универсальные услуги", "Вингараж_Универсальные услуги"])


def _file_with_dup_keys(second_price):
    """Файл, где услуга «Уборка» ЛО/ГМ встречается дважды (дубль ключа)."""
    wb = Workbook()
    ws = wb.active
    ws.title = "ставки"
    ws.append(["РЕГИОН", "ТК", "УСЛУГА", "1 уровень", "2 уровень", "3 уровень", "4 уровень", "5 уровень"])
    ws.append(["Ленинградская область", "ГМ", "Уборка", 200, None, None, None, None])
    ws.append(["Ленинградская область", "ГМ", "Уборка", second_price, None, None, None, None])
    buffer = io.BytesIO()
    wb.save(buffer)
    buffer.seek(0)
    return buffer


class KeyInvariantLoaderTests(unittest.TestCase):
    def test_different_price_same_key_is_conflict(self):
        rows, conflicts = parse_tariff_grid(_file_with_dup_keys(350))
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["service"], "1ур_Уборка")

    def test_same_price_same_key_no_conflict(self):
        rows, conflicts = parse_tariff_grid(_file_with_dup_keys(200))
        self.assertEqual(conflicts, [])
        # обе строки распарсились (схлопывание — на этапе применения)
        self.assertEqual(len([r for r in rows if r["service"] == "1ур_Уборка"]), 2)


class ApplyCreatesModelTests(unittest.TestCase):
    """Симуляция записи upload_rates: Service заводится, Rate с service_id+level."""

    def setUp(self):
        self.s = _session()
        rows, _ = parse_tariff_grid(_new_format_file())
        for row in rows:
            service = get_or_create_service(self.s, row["service_name"])
            self.s.add(Rate(
                service=row["service"], service_id=service.id, level=row["level"],
                format=row["format"], city=row["city"],
                store=None, employee_name=None, hourly_rate=row["hourly_rate"],
            ))
        self.s.commit()

    def test_services_created_without_merge(self):
        names = {sv.name for sv in self.s.query(Service).all()}
        # Уборка + два написания Вингаража (НЕ склеены)
        self.assertEqual(names, {"Уборка", "Вингараж Универсальные услуги",
                                 "Вингараж_Универсальные услуги"})

    def test_rate_has_service_id_and_level(self):
        rate = self.s.query(Rate).filter(Rate.service == "2ур_Уборка", Rate.format == "ГМ").one()
        self.assertIsNotNone(rate.service_id)
        self.assertEqual(rate.level, 2)
        self.assertIsNone(rate.store)
        self.assertIsNone(rate.employee_name)

    def test_etap2_pickrate_finds_uploaded_rate(self):
        rates = self.s.query(Rate).all()
        resolve = build_service_resolver(self.s)
        shift = SimpleNamespace(service="2ур_Уборка", format="ГМ",
                                city="Ленинградская область", store="Лента-1",
                                employee="Иванов", shift_date=date(2026, 7, 20))
        rate = pick_rate(rates, shift, resolve=resolve)
        self.assertIsNotNone(rate)
        self.assertEqual(rate.hourly_rate, 250)


if __name__ == "__main__":
    unittest.main()

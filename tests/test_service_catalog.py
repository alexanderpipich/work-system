import os
import unittest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import Rate, Service, Shift
from service_catalog import migrate_services, service_diagnostics
from utils import normalize_format


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _rate(service, hourly_rate=200, **kw):
    kw.setdefault("format", "ГМ")
    kw.setdefault("city", "ЛО")
    return Rate(service=service, hourly_rate=hourly_rate, **kw)


def _shift(service, **kw):
    kw.setdefault("store", "Лента-1")
    kw.setdefault("format", "ГМ")
    kw.setdefault("city", "ЛО")
    kw.setdefault("shift_date", __import__("datetime").date(2026, 7, 20))
    kw.setdefault("employee", "Иванов")
    kw.setdefault("hours", 8)
    kw.setdefault("request_type", "Основные заказы")
    return Shift(service=service, **kw)


class NormalizeFormatRcTests(unittest.TestCase):
    def test_rc_legalized(self):
        self.assertEqual(normalize_format("рц"), "РЦ")
        self.assertEqual(normalize_format(" РЦ "), "РЦ")
        # ГМ/СМ по-прежнему работают
        self.assertEqual(normalize_format("гм"), "ГМ")


class MigrateServicesTests(unittest.TestCase):
    def setUp(self):
        self.s = _session()
        self.s.add_all([
            _rate("1ур_Уборка", 200),
            _rate("2ур_Уборка", 250),
            _rate("Вингараж Универсальные услуги", 300),
            _rate("Вингараж_Универсальные услуги", 300),
            _rate("1ур_Квалифицированные услуги", 400),
            _rate("1ур_Неквалифицированные услуги", 350),
        ])
        self.s.add_all([
            _shift("1ур_Уборка"),                       # тариф есть
            _shift("1ур_Продавец-универсал"),           # тарифа нет, уровень есть
            _shift("Услуги комплектации заказов"),      # тарифа нет, уровня нет
        ])
        self.s.commit()

    def test_services_created_without_merging_duplicates(self):
        report = migrate_services(self.s)
        names = {sv.name for sv in self.s.query(Service).all()}
        # Уборка (1ур+2ур схлопнулись в одну), 2 варианта Вингаража (НЕ склеены),
        # Квалиф + Неквалиф раздельно, + 2 услуги из смен без тарифа.
        self.assertIn("Уборка", names)
        self.assertIn("Вингараж Универсальные услуги", names)
        self.assertIn("Вингараж_Универсальные услуги", names)
        self.assertIn("Квалифицированные услуги", names)
        self.assertIn("Неквалифицированные услуги", names)
        self.assertIn("Продавец-универсал", names)
        self.assertIn("Услуги комплектации заказов", names)
        self.assertEqual(len(names), 7)
        self.assertEqual(report["services_created"], 7)

    def test_rate_linked_with_level(self):
        migrate_services(self.s)
        uborka = self.s.query(Service).filter(Service.name == "Уборка").one()
        rates = self.s.query(Rate).filter(Rate.service.like("%Уборка")).all()
        for rate in rates:
            self.assertEqual(rate.service_id, uborka.id)
        levels = sorted(r.level for r in rates)
        self.assertEqual(levels, [1, 2])

        # Услуга без уровня → level NULL, но связь есть.
        ving = self.s.query(Rate).filter(Rate.service == "Вингараж Универсальные услуги").one()
        self.assertIsNone(ving.level)
        self.assertIsNotNone(ving.service_id)

    def test_diagnostics_no_tariff_and_level(self):
        report = migrate_services(self.s)
        self.assertIn("Продавец-универсал", report["no_tariff_services"])
        self.assertIn("Услуги комплектации заказов", report["no_tariff_services"])
        self.assertNotIn("Уборка", report["no_tariff_services"])
        # Одна смена без уровня.
        self.assertEqual(report["shifts_without_level"], 1)

    def test_duplicate_spelling_reported(self):
        report = migrate_services(self.s)
        pairs = report["duplicate_spelling"]
        self.assertEqual(len(pairs), 1)
        self.assertEqual(
            pairs[0],
            ["Вингараж Универсальные услуги", "Вингараж_Универсальные услуги"],
        )

    def test_idempotent(self):
        migrate_services(self.s)
        count_after_first = self.s.query(Service).count()
        report2 = migrate_services(self.s)
        self.assertEqual(report2["services_created"], 0)
        self.assertEqual(self.s.query(Service).count(), count_after_first)

    def test_aliases_not_overwritten(self):
        migrate_services(self.s)
        ving = self.s.query(Service).filter(Service.name == "Вингараж Универсальные услуги").one()
        ving.aliases = "Вингараж_Универсальные услуги"
        self.s.commit()
        migrate_services(self.s)
        ving = self.s.query(Service).filter(Service.name == "Вингараж Универсальные услуги").one()
        self.assertEqual(ving.aliases, "Вингараж_Универсальные услуги")


if __name__ == "__main__":
    unittest.main()

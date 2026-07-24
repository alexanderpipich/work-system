import os
import unittest
from datetime import date

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import Rate, Service, Shift
from service_catalog import build_service_resolver, migrate_services, resolve_shift_service
from utils import pick_rate


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _rate(service, hourly_rate, **kw):
    kw.setdefault("format", "ГМ")
    kw.setdefault("city", "ЛО")
    return Rate(service=service, hourly_rate=hourly_rate, **kw)


def _shift(service, **kw):
    kw.setdefault("store", "Лента-1")
    kw.setdefault("format", "ГМ")
    kw.setdefault("city", "ЛО")
    kw.setdefault("shift_date", date(2026, 7, 20))
    kw.setdefault("employee", "Иванов")
    kw.setdefault("hours", 8)
    kw.setdefault("request_type", "Основные заказы")
    return Shift(service=service, **kw)


class ResolverTests(unittest.TestCase):
    def setUp(self):
        self.s = _session()
        self.s.add_all([_rate("1ур_Уборка", 200), _rate("Продавец", 300)])
        self.s.add_all([_shift("1ур_Уборка"), _shift("Продавец"), _shift("5ур_НетТакой")])
        self.s.commit()
        migrate_services(self.s)
        self.resolve = build_service_resolver(self.s)

    def test_resolve_level_and_id(self):
        sid, level = self.resolve(_shift("1ур_Уборка"))
        uborka = self.s.query(Service).filter(Service.name == "Уборка").one()
        self.assertEqual(sid, uborka.id)
        self.assertEqual(level, 1)

    def test_resolve_no_level(self):
        sid, level = self.resolve(_shift("Продавец"))
        self.assertIsNotNone(sid)
        self.assertIsNone(level)

    def test_resolve_alias(self):
        uborka = self.s.query(Service).filter(Service.name == "Уборка").one()
        uborka.aliases = "Клининг"
        self.s.commit()
        resolve = build_service_resolver(self.s)
        sid, level = resolve(_shift("2ур_Клининг"))
        self.assertEqual(sid, uborka.id)
        self.assertEqual(level, 2)

    def test_cache_stable(self):
        a = self.resolve(_shift("1ур_Уборка"))
        b = self.resolve(_shift("1ур_Уборка"))
        self.assertEqual(a, b)


class PickRateRegressionTests(unittest.TestCase):
    """Ключевая проверка этапа 2: pick_rate по id+level ⟶ ТЕ ЖЕ ставки, что по тексту."""

    def setUp(self):
        self.s = _session()
        self.s.add_all([
            _rate("1ур_Уборка", 200),
            _rate("2ур_Уборка", 250),
            _rate("2ур_Уборка", 260, format="СМ"),
            _rate("2ур_Уборка", 999, store="Лента-1"),   # индивидуальная по ТК
            _rate("2ур_Уборка", 1500, employee_name="Иванов"),  # индивидуальная сотрудника
            _rate("Продавец", 300),                       # без уровня
        ])
        self.s.add_all([
            _shift("1ур_Уборка"),
            _shift("2ур_Уборка", store="Лента-2", employee="Петров"),   # база ГМ → 250
            _shift("2ур_Уборка", store="Лента-2", employee="Петров", format="СМ"),  # база СМ → 260
            _shift("2ур_Уборка", store="Лента-1", employee="Петров"),   # ТК → 999
            _shift("2ур_Уборка"),                                        # сотрудник Иванов → 1500
            _shift("Продавец", employee="Петров"),                      # без уровня → 300
            _shift("5ур_НетТарифа", employee="Петров"),                 # нет ставки → None
        ])
        self.s.commit()
        migrate_services(self.s)
        self.rates = self.s.query(Rate).all()
        self.resolve = build_service_resolver(self.s)

    def test_text_vs_id_level_identical(self):
        shifts = self.s.query(Shift).all()
        for shift in shifts:
            old = pick_rate(self.rates, shift)                       # по тексту
            new = pick_rate(self.rates, shift, resolve=self.resolve)  # по service_id+level
            old_val = old.hourly_rate if old else None
            new_val = new.hourly_rate if new else None
            self.assertEqual(old_val, new_val, f"расхождение на {shift.service}")

    def test_expected_rates(self):
        by = {}
        for shift in self.s.query(Shift).all():
            r = pick_rate(self.rates, shift, resolve=self.resolve)
            by[(shift.service, shift.store, shift.employee, shift.format)] = r.hourly_rate if r else None
        self.assertEqual(by[("1ур_Уборка", "Лента-1", "Иванов", "ГМ")], 200)
        self.assertEqual(by[("2ур_Уборка", "Лента-2", "Петров", "ГМ")], 250)
        self.assertEqual(by[("2ур_Уборка", "Лента-2", "Петров", "СМ")], 260)
        self.assertEqual(by[("2ур_Уборка", "Лента-1", "Петров", "ГМ")], 999)
        self.assertEqual(by[("2ур_Уборка", "Лента-1", "Иванов", "ГМ")], 1500)
        self.assertEqual(by[("Продавец", "Лента-1", "Петров", "ГМ")], 300)
        self.assertIsNone(by[("5ур_НетТарифа", "Лента-1", "Петров", "ГМ")])

    def test_service_without_catalog_returns_none(self):
        # Услуга, которой нет в справочнике Service вовсе → нет тарифа, не падать.
        orphan_resolve = build_service_resolver(self.s)
        sid, level = orphan_resolve(_shift("9ур_Выдуманная", employee="Петров"))
        # Service такой нет (в справочник попали только услуги из rate/shift сетапа)
        self.assertIsNone(sid)

    def test_unmigrated_rate_falls_back_to_text(self):
        # Rate без service_id (ручная запись после миграции) должен всё равно найтись.
        self.s.add(_rate("3ур_НоваяУслуга", 700))  # service_id/level = None
        self.s.commit()
        rates = self.s.query(Rate).all()
        resolve = build_service_resolver(self.s)
        shift = _shift("3ур_НоваяУслуга", employee="Петров")
        r = pick_rate(rates, shift, resolve=resolve)
        self.assertIsNotNone(r)
        self.assertEqual(r.hourly_rate, 700)


if __name__ == "__main__":
    unittest.main()

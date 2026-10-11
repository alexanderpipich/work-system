"""П4.4: тарифный регион магазина, надбавка к часу, кабинеты ТМ, недельные списки,
выплатной табель в формате ведомости."""

import datetime
import os
import unittest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base
from models import Rate, Service, Shift, Store
from service_catalog import build_service_resolver
from store_helpers import populate_stores_from_shifts
from utils import pick_rate

DAY = datetime.date(2026, 9, 16)


def _session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _shift(store="Лента-660 (г. Одинцово)", city="Москва", service="3ур_Универсальная услуга для ММФ",
           hours=11.0, employee="Абазов Жанторо", fmt="СМ", day=DAY, request_type="Основные заказы"):
    return Shift(employee=employee, store=store, city=city, service=service, format=fmt, hours=hours,
                 shift_date=day, request_type=request_type)


def _grid(session):
    service = Service(name="Универсальная услуга для ММФ", is_active=True)
    session.add(service)
    session.flush()
    for region, rate in (("Москва", 304), ("Московская область", 311)):
        session.add(Rate(service="3ур_Универсальная услуга для ММФ", service_id=service.id, level=3,
                         format="СМ", city=region, hourly_rate=rate))
    session.commit()


class RateRegionTests(unittest.TestCase):
    def setUp(self):
        self.s = _session()
        _grid(self.s)

    def _rate(self, shift):
        return pick_rate(self.s.query(Rate).all(), shift, resolve=build_service_resolver(self.s)).hourly_rate

    def test_store_region_beats_shift_city(self):
        self.s.add(Store(tk_number=660, city="Москва", rate_region="Московская область", format="СМ"))
        self.s.commit()
        self.assertEqual(self._rate(_shift()), 311)  # подмосковный ТК — ставка МО

    def test_without_region_city_of_shift(self):
        self.s.add(Store(tk_number=660, city="Москва", rate_region=None, format="СМ"))
        self.s.commit()
        self.assertEqual(self._rate(_shift()), 304)
        self.assertEqual(self._rate(_shift(store="Лента-9999")), 304)  # ТК нет в справочнике

    def test_without_resolver_old_behaviour(self):
        self.s.add(Store(tk_number=660, rate_region="Московская область"))
        self.s.commit()
        self.assertEqual(pick_rate(self.s.query(Rate).all(), _shift()).hourly_rate, 304)

    def test_populate_sets_region_to_city(self):
        self.s.add(_shift(store="Лента-777", city="Санкт-Петербург"))
        self.s.commit()
        populate_stores_from_shifts(self.s)
        self.assertEqual(self.s.query(Store).filter_by(tk_number=777).one().rate_region, "Санкт-Петербург")


class TariffPreviewTests(unittest.TestCase):
    def test_new_services_and_catalog_spelling(self):
        from routers.rates import _services_vs_catalog

        s = _session()
        s.add_all([Service(name="Табакошоп Универсальные услуги"), Service(name="Услуги кассового сервиса")])
        s.commit()
        rows = [{"service_name": "Табакошоп_Универсальные услуги"}, {"service_name": "Услуги кассового сервиса"},
                {"service_name": "Услуги по выкладке СОФ"}]
        new, spelling = _services_vs_catalog(s, rows)
        self.assertEqual(new, ["Табакошоп_Универсальные услуги", "Услуги по выкладке СОФ"])
        self.assertEqual(spelling, [("Табакошоп_Универсальные услуги", "Табакошоп Универсальные услуги")])


if __name__ == "__main__":
    unittest.main()

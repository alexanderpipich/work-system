"""П4.5: закрытие старых индивидуальных ставок, регион ТК по --force-region,
новые ТК в справочнике, сводка «без ЧТС»."""

import datetime
import os
import unittest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base
from models import AuditLog, Rate, Shift, Store
from payouts_helpers import no_rate_summary
from reference_data import REFERENCE_DIR, read_reference_files, seed_reference_data
from scripts.close_legacy_individual_rates import CLOSE_DATE, close_legacy_rates
from utils import pick_rate


def _session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _shift(day, employee="Иванова Татьяна Михайловна"):
    return Shift(employee=employee, store="Лента-736", city="Ленинградская область", format="СМ", hours=11,
                 service="3ур_Универсальная услуга для ММФ", shift_date=day, request_type="Основные заказы")


class LegacyRatesTests(unittest.TestCase):
    def setUp(self):
        self.s = _session()
        self.s.add_all([
            Rate(service="3ур_Универсальная услуга для ММФ", format="СМ", city="Ленинградская область", hourly_rate=273),
            Rate(service="3ур_Универсальная услуга для ММФ", format="СМ", employee_name="Иванова Татьяна Михайловна",
                 hourly_rate=313),
            Rate(service="2ур_Квалифицированные услуги на производстве", format="СМ", store="Лента-1344 (г. Химки)",
                 hourly_rate=100),
            Rate(service="3ур_Универсальная услуга для ММФ", employee_name="Новый Сотрудник", hourly_rate=400),
            Rate(service="Повар осн.", store="Лента-48 (д. Кудрово)", hourly_rate=370,
                 active_to=datetime.date(2026, 6, 30)),  # уже закрыта раньше — не трогаем
        ])
        self.s.commit()

    def test_close_only_listed_open_rates(self):
        self.assertEqual(len(close_legacy_rates(self.s)), 2)  # сухой прогон
        self.assertIsNone(self.s.query(Rate).filter_by(hourly_rate=313).one().active_to)
        closed = close_legacy_rates(self.s, apply=True)
        self.s.commit()
        self.assertEqual(sorted(r.hourly_rate for r in closed), [100, 313])
        self.assertEqual(self.s.query(Rate).filter_by(hourly_rate=313).one().active_to, CLOSE_DATE)
        self.assertIsNone(self.s.query(Rate).filter_by(hourly_rate=400).one().active_to)  # не из списка
        self.assertEqual(self.s.query(Rate).filter_by(hourly_rate=370).one().active_to, datetime.date(2026, 6, 30))
        self.assertEqual(self.s.query(AuditLog).filter_by(action="rate.legacy_closed").count(), 2)
        self.assertEqual(close_legacy_rates(self.s), [])

    def test_pick_rate_respects_active_to(self):
        close_legacy_rates(self.s, apply=True)
        self.s.commit()
        rates = self.s.query(Rate).all()
        self.assertEqual(pick_rate(rates, _shift(datetime.date(2026, 8, 31))).hourly_rate, 313)  # до закрытия
        self.assertEqual(pick_rate(rates, _shift(datetime.date(2026, 9, 16))).hourly_rate, 273)  # после — сетка


class StoreRegionTests(unittest.TestCase):
    def _store(self, tk, region, city="КО, Обнинск"):
        return {"tk_number": tk, "display_name": f"Лента-{tk}", "city": city, "rate_region": region, "format": "ГМ",
                "object_address": None, "is_active": True, "comment": None}

    def test_force_region_overwrites_only_region_of_listed(self):
        s = _session()
        s.add_all([Store(tk_number=629, city="Обнинск", rate_region="КО, Обнинск", format="ГМ"),
                   Store(tk_number=660, city="Москва", rate_region="Московская область", format="СМ")])
        s.commit()
        data = {"stores": [self._store(629, "Обнинск"), self._store(660, "Москва", city="Москва")]}
        stats = seed_reference_data(s, data, update=True, force={"stores": ({629}, {"rate_region"})})
        s.commit()
        stores = {st.tk_number: (st.city, st.rate_region) for st in s.query(Store)}
        self.assertEqual(stores[629], ("Обнинск", "Обнинск"))  # регион перезаписан, город базы остался
        self.assertEqual(stores[660], ("Москва", "Московская область"))  # не в списке — регион базы
        self.assertIn((629, "city", "Обнинск", "КО, Обнинск"), stats["stores"]["kept"])

    def test_committed_stores_json(self):
        stores = {st["tk_number"]: st for st in read_reference_files(REFERENCE_DIR)["stores"]}
        self.assertEqual({tk: stores[tk]["rate_region"] for tk in (391, 2812, 2870)},
                         {391: "Московская область", 2812: "Московская область", 2870: "Малоярославец"})
        self.assertEqual({tk: stores[tk]["rate_region"] for tk in (610, 629, 807, 3640, 352)},
                         {610: "Малоярославец", 629: "Обнинск", 807: "Искитим", 3640: "Сортавала", 352: None})
        junk = [st["tk_number"] for st in stores.values()
                if st["rate_region"] and ("," in st["rate_region"] or st["rate_region"].startswith("г."))]
        self.assertEqual(junk, [])


class NoRateSummaryTests(unittest.TestCase):
    def test_grouped_by_base_service(self):
        summary = no_rate_summary([("3ур_Услуги комплектации заказов в ГМ и СМ", 11),
                                   ("2ур_Услуги комплектации заказов в ГМ и СМ", 4.5), ("Пекарь", 8)])
        self.assertEqual((summary["shifts"], summary["hours"]), (3, 23.5))
        self.assertEqual([(i["service"], i["shifts"], i["hours"]) for i in summary["by_service"]],
                         [("Услуги комплектации заказов в ГМ и СМ", 2, 15.5), ("Пекарь", 1, 8)])
        self.assertEqual(no_rate_summary([])["shifts"], 0)


if __name__ == "__main__":
    unittest.main()

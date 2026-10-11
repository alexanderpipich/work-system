"""П4.3: контакты ТК в справочниках, сид только добавляет / --update / --only,
город ТК не перезаписывается, МФ → СМ, город смен из справочника ТК."""

import datetime
import os
import unittest
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import Shift, Store, StoreContact
from reference_data import export_reference_data, seed_reference_data
from routers.upload import _process_shift_dataframe
from scripts.backfill_shift_city import backfill_shift_city
from utils import normalize_format


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _store(tk, city="Москва", **extra):
    record = {"tk_number": tk, "display_name": f"Лента-{tk}", "city": city, "format": "ГМ",
              "object_address": f"Адрес {tk}", "is_active": True, "comment": "Дивизион: Центр"}
    record.update(extra)
    return record


def _contact(tk, email, role="hr_dept"):
    return {"tk_number": tk, "email": email, "role": role, "name": "Иванова 8(812)000", "for_planning": True,
            "for_reconciliation": True, "for_unplanned": True, "is_active": True}


class SeedModesTests(unittest.TestCase):
    def setUp(self):
        self.s = _session()
        self.s.add(Store(tk_number=1, display_name="Лента-1 старое", city="Москва", format="ГМ"))
        self.s.add(Store(tk_number=2, display_name="Лента-2", city=None, format="ГМ"))
        self.s.commit()
        self.data = {
            "stores": [_store(1, city="МО, Королев"), _store(2, city="Химки"), _store(3)],
            "store_contacts": [_contact(1, "hr1@lenta.com"), _contact(3, "hr3@lenta.com", role="Отдел персонала"),
                               _contact(99, "hr99@lenta.com")],
        }

    def test_default_only_inserts(self):
        stats = seed_reference_data(self.s, self.data)
        self.s.commit()
        self.assertEqual((stats["stores"]["inserted"], stats["stores"]["updated"], stats["stores"]["existing"]),
                         (1, 0, 2))
        self.assertEqual(stats["stores"]["differs"], 2)
        self.assertEqual(self.s.query(Store).filter_by(tk_number=1).one().display_name, "Лента-1 старое")
        self.assertIsNone(self.s.query(Store).filter_by(tk_number=2).one().city)

    def test_update_overwrites_but_keeps_known_city(self):
        stats = seed_reference_data(self.s, self.data, update=True)
        self.s.commit()
        store1 = self.s.query(Store).filter_by(tk_number=1).one()
        self.assertEqual((store1.display_name, store1.city, store1.object_address),
                         ("Лента-1", "Москва", "Адрес 1"))
        self.assertEqual(stats["stores"]["kept"], [(1, "city", "Москва", "МО, Королев")])
        # Пустой город в базе берётся из JSON.
        self.assertEqual(self.s.query(Store).filter_by(tk_number=2).one().city, "Химки")
        self.assertEqual(stats["stores"]["updated"], 2)

    def test_second_seed_changes_nothing(self):
        seed_reference_data(self.s, self.data, update=True)
        self.s.commit()
        stats = seed_reference_data(self.s, self.data)
        for table, counts in stats.items():
            self.assertEqual((counts["inserted"], counts["updated"], counts["differs"]), (0, 0, 0), table)

    def test_contacts_resolve_store_and_role(self):
        stats = seed_reference_data(self.s, self.data)
        self.s.commit()
        self.assertEqual(stats["store_contacts"]["inserted"], 2)
        self.assertEqual(stats["store_contacts"]["unresolved"], ["нет ТК 99"])
        contact = self.s.query(StoreContact).filter_by(email="hr3@lenta.com").one()
        self.assertEqual(contact.store_id, self.s.query(Store).filter_by(tk_number=3).one().id)
        self.assertEqual(contact.role, "hr_dept")  # подпись из файла Ленты → код
        exported = export_reference_data(self.s)["store_contacts"]
        self.assertEqual(exported, [_contact(1, "hr1@lenta.com"), _contact(3, "hr3@lenta.com")])

    def test_only_limits_tables(self):
        stats = seed_reference_data(self.s, self.data, only=["store_contacts"])
        self.assertEqual(set(stats), {"store_contacts"})
        self.assertEqual(stats["store_contacts"]["unresolved"], ["нет ТК 3", "нет ТК 99"])  # ТК 3 не вставлен
        with self.assertRaises(ValueError):
            seed_reference_data(self.s, self.data, only=["shops"])


class FormatAliasTests(unittest.TestCase):
    def test_mf_is_sm(self):
        self.assertEqual(normalize_format("МФ"), "СМ")
        self.assertEqual(normalize_format(" мф "), "СМ")


class ShiftCityTests(unittest.TestCase):
    def setUp(self):
        self.s = _session()
        self.s.add_all([
            Store(tk_number=124, city="Москва", format="ГМ"),
            Store(tk_number=3168, city="Московская область", format="ГМ"),
            Store(tk_number=500, city=None, format="СМ"),
        ])
        day = datetime.date(2026, 10, 1)
        for i, (store, city) in enumerate([("Лента-124", "Москва"), ("Лента-124", None), ("Лента-124", None),
                                           ("Лента-3168", None), ("Лента-500", None), ("Лента-777", None),
                                           ("ООО «Лента»", None)]):
            self.s.add(Shift(employee=f"Сотрудник {i}", store=store, format="ГМ", city=city, service="Выкладка",
                             hours=8, shift_date=day, request_type="Основные заказы"))
        self.s.commit()

    def test_backfill_script(self):
        dry = backfill_shift_city(self.s)
        self.assertEqual(dry["filled"], {(124, "Москва"): 2})
        self.assertEqual(self.s.query(Shift).filter(Shift.city == None).count(), 6)  # noqa: E711 сухой прогон
        result = backfill_shift_city(self.s, apply=True)
        self.s.commit()
        self.assertEqual(self.s.query(Shift).filter(Shift.city == "Москва").count(), 3)
        reasons = {store: reason for (store, reason), _n in result["left"].items()}
        self.assertEqual(reasons, {
            "Лента-3168": "город ТК «Московская область» не встречается в выгрузках",
            "Лента-500": "у ТК нет города",
            "Лента-777": "ТК нет в справочнике",
            "ООО «Лента»": "нет номера ТК",
        })

    def test_upload_takes_city_from_reference(self):
        raw = pd.DataFrame({
            "Магазин": ["Лента-124", "Лента-3168", "Лента-124"],
            "Формат": ["ГМ", "ГМ", "ГМ"],
            "Город": ["", "nan", "г. Москва"],
            "Дата": ["05.10.2026", "05.10.2026", "06.10.2026"],
            "Тип заявки": ["Основные заказы"] * 3,
            "Услуга": ["Выкладка"] * 3,
            "ФИО сотрудника Исполнителя": ["Новиков", "Новиков", "Новиков"],
            "ПланФакт минус неоплач. обед (в числовом формате), часы": [8, 8, 8],
        })
        with patch("routers.upload.business_today", return_value=datetime.date(2026, 10, 10)):
            result = _process_shift_dataframe(self.s, raw)
        self.assertEqual((result["city_from_reference"], result["empty_city_shifts"]), (1, 1))
        cities = {(s.store, s.shift_date.day): s.city for s in self.s.query(Shift).filter_by(employee="Новиков")}
        self.assertEqual(cities, {("Лента-124", 5): "Москва", ("Лента-3168", 5): None, ("Лента-124", 6): "Москва"})


if __name__ == "__main__":
    unittest.main()

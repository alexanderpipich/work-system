import datetime
import os
import unittest
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import Rate, Service
from routers.services import merge_services
from service_catalog import build_service_resolver


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _user():
    return SimpleNamespace(id=1, role="superadmin")


class MergeServicesTests(unittest.TestCase):
    def setUp(self):
        self.s = _session()

    def _svc(self, name, aliases=None):
        sv = Service(name=name, aliases=aliases, is_active=True)
        self.s.add(sv)
        self.s.flush()
        return sv

    def _rate(self, sv, level, price, city="ЛО", fmt="ГМ", store=None, emp=None):
        r = Rate(service=f"{level}ур_{sv.name}", service_id=sv.id, level=level,
                 city=city, format=fmt, store=store, employee_name=emp, hourly_rate=price)
        self.s.add(r)
        self.s.flush()
        return r

    def _merge(self, canon, dups, city="", fmt=""):
        return merge_services(
            request=None, canon_id=canon.id, merge_ids=[d.id for d in dups],
            city=city, fmt=fmt, session=self.s, user=_user(),
        )

    def test_merge_repoints_rates_and_aliases_and_deletes_dup(self):
        c = self._svc("Вингараж Универсальные услуги")
        d = self._svc("Вингараж_Универсальные услуги")
        self._rate(c, 1, 100)
        self._rate(d, 2, 200)  # другой ключ → перепривязка
        resp = self._merge(c, [d])

        self.assertEqual(resp.status_code, 302)
        self.assertIn("message", resp.headers["location"])
        self.assertIsNone(self.s.query(Service).filter(Service.id == d.id).first())  # D удалён
        self.assertEqual(self.s.query(Rate).filter(Rate.service_id == c.id).count(), 2)
        canon = self.s.query(Service).filter(Service.id == c.id).first()
        self.assertIn("Вингараж_Универсальные услуги", canon.aliases)

    def test_shifts_of_both_spellings_resolve_to_canon(self):
        c = self._svc("Вингараж Универсальные услуги")
        d = self._svc("Вингараж_Универсальные услуги")
        self._rate(c, 1, 100)
        self._merge(c, [d])
        resolve = build_service_resolver(self.s)
        sid_space, _ = resolve(SimpleNamespace(service="1ур_Вингараж Универсальные услуги"))
        sid_under, _ = resolve(SimpleNamespace(service="1ур_Вингараж_Универсальные услуги"))
        self.assertEqual(sid_space, c.id)
        self.assertEqual(sid_under, c.id)  # через алиас

    def test_invariant_conflict_blocks_merge(self):
        c = self._svc("Услуга")
        d = self._svc("Услуга дубль")
        self._rate(c, 2, 240)          # тот же ключ (2,ЛО,ГМ) …
        self._rate(d, 2, 250)          # … но РАЗНАЯ цена → конфликт
        resp = self._merge(c, [d])

        self.assertIn("error", resp.headers["location"])
        self.assertIsNotNone(self.s.query(Service).filter(Service.id == d.id).first())  # НЕ удалён
        self.assertEqual(self.s.query(Rate).filter(Rate.service_id == d.id).count(), 1)  # ставка на месте

    def test_same_price_same_key_collapses(self):
        c = self._svc("Услуга")
        d = self._svc("Услуга дубль")
        self._rate(c, 2, 240)
        self._rate(d, 2, 240)          # тот же ключ, та же цена → схлопнуть
        resp = self._merge(c, [d])

        self.assertIn("message", resp.headers["location"])
        self.assertEqual(self.s.query(Rate).filter(Rate.service_id == c.id).count(), 1)

    def test_individual_rate_repointed_not_collapsed(self):
        c = self._svc("Услуга")
        d = self._svc("Услуга дубль")
        self._rate(c, 2, 240)
        self._rate(d, 2, 999, store="Лента-1")  # индивидуальная — перепривязать, не схлопывать
        self._merge(c, [d])
        rates = self.s.query(Rate).filter(Rate.service_id == c.id).all()
        self.assertEqual(len(rates), 2)
        self.assertTrue(any(r.store == "Лента-1" and r.hourly_rate == 999 for r in rates))

    def test_no_merge_ids_error(self):
        c = self._svc("Услуга")
        resp = self._merge(c, [])
        self.assertIn("error", resp.headers["location"])


if __name__ == "__main__":
    unittest.main()

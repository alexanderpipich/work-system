import os
import unittest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import Shift, Store, StoreContact
from store_helpers import extract_tk_number, populate_stores_from_shifts


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


class TkParsingTests(unittest.TestCase):
    def _p(self, s):
        return extract_tk_number(s)

    def test_plain_number(self):
        self.assertEqual(self._p("Лента-318"), 318)

    def test_leading_zero_stripped(self):
        self.assertEqual(self._p("Лента-07"), 7)

    def test_city_in_parens(self):
        self.assertEqual(self._p("Лента-115 (г. Брянск)"), 115)

    def test_large_number_with_city(self):
        self.assertEqual(self._p("Лента-1344 (г. Химки)"), 1344)

    def test_format_prefix_gm(self):
        self.assertEqual(self._p("ГМ Лента-318"), 318)

    def test_format_prefix_sm(self):
        self.assertEqual(self._p("СМ Лента-7"), 7)

    def test_empty_string_returns_none(self):
        self.assertIsNone(self._p(""))

    def test_no_digits_returns_none(self):
        self.assertIsNone(self._p("без номера"))

    def test_none_input_returns_none(self):
        self.assertIsNone(self._p(None))

    def test_same_tk_different_strings(self):
        self.assertEqual(self._p("Лента-115"), self._p("Лента-115 (г. Брянск)"))


class PopulateIdempotentTests(unittest.TestCase):
    def setUp(self):
        self.session = _session()
        import datetime
        rows = [
            ("Лента-318",           "Санкт-Петербург", "ГМ", datetime.date(2026, 1, 1)),
            ("Лента-07",            "Москва",           "СМ", datetime.date(2026, 1, 1)),
            ("Лента-115 (г. Брянск)", "Брянск",         "ГМ", datetime.date(2026, 1, 1)),
            # same TK 7, different date — must still produce only one Store(tk=7)
            ("Лента-07",            "Москва",           "СМ", datetime.date(2026, 1, 2)),
        ]
        for store_str, city, fmt, shift_date in rows:
            self.session.add(Shift(
                store=store_str, city=city, format=fmt,
                shift_date=shift_date,
                service="Кассир", employee="Тест Тест", hours=8.0,
            ))
        self.session.commit()

    def test_first_run_creates_stores(self):
        report = populate_stores_from_shifts(self.session)
        self.assertEqual(report["created"], 3)  # TK 7, 115, 318
        self.assertEqual(report["updated"], 0)
        self.assertEqual(report["unrecognized"], [])

    def test_second_run_creates_no_duplicates(self):
        populate_stores_from_shifts(self.session)
        report = populate_stores_from_shifts(self.session)
        count = self.session.query(Store).count()
        self.assertEqual(count, 3)
        self.assertEqual(report["created"], 0)

    def test_unrecognized_store_not_added(self):
        import datetime
        self.session.add(Shift(
            store="Без номера", city="Город", format="ГМ",
            shift_date=datetime.date(2026, 1, 3),
            service="Кассир", employee="Тест Тест", hours=8.0,
        ))
        self.session.commit()
        report = populate_stores_from_shifts(self.session)
        self.assertIn("Без номера", report["unrecognized"])
        self.assertEqual(self.session.query(Store).count(), 3)

    def test_existing_manual_fields_not_overwritten(self):
        populate_stores_from_shifts(self.session)
        store = self.session.query(Store).filter(Store.tk_number == 318).first()
        store.object_address = "ул. Коллонтай д.10"
        self.session.commit()
        populate_stores_from_shifts(self.session)
        store = self.session.query(Store).filter(Store.tk_number == 318).first()
        self.assertEqual(store.object_address, "ул. Коллонтай д.10")


class ContactScenariosTests(unittest.TestCase):
    def setUp(self):
        self.session = _session()
        store = Store(tk_number=999, display_name="Тест-999", city="Город", format="ГМ")
        self.session.add(store)
        self.session.flush()
        self.store_id = store.id
        self.session.add_all([
            StoreContact(store_id=self.store_id, email="plan@ex.com",    role="hr_dept", for_planning=True,  for_reconciliation=False, for_unplanned=False),
            StoreContact(store_id=self.store_id, email="recon@ex.com",   role="director", for_planning=False, for_reconciliation=True,  for_unplanned=False),
            StoreContact(store_id=self.store_id, email="unplan@ex.com",  role="security", for_planning=False, for_reconciliation=False, for_unplanned=True),
            StoreContact(store_id=self.store_id, email="multi@ex.com",   role="other",    for_planning=True,  for_reconciliation=True,  for_unplanned=True),
            StoreContact(store_id=self.store_id, email="inactive@ex.com",role="other",    for_planning=True,  is_active=False),
        ])
        self.session.commit()

    def _contacts(self, **flag):
        field, val = next(iter(flag.items()))
        return (
            self.session.query(StoreContact)
            .filter(
                StoreContact.store_id == self.store_id,
                StoreContact.is_active == True,
                getattr(StoreContact, field) == val,
            )
            .all()
        )

    def test_planning_contacts(self):
        contacts = self._contacts(for_planning=True)
        emails = {c.email for c in contacts}
        self.assertEqual(emails, {"plan@ex.com", "multi@ex.com"})

    def test_reconciliation_contacts(self):
        contacts = self._contacts(for_reconciliation=True)
        emails = {c.email for c in contacts}
        self.assertEqual(emails, {"recon@ex.com", "multi@ex.com"})

    def test_unplanned_contacts(self):
        contacts = self._contacts(for_unplanned=True)
        emails = {c.email for c in contacts}
        self.assertEqual(emails, {"unplan@ex.com", "multi@ex.com"})

    def test_inactive_contact_excluded(self):
        contacts = self._contacts(for_planning=True)
        emails = {c.email for c in contacts}
        self.assertNotIn("inactive@ex.com", emails)

    def test_role_stored_correctly(self):
        c = self.session.query(StoreContact).filter(StoreContact.email == "recon@ex.com").first()
        self.assertEqual(c.role, "director")


if __name__ == "__main__":
    unittest.main()

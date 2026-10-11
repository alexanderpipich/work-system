import os
import tempfile
import unittest
from datetime import date

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import (
    CitizenshipRegime, Country, DocumentType, EmployeeMonitoringSettings, Rate,
    ReferralSettings, RegimeDocumentRule, Service, Store,
)
from reference_data import (
    REFERENCE_DIR, TABLES, export_reference_data, read_reference_files,
    seed_reference_data, write_reference_files,
)


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _seed_source(s):
    # id намеренно «дырявые»: на новой базе они будут другими, связи — по ключам.
    s.add_all([
        CitizenshipRegime(id=7, code="rf", name="РФ", sort_order=1),
        CitizenshipRegime(id=9, code="patent", name="Патент", sort_order=2),
    ])
    s.add(Country(id=3, name="Россия", regime_id=7, aliases="РФ"))
    s.add(Country(id=5, name="Узбекистан", regime_id=9))
    s.add_all([
        DocumentType(id=11, name="Паспорт", sort_order=1, sample_image_path="/data/lost.png"),
        DocumentType(id=12, name="Патент", sort_order=7),
    ])
    s.add_all([
        RegimeDocumentRule(regime_id=7, document_type_id=11),
        RegimeDocumentRule(regime_id=9, document_type_id=11),
        RegimeDocumentRule(regime_id=9, document_type_id=12, is_required=False),
    ])
    s.add(Service(id=20, name="Выкладка", aliases="выкладка товара"))
    s.add(Store(tk_number=1234, display_name="ТК 1234", city="Санкт-Петербург", format="ГМ"))
    s.add_all([
        Rate(service="1ур_Выкладка", service_id=20, level=1, format="ГМ", hourly_rate=250.0),
        Rate(service="1ур_Выкладка", service_id=20, level=1, format="ГМ", store="1234",
             hourly_rate=270.0, active_from=date(2026, 9, 1)),
        Rate(service="Старая", hourly_rate=100.0),  # без service_id — легитимно
    ])
    s.add(EmployeeMonitoringSettings(inactive_days=10, minimum_shifts=2, analysis_days=30))
    s.add(ReferralSettings(hours_threshold=120, bonus_amount=3000))
    s.commit()


class ReferenceDataTests(unittest.TestCase):
    def setUp(self):
        self.source = _session()
        _seed_source(self.source)
        self.data = export_reference_data(self.source)

    def test_export_uses_natural_keys(self):
        country = next(c for c in self.data["countries"] if c["name"] == "Узбекистан")
        self.assertEqual(country["regime_code"], "patent")
        self.assertNotIn("id", country)
        rule = next(r for r in self.data["regime_document_rules"] if not r["is_required"])
        self.assertEqual((rule["regime_code"], rule["document_type_name"]), ("patent", "Патент"))
        self.assertNotIn("sample_image_path", self.data["document_types"][0])

    def test_round_trip_into_empty_db(self):
        target = _session()
        stats = seed_reference_data(target, self.data)
        target.commit()
        self.assertEqual(stats["rates"], {"inserted": 3, "updated": 0, "skipped": 0})
        self.assertEqual(export_reference_data(target), self.data)

        rate = target.query(Rate).filter(Rate.store == "1234").one()
        self.assertEqual(rate.service_id, target.query(Service).one().id)
        self.assertEqual(rate.active_from, date(2026, 9, 1))

    def test_second_seed_inserts_nothing(self):
        target = _session()
        seed_reference_data(target, self.data)
        target.commit()
        stats = seed_reference_data(target, self.data)
        target.commit()
        for table, counts in stats.items():
            self.assertEqual(counts["inserted"], 0, table)
            self.assertEqual(counts["updated"], 0, table)

    def test_changed_json_updates_existing_row(self):
        target = _session()
        seed_reference_data(target, self.data)
        target.commit()
        self.data["stores"][0]["display_name"] = "Новое имя"
        self.data["referral_settings"][0]["bonus_amount"] = 4000
        stats = seed_reference_data(target, self.data)
        target.commit()
        self.assertEqual(stats["stores"]["updated"], 1)
        self.assertEqual(target.query(Store).one().display_name, "Новое имя")
        self.assertEqual(target.query(ReferralSettings).one().bonus_amount, 4000)
        self.assertEqual(target.query(ReferralSettings).count(), 1)

    def test_files_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_reference_files(self.data, tmp)
            self.assertEqual(read_reference_files(tmp), self.data)


class CommittedReferenceFilesTests(unittest.TestCase):
    def test_committed_json_seeds_clean_db(self):
        data = read_reference_files(REFERENCE_DIR)
        self.assertEqual(set(data), {table for table, _ in TABLES})
        target = _session()
        seed_reference_data(target, data)
        target.commit()
        self.assertEqual(export_reference_data(target), data)


if __name__ == "__main__":
    unittest.main()

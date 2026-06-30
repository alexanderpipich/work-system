import os
import unittest
from datetime import date

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import ReconciliationNotification, Shift, Store, StoreContact
from reconciliation_helpers import (
    build_reconciliation_attachment,
    collect_reconciliation,
    period_for,
    resolve_default_period,
    shifts_for_period,
)
from reconciliation_xls import _aggregate_by_service, _group_by_employee


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _shift(**kw):
    kw.setdefault("format", "ГМ")
    kw.setdefault("request_type", "Основные заказы")
    return Shift(store="Лента-7", **kw)


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.s = _session()
        self.s.add(Store(tk_number=7, display_name="Лента-7", city="Санкт-Петербург",
                         object_address="Дальневосточный пр-т 16", is_active=True))
        self.s.add_all([
            StoreContact(store_id=1, email="recon@ex.com", role="director",
                         for_reconciliation=True, is_active=True),
            StoreContact(store_id=1, email="off@ex.com", role="other",
                         for_reconciliation=True, is_active=False),
            StoreContact(store_id=1, email="plan@ex.com", role="hr_dept",
                         for_planning=True, for_reconciliation=False, is_active=True),
        ])
        self.s.add_all([
            # Первая половина апреля (тип A и B): свод 86+116=202; сотрудники 86+83+33=202.
            _shift(employee="Иванов И.И.", service="Услуга1", hours=86, shift_date=date(2026, 4, 5)),
            _shift(employee="Петров П.П.", service="Услуга2", hours=83, shift_date=date(2026, 4, 10)),
            _shift(employee="Сидоров С.С.", service="Услуга2", hours=33, shift_date=date(2026, 4, 12)),
            # Вторая половина — только для типа B.
            _shift(employee="Иванов И.И.", service="Услуга1", hours=10, shift_date=date(2026, 4, 20)),
            # Смена без плана — исключается всегда.
            _shift(employee="Петров П.П.", service="Услуга1", hours=5, shift_date=date(2026, 4, 8),
                   request_type="Смена без плана"),
            # Вне апреля — исключается по периоду.
            _shift(employee="Иванов И.И.", service="Услуга1", hours=99, shift_date=date(2026, 3, 30)),
        ])
        self.s.commit()

    def tearDown(self):
        self.s.close()

    def test_period_for_bounds(self):
        self.assertEqual(period_for("A", 2026, 4), (date(2026, 4, 1), date(2026, 4, 15)))
        self.assertEqual(period_for("B", 2026, 4), (date(2026, 4, 1), date(2026, 4, 30)))

    def test_default_period_logic(self):
        self.assertEqual(resolve_default_period(date(2026, 4, 20)), ("A", 2026, 4))   # после 17
        self.assertEqual(resolve_default_period(date(2026, 4, 5)), ("B", 2026, 3))    # после 03 → пред. месяц
        self.assertEqual(resolve_default_period(date(2026, 4, 2)), ("A", 2026, 3))    # до 03
        self.assertEqual(resolve_default_period(date(2026, 1, 10)), ("B", 2025, 12))  # переход года

    def test_excludes_no_plan_and_out_of_period(self):
        # Тип B (весь апрель): 86+83+33+10 = 212; без 5 (без плана) и 99 (март).
        data = collect_reconciliation(self.s, "B", 2026, 4)
        self.assertEqual(len(data["to_send"]), 1)
        self.assertEqual(data["to_send"][0]["hours"], 212)

    def test_type_a_excludes_second_half(self):
        data = collect_reconciliation(self.s, "A", 2026, 4)
        self.assertEqual(data["to_send"][0]["hours"], 202)  # без смены 04-20

    def test_control_sums_equal(self):
        groups = shifts_for_period(self.s, *period_for("B", 2026, 4), tk_filter=7)
        shifts = groups[7]["shifts"]
        by_service = _aggregate_by_service(shifts)
        by_employee = _group_by_employee(shifts)
        total = sum(float(s.hours) for s in shifts)
        svod_sum = sum(by_service.values())
        emp_sum = sum(float(s.hours) for emp in by_employee.values() for s in emp)
        self.assertEqual(svod_sum, total)
        self.assertEqual(emp_sum, total)
        self.assertEqual(total, 212)

    def test_recipients_only_for_reconciliation_active(self):
        data = collect_reconciliation(self.s, "A", 2026, 4)
        self.assertEqual(data["to_send"][0]["contacts"], ["recon@ex.com"])

    def test_store_without_contacts_is_no_contacts(self):
        self.s.query(StoreContact).filter(StoreContact.email == "recon@ex.com").update(
            {"for_reconciliation": False})
        self.s.commit()
        data = collect_reconciliation(self.s, "A", 2026, 4)
        self.assertEqual(data["to_send"], [])
        self.assertEqual(len(data["no_contacts"]), 1)
        self.assertEqual(data["no_contacts"][0]["tk"], 7)

    def test_subject_format(self):
        letter = collect_reconciliation(self.s, "A", 2026, 4)["to_send"][0]
        self.assertEqual(letter["subject"], "СВЕРКА / ООО ПРОГРЕСС / Апрель / 01-15 / ТК 7")

    def test_filename_and_xlsx(self):
        filename, data = build_reconciliation_attachment(self.s, 7, "B", 2026, 4)
        self.assertEqual(filename, "сверка_ТК-007_и_ООО_ПРОГРЕСС_-_апрель_2026_-_212ч.xlsx")
        self.assertTrue(data.startswith(b"PK"))  # xlsx = zip

    def test_idempotency_by_tk_period_type(self):
        data = collect_reconciliation(self.s, "A", 2026, 4)
        self.assertFalse(data["to_send"][0]["already_sent"])

        pf, pt = period_for("A", 2026, 4)
        self.s.add(ReconciliationNotification(
            store_tk=7, period_from=pf, period_to=pt, recon_type="A", status="sent"))
        self.s.commit()

        # Тип A — теперь отправлен.
        a = collect_reconciliation(self.s, "A", 2026, 4)
        self.assertTrue(a["to_send"][0]["already_sent"])
        self.assertEqual(a["total_pending"], 0)
        # Тип B того же месяца — НЕ заблокирован (другой тип в ключе).
        b = collect_reconciliation(self.s, "B", 2026, 4)
        self.assertFalse(b["to_send"][0]["already_sent"])


if __name__ == "__main__":
    unittest.main()

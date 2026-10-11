"""Услуги, не оплачиваемые из timebook (комплектация — другой отчёт), и алиасы
формата ТШ/ЗМ → СМ, ЦП → ГМ при подборе ставки (сверка с ведомостью за сентябрь)."""

import datetime
import os
import unittest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base
from models import AuditLog, PayrollRun, Rate, Service, Shift, User
from payouts_helpers import advance_week_rows
from payroll_run_helpers import build_run_items, payable_shifts
from service_catalog import build_service_resolver
from utils import pick_rate

MONDAY = datetime.date(2026, 9, 14)
KOMPL = "Услуги комплектации заказов в ГМ и СМ"


def _session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _shift(service, fmt="СМ", employee="Иванов Иван", day=MONDAY, hours=11.0):
    return Shift(employee=employee, store="Лента-660", city="Москва", service=service, format=fmt, hours=hours,
                 shift_date=day, request_type="Основные заказы")


def _rate(service, fmt, rate, service_id):
    return Rate(service=f"3ур_{service}", service_id=service_id, level=3, format=fmt, city="Москва",
                hourly_rate=rate)


class FormatAliasTests(unittest.TestCase):
    def setUp(self):
        self.s = _session()
        for name in ("Табакошоп_Универсальные услуги", "Квалифицированные услуги на производстве"):
            self.s.add(Service(name=name))
        self.s.commit()
        self.ids = {sv.name: sv.id for sv in self.s.query(Service)}

    def _pick(self, shift):
        rate = pick_rate(self.s.query(Rate).all(), shift, resolve=build_service_resolver(self.s))
        return rate.hourly_rate if rate else None

    def test_tsh_and_zm_take_sm_rate(self):
        self.s.add(_rate("Табакошоп_Универсальные услуги", "СМ", 359, self.ids["Табакошоп_Универсальные услуги"]))
        self.s.commit()
        self.assertEqual(self._pick(_shift("3ур_Табакошоп_Универсальные услуги", fmt="ТШ")), 359)
        self.assertEqual(self._pick(_shift("3ур_Табакошоп_Универсальные услуги", fmt="ЗМ")), 359)
        self.assertIsNone(self._pick(_shift("3ур_Табакошоп_Универсальные услуги", fmt="ГМ")))

    def test_cp_takes_gm_rate(self):
        sid = self.ids["Квалифицированные услуги на производстве"]
        self.s.add_all([_rate("Квалифицированные услуги на производстве", "ГМ", 361, sid),
                        _rate("Квалифицированные услуги на производстве", "СМ", 333, sid)])
        self.s.commit()
        self.assertEqual(self._pick(_shift("3ур_Квалифицированные услуги на производстве", fmt="ЦП")), 361)

    def test_exact_format_beats_alias(self):
        sid = self.ids["Табакошоп_Универсальные услуги"]
        self.s.add_all([_rate("Табакошоп_Универсальные услуги", "СМ", 359, sid),
                        _rate("Табакошоп_Универсальные услуги", "ТШ", 400, sid)])
        self.s.commit()
        self.assertEqual(self._pick(_shift("3ур_Табакошоп_Универсальные услуги", fmt="ТШ")), 400)


class ExcludedServiceTests(unittest.TestCase):
    def setUp(self):
        self.s = _session()
        mmf = Service(name="Универсальная услуга для ММФ")
        kompl = Service(name=KOMPL, excluded_from_payroll=True)
        self.s.add_all([mmf, kompl])
        self.s.flush()
        self.s.add(_rate("Универсальная услуга для ММФ", "СМ", 304, mmf.id))  # у комплектации ставки нет
        self.shifts = [_shift("3ур_Универсальная услуга для ММФ"), _shift(f"3ур_{KOMPL}"),
                       _shift(f"2ур_{KOMPL}", day=MONDAY + datetime.timedelta(days=1))]
        self.s.add_all(self.shifts)
        self.s.commit()

    def test_payable_shifts(self):
        resolve = build_service_resolver(self.s)
        self.assertEqual([s.service for s in payable_shifts(self.shifts, resolve)],
                         ["3ур_Универсальная услуга для ММФ"])
        self.assertEqual(len(payable_shifts(self.shifts, lambda shift: (None, None))), 3)  # резолвер без признака

    def test_run_items_skip_excluded(self):
        run = PayrollRun(status="draft", kind="period", date_from=MONDAY, date_to=MONDAY + datetime.timedelta(days=6))
        self.s.add(run)
        self.s.flush()
        items = build_run_items(self.s, run, self.shifts, date_from=run.date_from, date_to=run.date_to,
                                rates=self.s.query(Rate).all(), resolve=build_service_resolver(self.s),
                                apply_lmk=False, apply_auto=False, manual=None)
        self.assertEqual([(i.service, i.amount, i.comment) for i in items],
                         [("3ур_Универсальная услуга для ММФ", 3344, None)])  # нет «Не найдена ЧТС»

    def test_advance_screen_skips_excluded(self):
        rows = advance_week_rows(self.s, MONDAY)
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["hours"], rows[0]["calc"], rows[0]["no_rate"]), (11, 3344, False))

    def test_toggle_route(self):
        import main
        from fastapi.testclient import TestClient

        from dependencies import current_user, get_db

        admin = User(id=1, employee_name="Админ", role="superadmin", is_admin=True)
        self.s.add(admin)
        self.s.commit()
        self.s.refresh(admin)
        self.s.expunge(admin)
        kompl = self.s.query(Service).filter_by(name=KOMPL).one()
        main.app.dependency_overrides[get_db] = lambda: self.s
        main.app.dependency_overrides[current_user] = lambda: admin
        try:
            client = TestClient(main.app)
            self.assertIn("Вернуть в расчёт", client.get("/admin/services").text)
            client.post(f"/admin/services/{kompl.id}/payroll-exclusion", data={"excluded": "0"})
            self.assertFalse(kompl.excluded_from_payroll)
            self.assertEqual(self.s.query(AuditLog).filter_by(action="service.payroll_exclusion").count(), 1)
        finally:
            main.app.dependency_overrides.pop(get_db, None)
            main.app.dependency_overrides.pop(current_user, None)


if __name__ == "__main__":
    unittest.main()

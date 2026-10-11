"""П3: еженедельные авансы, табель за период, реестр, права."""

import io
import os
import unittest
from datetime import date, timedelta
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

import openpyxl
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base
from models import (AdvanceSelection, LegalEntity, ManualPayrollAdjustment, PayrollRun, PayrollRunItem, Rate,
                    ReferralPayout, ReferralPromo, Requisite, Shift, User)
from payouts_helpers import (REGISTRY_COLUMNS, advance_week_rows, build_registry_xlsx, carry_over_selection,
                             create_period_draft, fix_advance, fix_period_run, registry_rows,
                             save_week_deduction, set_selection, unfix_run)
from payroll_run_helpers import half_month_bounds, is_advance_week, is_half_month

A, B, C = "Абрамов Антон", "Борисова Вера", "Третьякова Ирина"
RATE = 300.0
WEEK = date(2026, 9, 28)  # Пн; неделя 28.09–04.10 пересекает 1-е число


def _engine():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return engine


def _shift(employee, day, hours=12.0, store="ТК-1"):
    return Shift(employee=employee, store=store, format="ГМ", city="Москва", shift_date=day,
                 service="Выкладка", hours=hours, request_type="Основные заказы")


def seed(session):
    session.add(Rate(service="Выкладка", hourly_rate=RATE))
    session.add(LegalEntity(name="ООО Новая", is_active=True))
    tm = User(id=10, employee_name="Пиунов Андрей", role="tm", phone="70000000010", password_hash="x")
    other_tm = User(id=11, employee_name="Амин", role="tm", phone="70000000011", password_hash="x")
    session.add_all([tm, other_tm])
    session.add_all([
        User(id=20, employee_name="Экономист", role="economist", phone="70000000020", password_hash="x"),
        User(id=21, employee_name="Кадровик", role="hr_clerk", phone="70000000021", password_hash="x"),
        User(id=22, employee_name="Админ", role="superadmin", is_admin=True, phone="70000000022", password_hash="x"),
        User(id=1, employee_name=A, role="employee", tm_id=10),
        User(id=2, employee_name=B, role="employee", tm_id=11),
        User(id=3, employee_name=C, role="employee", tm_id=10),
    ])
    session.add_all([
        Requisite(user_id=1, employee_name=A, card_number="2202206716673921", card_expiry="11/35",
                  card_phone="79110000001", bank_name="Сбербанк", payout_method="card_phone",
                  is_active=True, is_verified=True),
        Requisite(user_id=2, employee_name=B, bank_name="Т-Банк", is_third_party=True,
                  recipient_name="Борисов Пётр", payout_method="card_phone", is_active=True, is_verified=True),
        Requisite(user_id=3, employee_name=C, card_number="4276400048438148", payout_method="card",
                  is_active=True, is_verified=True),
    ])
    day = date(2026, 9, 16)
    while day <= date(2026, 11, 2):
        if day.weekday() < 5 or day in (date(2026, 10, 4), date(2026, 11, 1)):
            session.add(_shift(A, day))
            session.add(_shift(B, day, hours=10.0))
        day += timedelta(days=1)
    session.commit()


def _user(session, user_id):
    return session.get(User, user_id)


def _items(session, run, employee):
    return session.query(PayrollRunItem).filter(
        PayrollRunItem.run_id == run.id, PayrollRunItem.employee_name == employee,
    ).order_by(PayrollRunItem.shift_date).all()


class PeriodRulesTests(unittest.TestCase):
    def test_week_and_half_month(self):
        self.assertTrue(is_advance_week(WEEK, WEEK + timedelta(days=6)))
        self.assertFalse(is_advance_week(WEEK + timedelta(days=1), WEEK + timedelta(days=7)))
        self.assertTrue(is_half_month(date(2026, 9, 16), date(2026, 9, 30)))
        self.assertTrue(is_half_month(date(2026, 2, 16), date(2026, 2, 28)))
        self.assertFalse(is_half_month(date(2026, 9, 28), date(2026, 10, 4)))
        self.assertEqual(half_month_bounds(date(2026, 10, 20)), (date(2026, 10, 16), date(2026, 10, 31)))


class AdvanceAndPeriodTests(unittest.TestCase):
    def setUp(self):
        self.session = sessionmaker(bind=_engine())()
        seed(self.session)
        self.economist = _user(self.session, 20)

    def _fix_week(self, week, names, deduction=None):
        for name in names:
            set_selection(self.session, None, self.economist, week, name, True)
        if deduction:
            self.assertIsNone(save_week_deduction(self.session, None, self.economist, week, *deduction))
        self.session.commit()
        run, errors = fix_advance(self.session, None, self.economist, week)
        self.assertEqual(errors, [])
        return run

    def test_advance_only_selected_and_period_subtracts(self):
        advance = self._fix_week(WEEK, [A])
        self.assertEqual(advance.kind, "advance")
        self.assertEqual(advance.legal_entity, "ООО Новая")
        self.assertEqual({i.employee_name for i in self.session.query(PayrollRunItem).filter(
            PayrollRunItem.run_id == advance.id)}, {A})

        sept = create_period_draft(self.session, None, self.economist, date(2026, 9, 16), date(2026, 9, 30))
        a_items = _items(self.session, sept, A)
        late = [i for i in a_items if i.shift_date >= date(2026, 9, 28)]
        self.assertEqual(len(late), 3)
        for item in late:
            self.assertEqual(item.paid_by_run_id, advance.id)
            self.assertEqual(item.advanced_amount, item.amount)
            self.assertEqual(item.total_amount, 0)
        early = [i for i in a_items if i.shift_date < date(2026, 9, 28)]
        self.assertTrue(all(i.advanced_amount == 0 and i.total_amount == i.amount for i in early))
        self.assertTrue(all(i.advanced_amount == 0 for i in _items(self.session, sept, B)))

        october = create_period_draft(self.session, None, self.economist, date(2026, 10, 1), date(2026, 10, 15))
        for item in _items(self.session, october, A):
            if item.shift_date <= date(2026, 10, 4):
                self.assertEqual(item.total_amount, 0, item.shift_date)
            else:
                self.assertEqual(item.total_amount, item.amount, item.shift_date)

    def test_hours_changed_after_advance_gives_negative_row(self):
        advance = self._fix_week(WEEK, [A])
        shift = self.session.query(Shift).filter(Shift.employee == A, Shift.shift_date == date(2026, 10, 2)).one()
        shift.hours = 8.0
        self.session.commit()
        october = create_period_draft(self.session, None, self.economist, date(2026, 10, 1), date(2026, 10, 15))
        item = next(i for i in _items(self.session, october, A) if i.shift_date == date(2026, 10, 2))
        self.assertEqual(item.paid_by_run_id, advance.id)
        self.assertEqual(item.amount, 8 * RATE)
        self.assertEqual(item.advanced_amount, 12 * RATE)
        self.assertEqual(item.total_amount, -4 * RATE)

    def test_period_fixed_first_then_advance_skips_paid_days(self):
        period = create_period_draft(self.session, None, self.economist, date(2026, 10, 16), date(2026, 10, 31))
        self.assertEqual(fix_period_run(self.session, None, self.economist, period), [])
        # 26.10.2026 — понедельник: неделя 26.10–01.11, оплачен с ней только 01.11.
        advance = self._fix_week(date(2026, 10, 26), [A])
        days = {i.shift_date for i in _items(self.session, advance, A)}
        self.assertEqual(days, {date(2026, 11, 1)})

    def test_deduction_on_first_row_and_unfix_restores(self):
        advance = self._fix_week(WEEK, [A], deduction=(A, "-1000", "ЛМК"))
        items = _items(self.session, advance, A)
        self.assertEqual(items[0].manual_adjustments_amount, -1000)
        self.assertTrue(all(i.manual_adjustments_amount == 0 for i in items[1:]))
        self.assertEqual(sum(i.total_amount for i in items), sum(i.amount for i in items) - 1000)
        adjustment = self.session.query(ManualPayrollAdjustment).one()
        self.assertEqual((adjustment.status, adjustment.applied_run_id), ("applied", advance.id))

        # Вычет аванса тоже «уже выплачен»: двойник = amount + manual (первая строка — 28.09).
        september = create_period_draft(self.session, None, self.economist, date(2026, 9, 16), date(2026, 9, 30))
        first = next(i for i in _items(self.session, september, A) if i.shift_date == items[0].shift_date)
        self.assertEqual(first.advanced_amount, items[0].amount - 1000)

        self.assertIsNone(unfix_run(self.session, None, self.economist, advance))
        self.assertEqual(advance.status, "draft")
        self.assertEqual(self.session.query(PayrollRunItem).filter(PayrollRunItem.run_id == advance.id).count(), 0)
        self.session.refresh(adjustment)
        self.assertEqual((adjustment.status, adjustment.applied_run_id), ("active", None))
        october = create_period_draft(self.session, None, self.economist, date(2026, 10, 1), date(2026, 10, 15))
        self.assertTrue(all(i.advanced_amount == 0 and i.paid_by_run_id is None
                            for i in _items(self.session, october, A)))

    def test_deduction_requires_comment(self):
        error = save_week_deduction(self.session, None, self.economist, WEEK, A, "-500", "")
        self.assertIn("комментарий", error)

    def test_carry_over_once(self):
        set_selection(self.session, None, self.economist, WEEK, A, True)
        self.session.commit()
        next_week = WEEK + timedelta(days=7)
        self.assertEqual(carry_over_selection(self.session, None, self.economist, next_week), 1)
        set_selection(self.session, None, self.economist, next_week, A, False)
        self.session.commit()
        self.assertIsNone(carry_over_selection(self.session, None, self.economist, next_week))
        self.assertEqual(self.session.query(AdvanceSelection).filter(
            AdvanceSelection.week_start == next_week).count(), 0)

    def test_week_rows_mark_paid_and_previous_selection(self):
        period = create_period_draft(self.session, None, self.economist, date(2026, 9, 16), date(2026, 9, 30))
        fix_period_run(self.session, None, self.economist, period)
        set_selection(self.session, None, self.economist, WEEK, C, True)  # без смен
        self.session.commit()
        rows = {r["employee_name"]: r for r in advance_week_rows(self.session, WEEK)}
        self.assertEqual(rows[A]["paid_hours"], 36)  # 28–30.09 оплачены табелем
        self.assertEqual(rows[A]["calc"], RATE * 12 * 3)  # 01, 02, 04.10 (03.10 — суббота)
        self.assertTrue(rows[C]["no_shifts"])


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.session = sessionmaker(bind=_engine())()
        seed(self.session)
        economist = _user(self.session, 20)
        promo = ReferralPromo(referred_employee_name="Новенький", beneficiary_name=C, status="threshold_reached")
        self.session.add(promo)
        self.session.flush()
        self.session.add(ReferralPayout(promo_id=promo.id, beneficiary_name=C, amount=5000, status="confirmed"))
        for name in (A, B):
            set_selection(self.session, None, economist, WEEK, name, True)
        self.session.commit()
        self.run, errors = fix_advance(self.session, None, economist, WEEK)
        self.assertEqual(errors, [])

    def test_rows(self):
        rows = registry_rows(self.session, self.run)
        self.assertEqual([r["Сотрудник"] for r in rows], [A, B, C])
        a, b, c = rows
        self.assertEqual((a["Номер карты"], a["Месяц"], a["Год"], a["Телефон"]), ("2202206716673921", "11", "35", "79110000001"))
        self.assertEqual((a["Способ выплаты"], a["Назначение"], a["Менеджер"], a["Проект"]),
                         ("Карта/Номер телефона", "Аванс", "Пиунов Андрей", "Лента Оффлайн"))
        self.assertEqual(a["Итого к выплате"], 12 * RATE * 6)  # Пн–Ср 28–30.09, Чт–Пт 01–02.10, Вс 04.10
        # Третье лицо, без карты.
        self.assertEqual((b["Получатель ФИО"], b["Способ выплаты"], b["Комментарии"]),
                         ("Борисов Пётр", "Наличные", "нет карты — выплата невозможна"))
        # Премия — отдельной строкой.
        self.assertEqual((c["Назначение"], c["Итого к выплате"], c["Способ выплаты"]), ("Приведи друга", 5000, "Карта"))

    def test_xlsx_columns(self):
        content = build_registry_xlsx(registry_rows(self.session, self.run))
        sheet = openpyxl.load_workbook(io.BytesIO(content)).active
        header = [cell.value for cell in sheet[1]]
        self.assertEqual(header, REGISTRY_COLUMNS)
        self.assertEqual(header[:5], ["Сотрудник", "Номер карты", "Месяц", "Год", "Телефон"])
        self.assertEqual(header[-5:], ["Способ выплаты", "Статус", "Исполнил", "Проверка карты", "Проверка тел"])


class PayoutRoutesTests(unittest.TestCase):
    def setUp(self):
        import main
        from dependencies import current_user, get_db

        engine = _engine()
        self.Session = sessionmaker(bind=engine)
        seed(self.Session())

        def override_db():
            db = self.Session()
            try:
                yield db
            finally:
                db.close()

        self.app = main.app
        self.get_db, self.current_user = get_db, current_user
        self.app.dependency_overrides[get_db] = override_db
        self.client = TestClient(main.app)

    def tearDown(self):
        self.app.dependency_overrides.pop(self.get_db, None)
        self.app.dependency_overrides.pop(self.current_user, None)

    def _as(self, user_id):
        session = self.Session()
        user = session.get(User, user_id)
        session.expunge(user)
        self.app.dependency_overrides[self.current_user] = lambda: user

    def test_tm_selects_only_own(self):
        self._as(10)
        own = self.client.post("/admin/payouts/advances/select", data={"week": WEEK.isoformat(), "employee_name": A, "checked": "1"})
        self.assertEqual(own.status_code, 200)
        other = self.client.post("/admin/payouts/advances/select", data={"week": WEEK.isoformat(), "employee_name": B, "checked": "1"})
        self.assertEqual(other.status_code, 403)
        page = self.client.get(f"/admin/payouts/advances?week={WEEK.isoformat()}").text
        self.assertIn(A, page)
        self.assertNotIn(B, page)  # «только мои» по умолчанию у ТМ
        fix = self.client.post("/admin/payouts/advances/fix", data={"week": WEEK.isoformat()}, follow_redirects=False)
        self.assertIn("error=", fix.headers["location"])
        self.assertEqual(self.Session().query(PayrollRun).count(), 0)

    def test_hr_clerk_closed(self):
        self._as(21)
        for path in ("/admin/payouts", "/admin/payouts/advances", "/admin/payouts/period/1"):
            with self.subTest(path=path):
                response = self.client.get(path, follow_redirects=False)
                self.assertEqual((response.status_code, response.headers["location"]), (302, "/"))

    def test_frozen_week_refuses_changes(self):
        self._as(20)
        self.client.post("/admin/payouts/advances/select", data={"week": WEEK.isoformat(), "employee_name": A, "checked": "1"})
        self.client.post("/admin/payouts/advances/fix", data={"week": WEEK.isoformat()})
        response = self.client.post("/admin/payouts/advances/select", data={"week": WEEK.isoformat(), "employee_name": B, "checked": "1"})
        self.assertEqual(response.status_code, 409)

    def test_registry_download(self):
        self._as(20)
        self.client.post("/admin/payouts/advances/select", data={"week": WEEK.isoformat(), "employee_name": A, "checked": "1"})
        self.client.post("/admin/payouts/advances/fix", data={"week": WEEK.isoformat()})
        run = self.Session().query(PayrollRun).one()
        with patch.dict(os.environ, {"GENERATED_FILES_ROOT": os.path.join(os.getcwd(), ".pytest_cache", "gen")}):
            response = self.client.get(f"/admin/payouts/runs/{run.id}/registry")
        self.assertEqual(response.status_code, 200)
        self.assertIn("filename*=UTF-8''%D0%90%D0%B2%D0%B0%D0%BD%D1%81_28.09.2026-04.10.2026.xlsx",
                      response.headers["content-disposition"])

    def test_legacy_fix_refuses_week_for_economist(self):
        self._as(20)
        response = self.client.post("/economist/payroll/fix", data={
            "date_from": WEEK.isoformat(), "date_to": (WEEK + timedelta(days=6)).isoformat()}, follow_redirects=False)
        self.assertIn("message=", response.headers["location"])
        self.assertEqual(self.Session().query(PayrollRun).count(), 0)

    def test_economist_legacy_fix_works_without_scopes(self):
        # Регрессия П1: Shift.city.in_(None) при выключенных скоупах.
        self._as(20)
        response = self.client.post("/economist/payroll/fix", data={
            "date_from": "2026-10-01", "date_to": "2026-10-15"}, follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["location"].startswith("/economist/payroll/runs/"))


if __name__ == "__main__":
    unittest.main()

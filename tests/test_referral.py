import os
import unittest
from datetime import date
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import (
    PayrollRunItem, ReferralPayout, ReferralPromo, ReferralSettings, Shift, User,
)
from referral_helpers import (
    apply_confirmed_payouts_to_run, cancel_payout, check_referral_thresholds,
    confirm_payout, get_referral_settings,
)
from routers.referral import referral_create


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _user(name="Приводящий"):
    return User(employee_name=name, phone="79990000000", password_hash="x", role="employee")


def _promo(session, referred="Друг", beneficiary=None):
    p = ReferralPromo(referred_employee_name=referred,
                      beneficiary_user_id=beneficiary.id if beneficiary else None,
                      beneficiary_name=beneficiary.employee_name if beneficiary else None,
                      status="active")
    session.add(p); session.flush()
    return p


def _shift(session, emp, hours, day=20):
    session.add(Shift(employee=emp, store="Лента-1", city="ЛО", format="ГМ",
                      service="1ур_У", shift_date=date(2026, 7, day), hours=hours,
                      request_type="Основные заказы"))


def _actor():
    return SimpleNamespace(id=1, role="superadmin")


class ThresholdHookTests(unittest.TestCase):
    def setUp(self):
        self.s = _session()
        s = get_referral_settings(self.s)
        s.hours_threshold = 150; s.bonus_amount = 5000
        self.ben = _user(); self.s.add(self.ben); self.s.flush()
        self.promo = _promo(self.s, "Друг", self.ben)
        self.s.commit()

    def test_below_threshold_no_payout(self):
        _shift(self.s, "Друг", 100); self.s.commit()
        created = check_referral_thresholds(self.s)
        self.assertEqual(created, 0)
        self.assertEqual(self.s.query(ReferralPromo).one().status, "active")
        self.assertEqual(self.s.query(ReferralPayout).count(), 0)

    def test_reaches_threshold_creates_pending(self):
        _shift(self.s, "Друг", 90, day=20); _shift(self.s, "Друг", 70, day=21); self.s.commit()  # 160 ≥ 150
        created = check_referral_thresholds(self.s)
        self.assertEqual(created, 1)
        promo = self.s.query(ReferralPromo).one()
        self.assertEqual(promo.status, "threshold_reached")
        self.assertIsNotNone(promo.threshold_reached_at)
        payout = self.s.query(ReferralPayout).one()
        self.assertEqual(payout.status, "pending")
        self.assertEqual(payout.amount, 5000)
        self.assertEqual(payout.beneficiary_name, "Приводящий")

    def test_idempotent(self):
        _shift(self.s, "Друг", 200); self.s.commit()
        check_referral_thresholds(self.s)
        again = check_referral_thresholds(self.s)
        self.assertEqual(again, 0)
        self.assertEqual(self.s.query(ReferralPayout).count(), 1)


class PayoutFlowTests(unittest.TestCase):
    def setUp(self):
        self.s = _session()
        get_referral_settings(self.s).hours_threshold = 150
        self.ben = _user(); self.s.add(self.ben); self.s.flush()
        self.promo = _promo(self.s, "Друг", self.ben)
        _shift(self.s, "Друг", 200); self.s.commit()
        check_referral_thresholds(self.s)
        self.payout = self.s.query(ReferralPayout).one()

    def test_confirm_then_apply_to_run_adds_bonus_item(self):
        confirm_payout(self.s, None, _actor(), self.payout.id)
        self.assertEqual(self.s.query(ReferralPayout).one().status, "confirmed")
        added = apply_confirmed_payouts_to_run(self.s, None, _actor(), run_id=1)
        self.s.commit()
        self.assertEqual(added, 1)
        item = self.s.query(PayrollRunItem).filter(PayrollRunItem.run_id == 1).one()
        self.assertEqual(item.employee_name, "Приводящий")
        self.assertEqual(item.total_amount, 5000)
        self.assertEqual(item.service, "Премия АПД")
        p = self.s.query(ReferralPayout).one()
        self.assertEqual(p.run_id, 1)
        self.assertEqual(self.s.query(ReferralPromo).one().status, "paid")

    def test_confirmed_payout_applied_once(self):
        confirm_payout(self.s, None, _actor(), self.payout.id)
        apply_confirmed_payouts_to_run(self.s, None, _actor(), run_id=1); self.s.commit()
        again = apply_confirmed_payouts_to_run(self.s, None, _actor(), run_id=2); self.s.commit()
        self.assertEqual(again, 0)  # run_id уже проставлен

    def test_cancel_payout_closes_promo(self):
        cancel_payout(self.s, None, _actor(), self.payout.id)
        self.assertEqual(self.s.query(ReferralPayout).one().status, "cancelled")
        self.assertEqual(self.s.query(ReferralPromo).one().status, "cancelled")


class UniquenessTests(unittest.TestCase):
    def setUp(self):
        self.s = _session()
        self.ben = _user(); self.s.add(self.ben); self.s.commit()

    def _req(self):
        return SimpleNamespace(url=SimpleNamespace(path="/admin/referral"))

    def test_duplicate_referred_rejected(self):
        referral_create(self._req(), "Друг", self.ben.id, "", self.s, _actor())
        resp = referral_create(self._req(), "Друг", self.ben.id, "", self.s, _actor())
        self.assertIn("error", resp.headers["location"])
        self.assertEqual(self.s.query(ReferralPromo).count(), 1)


if __name__ == "__main__":
    unittest.main()

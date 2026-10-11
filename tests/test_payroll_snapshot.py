"""Снимок фиксации табеля (П3): строки PayrollRunItem до и после выноса расчёта
в payroll_run_helpers.build_run_items должны совпадать байт-в-байт.

Эталон tests/snapshots/fix_payroll.json снят с кода до рефакторинга
(UPDATE_SNAPSHOT=1 перезаписывает его — только осознанно).
"""

import json
import os
import unittest
from datetime import date, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base
from models import (ManualPayrollAdjustment, MedicalBookCharge, PayrollAdjustment, PayrollRun,
                    PayrollRunItem, Rate, ReferralPayout, ReferralPromo, Requisite, Shift, User)

SNAPSHOT = Path(__file__).parent / "snapshots" / "fix_payroll.json"
DATE_FROM, DATE_TO = date(2026, 10, 1), date(2026, 10, 15)
A, B = "Абрамов Антон", "Борисова Вера"


def seed(session):
    session.add_all([
        Rate(service="Выкладка", hourly_rate=250.0),
        Rate(service="Выкладка", store="ТК-1", hourly_rate=300.0),
        Rate(service="Касса", hourly_rate=280.0),
        Rate(service="Касса", employee_name=B, hourly_rate=310.0),
    ])
    shifts = [
        # (сотрудник, магазин, услуга, день, часы, тип заявки)
        (A, "ТК-1", "Выкладка", 1, 11.0, "Основные заказы"),
        (A, "ТК-1", "Выкладка", 2, 12.0, "Основные заказы"),
        (A, "ТК-2", "Выкладка", 3, 8.0, "Основные заказы"),
        (A, "ТК-2", "Касса", 4, 7.5, "Основные заказы"),
        (A, "ТК-2", "Касса", 5, 4.0, "Смена без плана"),
        (B, "ТК-2", "Касса", 1, 10.0, "Основные заказы"),
        (B, "ТК-2", "Касса", 9, 9.25, "Основные заказы"),
        (B, "ТК-1", "Выкладка", 12, 6.0, "Основные заказы"),
        (B, "ТК-1", "Выкладка", 15, 12.0, "Основные заказы"),
        (B, "ТК-1", "Выкладка", 16, 12.0, "Основные заказы"),  # вне периода
    ]
    for employee, store, service, day, hours, request_type in shifts:
        session.add(Shift(employee=employee, store=store, format="ГМ", city="Москва",
                          shift_date=date(2026, 10, day), service=service, hours=hours,
                          request_type=request_type))
    for name in (A, B):
        session.add(Requisite(employee_name=name, is_active=True, is_verified=True))
    session.add(ManualPayrollAdjustment(employee_name=A, store="ТК-1", date_from=DATE_FROM,
                                        date_to=DATE_TO, amount=-500.0, comment="штраф", status="active"))
    session.add(PayrollAdjustment(employee_name=B, store="ТК-2", service="Касса",
                                  shift_date=date(2026, 9, 20), old_hours=8, new_hours=10, diff_hours=2,
                                  rate=60, diff_amount=120.0, source_run_id=1, status="approved"))
    session.add(MedicalBookCharge(employee_name=A, exam_date=date(2026, 9, 1), total_amount=2000,
                                  months_count=2, monthly_amount=1000, start_month=date(2026, 10, 1),
                                  remaining_amount=2000, status="active"))
    promo = ReferralPromo(referred_employee_name="Новенький", beneficiary_name=B, status="threshold_reached")
    session.add(promo)
    session.flush()
    session.add(ReferralPayout(promo_id=promo.id, beneficiary_name=B, amount=5000, status="confirmed"))
    session.add(User(id=900, employee_name="Админ Тест", phone="70000000900", password_hash="x",
                     role="superadmin", is_admin=True))
    session.add(User(id=901, employee_name="Экономист Тест", phone="70000000901", password_hash="x",
                     role="economist", economist_stores="Москва"))
    session.commit()


def _value(value):
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    return value


def dump(session):
    run = session.query(PayrollRun).one()
    items = session.query(PayrollRunItem).order_by(PayrollRunItem.id).all()
    item_fields = ["employee_name", "store", "service", "shift_date", "hours", "rate", "amount",
                   "other_amount", "auto_adjustments_amount", "manual_adjustments_amount",
                   "lmk_amount", "total_amount", "comment"]
    return {
        "run": {f: _value(getattr(run, f)) for f in ("status", "date_from", "date_to", "legal_entity", "comment")},
        "items": [{f: _value(getattr(item, f)) for f in item_fields} for item in items],
    }


def run_fix(path, user_id, env=None):
    import main
    from dependencies import current_user, get_db

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    seed(session)

    def override_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    user = session.get(User, user_id)
    session.expunge(user)
    main.app.dependency_overrides[get_db] = override_db
    main.app.dependency_overrides[current_user] = lambda: user
    try:
        with patch.dict(os.environ, env or {}):
            response = TestClient(main.app).post(path, data={
                "date_from": DATE_FROM.isoformat(), "date_to": DATE_TO.isoformat(),
                "legal_entity": "ООО Тест", "comment": "снимок",
            }, follow_redirects=False)
    finally:
        main.app.dependency_overrides.pop(get_db, None)
        main.app.dependency_overrides.pop(current_user, None)
    assert response.status_code == 302, response.text[:500]
    return dump(Session())


def current():
    return {
        # admin: ЛМК, авто- и ручные корректировки, премия АПД.
        "admin": run_fix("/admin/payroll/fix", 900),
        # economist (как было до П1 — со скоупами): без ЛМК.
        "economist": run_fix("/economist/payroll/fix", 901, {"SCOPES_ENABLED": "true"}),
    }


class FixPayrollSnapshotTests(unittest.TestCase):
    def test_matches_snapshot(self):
        data = current()
        if os.getenv("UPDATE_SNAPSHOT") == "1":
            SNAPSHOT.parent.mkdir(exist_ok=True)
            SNAPSHOT.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        expected = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        self.assertEqual(data, expected)


if __name__ == "__main__":
    unittest.main()

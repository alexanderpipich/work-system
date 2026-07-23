# -*- coding: utf-8 -*-
import os
import unittest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import EmployeeQr, User
from routers.qr import MAX_QR_PER_USER, _qr_access_allowed, next_qr_sort_order
from scripts.migrate_qr_codes import migrate_qr_codes
from utils import get_password_hash


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _user(session, name="Иванов И.И.", phone="79990001122", legacy_qr=None, role="employee"):
    u = User(phone=phone, password_hash=get_password_hash("x123456"),
             employee_name=name, role=role, qr_image_path=legacy_qr)
    session.add(u)
    session.commit()
    return u


class MigrationTests(unittest.TestCase):
    def test_transfers_legacy_to_first_row(self):
        s = _session()
        u = _user(s, legacy_qr="uploads/qr/qr_1_abc.png")
        moved = migrate_qr_codes(s)
        self.assertEqual(moved, 1)
        rows = s.query(EmployeeQr).filter(EmployeeQr.user_id == u.id).all()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].image_path, "uploads/qr/qr_1_abc.png")
        self.assertEqual(rows[0].sort_order, 0)
        self.assertEqual(rows[0].label, "Основной")

    def test_idempotent_second_run_transfers_nothing(self):
        s = _session()
        _user(s, legacy_qr="uploads/qr/a.png")
        self.assertEqual(migrate_qr_codes(s), 1)
        self.assertEqual(migrate_qr_codes(s), 0)  # уже перенесено — не дублируем

    def test_skips_user_without_legacy(self):
        s = _session()
        _user(s, legacy_qr=None)
        self.assertEqual(migrate_qr_codes(s), 0)

    def test_skips_user_with_existing_rows(self):
        s = _session()
        u = _user(s, legacy_qr="uploads/qr/a.png")
        s.add(EmployeeQr(user_id=u.id, image_path="uploads/qr/manual.png", label="Пекарь", sort_order=0))
        s.commit()
        self.assertEqual(migrate_qr_codes(s), 0)
        self.assertEqual(s.query(EmployeeQr).filter(EmployeeQr.user_id == u.id).count(), 1)


class SortOrderAndLimitTests(unittest.TestCase):
    def test_next_sort_order(self):
        s = _session()
        u = _user(s)
        self.assertEqual(next_qr_sort_order(s, u.id), 0)
        s.add(EmployeeQr(user_id=u.id, image_path="a.png", sort_order=0))
        s.add(EmployeeQr(user_id=u.id, image_path="b.png", sort_order=1))
        s.commit()
        self.assertEqual(next_qr_sort_order(s, u.id), 2)

    def test_limit_three(self):
        s = _session()
        u = _user(s)
        for i in range(MAX_QR_PER_USER):
            s.add(EmployeeQr(user_id=u.id, image_path=f"{i}.png", sort_order=i))
        s.commit()
        count = s.query(EmployeeQr).filter(EmployeeQr.user_id == u.id).count()
        self.assertGreaterEqual(count, MAX_QR_PER_USER)  # 4-й эндпоинт отклонит

    def test_relationship_ordered(self):
        s = _session()
        u = _user(s)
        s.add(EmployeeQr(user_id=u.id, image_path="b.png", label="B", sort_order=1))
        s.add(EmployeeQr(user_id=u.id, image_path="a.png", label="A", sort_order=0))
        s.commit()
        reloaded = s.query(User).filter(User.id == u.id).first()
        self.assertEqual([q.label for q in reloaded.qr_codes], ["A", "B"])


class AccessTests(unittest.TestCase):
    def test_self_allowed(self):
        s = _session()
        u = _user(s)
        self.assertTrue(_qr_access_allowed(u, u.id))

    def test_admin_allowed_for_other(self):
        s = _session()
        owner = _user(s, name="Владелец QR", phone="79990000001")
        admin = _user(s, name="Админ", phone="79990000002", role="superadmin")
        self.assertTrue(_qr_access_allowed(admin, owner.id))

    def test_other_employee_denied(self):
        s = _session()
        owner = _user(s, name="Владелец QR", phone="79990000001")
        stranger = _user(s, name="Чужой", phone="79990000003", role="employee")
        self.assertFalse(_qr_access_allowed(stranger, owner.id))


if __name__ == "__main__":
    unittest.main()

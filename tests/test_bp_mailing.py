import os
import unittest
from datetime import date

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import BPNotification, EmployeeStoreAssignment, Store, StoreContact
from bp_mailing_helpers import build_bp_attachment, collect_planning_bp


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


PF = date(2026, 6, 1)
PT = date(2026, 6, 30)


class BPMailingTests(unittest.TestCase):
    def setUp(self):
        self.s = _session()
        self.s.add(Store(tk_number=7, display_name="Лента-7", city="Санкт-Петербург",
                         object_address="Дальневосточный пр-т 16", format="ГМ", is_active=True))
        self.s.add_all([
            EmployeeStoreAssignment(employee_name="Иванов И.И.", store="Лента-7", is_active=True),
            EmployeeStoreAssignment(employee_name="Петров П.П.", store="Лента-7", is_active=True),
            EmployeeStoreAssignment(employee_name="Старый С.С.", store="Лента-7", is_active=False),
        ])
        self.s.add_all([
            StoreContact(store_id=1, email="plan@ex.com", role="director",
                         for_planning=True, is_active=True),
            StoreContact(store_id=1, email="off@ex.com", role="other",
                         for_planning=True, is_active=False),
            StoreContact(store_id=1, email="unplan@ex.com", role="security",
                         for_planning=False, for_unplanned=True, is_active=True),
        ])
        self.s.commit()

    def tearDown(self):
        self.s.close()

    def test_recipients_only_for_planning_active(self):
        data = collect_planning_bp(self.s, PF, PT)
        self.assertEqual(len(data["to_send"]), 1)
        letter = data["to_send"][0]
        self.assertEqual(letter["contacts"], ["plan@ex.com"])  # active for_planning only
        self.assertEqual(letter["employees_count"], 2)         # active assignments only

    def test_non_gm_format_excluded_from_bp(self):
        # БП формируется только для ГМ: сменив формат на СМ, ТК уходит из кандидатов.
        self.s.query(Store).filter(Store.tk_number == 7).update({"format": "СМ"})
        self.s.commit()
        data = collect_planning_bp(self.s, PF, PT)
        self.assertEqual(data["to_send"], [])
        self.assertEqual(data["no_contacts"], [])  # не-ГМ не показывается вовсе

    def test_subject_format(self):
        letter = collect_planning_bp(self.s, PF, PT)["to_send"][0]
        self.assertEqual(
            letter["subject"],
            "БП / ООО ПРОГРЕСС / Июнь / 01.06.2026–30.06.2026 / ТК 7",
        )

    def test_store_without_for_planning_is_no_contacts(self):
        # снимаем единственный активный for_planning контакт
        self.s.query(StoreContact).filter(StoreContact.email == "plan@ex.com").update(
            {"for_planning": False})
        self.s.commit()
        data = collect_planning_bp(self.s, PF, PT)
        self.assertEqual(data["to_send"], [])
        self.assertEqual(len(data["no_contacts"]), 1)
        self.assertEqual(data["no_contacts"][0]["tk"], 7)

    def test_idempotency_marks_already_sent(self):
        data = collect_planning_bp(self.s, PF, PT)
        self.assertFalse(data["to_send"][0]["already_sent"])
        self.assertEqual(data["total_pending"], 1)

        self.s.add(BPNotification(store_tk=7, period_from=PF, period_to=PT, status="sent"))
        self.s.commit()

        data2 = collect_planning_bp(self.s, PF, PT)
        self.assertTrue(data2["to_send"][0]["already_sent"])
        self.assertEqual(data2["total_pending"], 0)
        self.assertEqual(data2["already_sent_count"], 1)

    def test_idempotency_scoped_to_period(self):
        self.s.add(BPNotification(store_tk=7, period_from=PF, period_to=PT, status="sent"))
        self.s.commit()
        # другой период — не считается отправленным
        other = collect_planning_bp(self.s, date(2026, 7, 1), date(2026, 7, 31))
        self.assertFalse(other["to_send"][0]["already_sent"])

    def test_attachment_is_pdf(self):
        filename, data = build_bp_attachment(self.s, 7, PF, PT)
        self.assertTrue(filename.startswith("БП-007"))
        self.assertTrue(filename.endswith(".pdf"))
        self.assertTrue(data.startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()

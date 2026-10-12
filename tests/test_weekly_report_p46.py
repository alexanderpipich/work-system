"""П4.6: еженедельный отчёт по сменам — строки, колонки, ставка с надбавкой, «НЕТ»,
ИТОГО, сортировка без учёта регистра, выбор недели, маршруты."""

import datetime
import os
import tempfile
import unittest
from io import BytesIO
from unittest import mock

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

import openpyxl
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base
from models import HourlyBonus, Rate, Service, Shift, User
from weekly_report import (NO_RATE, TOTAL, WEEKLY_SHEET, build_weekly_xlsx, resolve_week, weekly_filename,
                           weekly_report)

MONDAY = datetime.date(2026, 10, 5)
UNIVERSAL = "Универсальная услуга для ММФ"
KITCHEN = "Квалифицированные услуги в столовой"  # ставки нет


def _session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _shift(employee, day, hours, service=UNIVERSAL, store="Лента-669 (г. Балашиха)", request_type="Основные заказы"):
    return Shift(employee=employee, store=store, city="Москва", format="СМ", service=f"3ур_{service}", hours=hours,
                 shift_date=MONDAY + datetime.timedelta(days=day), request_type=request_type)


def _fixture():
    s = _session()
    tm = User(id=10, employee_name="Пиунов Андрей", role="tm")
    s.add_all([tm, User(id=11, employee_name="Борисов Борис", role="employee", tm_id=10),
               Service(name=UNIVERSAL), Service(name=KITCHEN)])
    s.flush()
    universal = s.query(Service).filter_by(name=UNIVERSAL).one()
    s.add_all([
        Rate(service=f"3ур_{UNIVERSAL}", service_id=universal.id, level=3, format="СМ", city="Москва", hourly_rate=333),
        HourlyBonus(name="Акция", amount_per_hour=5, active_from=datetime.date(2026, 9, 1), is_active=True),
        # Борисов: две услуги — две строки; столовая без ставки.
        _shift("Борисов Борис", 0, 11), _shift("Борисов Борис", 1, 0),  # смена 0 часов
        _shift("Борисов Борис", 2, 10, service=KITCHEN),
        _shift("Борисов Борис", 3, 8, request_type="Смена без плана"),  # без плана — не в отчёте
        # Регистр: «АРСТАНБЕКОВА» не должна встать первой.
        _shift("АРСТАНБЕКОВА Дамира", 4, 11), _shift("аблеева Глюза", 5, 12),
        _shift("Борисов Борис", 0, 1, store="Лента-62 (г. Москва)"),
        _shift("Вне недели", 7, 11),
    ])
    s.commit()
    return s


class WeeklyReportTests(unittest.TestCase):
    def setUp(self):
        self.s = _fixture()
        self.report = weekly_report(self.s, MONDAY)

    def test_rows_order_and_values(self):
        rows = self.report["rows"]
        self.assertEqual([(r["ФИО сотрудника Исполнителя"], r["№"], r["Услуга"]) for r in rows], [
            ("аблеева Глюза", "669", f"3ур_{UNIVERSAL}"),
            ("АРСТАНБЕКОВА Дамира", "669", f"3ур_{UNIVERSAL}"),
            ("Борисов Борис", "62", f"3ур_{UNIVERSAL}"),
            ("Борисов Борис", "669", f"3ур_{KITCHEN}"),
            ("Борисов Борис", "669", f"3ур_{UNIVERSAL}"),
        ])
        self.assertEqual(self.report["days"], ["05.10", "06.10", "07.10", "08.10", "09.10", "10.10", "11.10"])
        borisov = rows[4]
        self.assertEqual((borisov["05.10"], borisov["06.10"], borisov["07.10"], borisov["08.10"]), (11, 0, None, None))
        self.assertEqual((borisov["ИЧ"], borisov["Ставка"], borisov["ФОТ"]), (11, 338, 11 * 338))
        self.assertEqual((borisov["Город"], borisov["Тип"], borisov["ТМ"]), ("Москва", "СМ", "Пиунов Андрей"))
        kitchen = rows[3]
        self.assertEqual((kitchen["07.10"], kitchen["ИЧ"], kitchen["Ставка"], kitchen["ФОТ"]), (10, 10, NO_RATE, 0))
        self.assertEqual(rows[0]["ТМ"], "")
        self.assertEqual(self.report["total"], (11 + 11 + 12 + 1) * 338)
        self.assertEqual((self.report["no_rate"]["shifts"], self.report["no_rate"]["hours"]), (1, 10))

    def test_xlsx_like_sample(self):
        sheet = openpyxl.load_workbook(BytesIO(build_weekly_xlsx(self.report)))[WEEKLY_SHEET]
        header = [c.value for c in sheet[1]]
        self.assertEqual(len(header), 16)
        self.assertEqual(header[:6] + header[-4:], ["ФИО сотрудника Исполнителя", "№", "Город", "Тип", "Услуга",
                                                    "05.10", "ИЧ", "ТМ", "Ставка", "ФОТ"])
        self.assertTrue(sheet["A1"].font.b)
        self.assertEqual(sheet["A1"].fill.fgColor.rgb, "001F4E79")
        self.assertEqual(sheet.freeze_panes, "A2")
        self.assertEqual(sheet["B2"].value, "669")  # № — текстом
        self.assertEqual(sheet["G6"].value, 0)      # смена 0 часов — 0, а не пусто
        self.assertIsNone(sheet["H6"].value)
        self.assertEqual(sheet["O5"].value, NO_RATE)
        self.assertIn("₽", sheet["O6"].number_format)
        last = [c.value for c in sheet[sheet.max_row]]
        self.assertEqual((last[0], last[15], sheet.max_row), (TOTAL, self.report["total"], 7))
        self.assertEqual(weekly_filename(MONDAY), "Недельный_отчёт_05.10.2026-11.10.2026.xlsx")

    def test_resolve_week(self):
        today = datetime.date(2026, 10, 14)  # среда: последняя завершившаяся — 05–11.10
        self.assertEqual(resolve_week("", today), MONDAY)
        self.assertEqual(resolve_week("2026-10-08", today), MONDAY)  # не понедельник — вниз до понедельника
        self.assertEqual(resolve_week("2026-09-28", today), datetime.date(2026, 9, 28))
        self.assertEqual(resolve_week("2026-10-12", today), MONDAY)  # текущая неделя недоступна
        self.assertEqual(resolve_week("2026-12-01", today), MONDAY)
        self.assertEqual(resolve_week("2026-10-12", datetime.date(2026, 10, 19)), datetime.date(2026, 10, 12))


class WeeklyRouteTests(unittest.TestCase):
    def setUp(self):
        import main
        from fastapi.testclient import TestClient

        from dependencies import current_user, get_db

        self.s = _fixture()
        self.app = main.app
        self.client = TestClient(main.app)
        self.app.dependency_overrides[get_db] = lambda: self.s
        self._current_user = current_user
        self.today = mock.patch("routers.payouts.business_today", return_value=datetime.date(2026, 10, 14))
        self.today.start()

    def tearDown(self):
        self.today.stop()
        self.app.dependency_overrides.clear()

    def _as(self, role):
        user = User(id=99, employee_name="Проверяющий", role=role, is_admin=role == "superadmin")
        self.app.dependency_overrides[self._current_user] = lambda: user

    def test_page_and_export(self):
        self._as("economist")
        html = self.client.get("/admin/payouts/weekly").text
        self.assertIn("05.10.2026 — 11.10.2026", html)
        self.assertIn("Скачать xlsx", html)
        self.assertIn("Без ЧТС", html)
        self.assertIn('disabled title="Неделя ещё не завершилась"', html)
        self.assertEqual(self.client.get("/admin/payouts/weekly?week=2026-10-12&tm=").status_code, 200)
        filtered = self.client.get("/admin/payouts/weekly?tm=10").text
        self.assertIn("Борисов Борис", filtered)
        self.assertNotIn("аблеева Глюза", filtered)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"GENERATED_FILES_ROOT": tmp}):
            response = self.client.get("/admin/payouts/weekly.xlsx?week=2026-10-07")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(openpyxl.load_workbook(BytesIO(response.content)).active.title, WEEKLY_SHEET)

    def test_tm_sees_page_without_export(self):
        self._as("tm")
        html = self.client.get("/admin/payouts/weekly").text
        self.assertIn("аблеева Глюза", html)  # все видят всех
        self.assertNotIn("Скачать xlsx", html)
        response = self.client.get("/admin/payouts/weekly.xlsx", follow_redirects=False)
        self.assertEqual(response.status_code, 302)

    def test_employee_has_no_access(self):
        self._as("employee")
        response = self.client.get("/admin/payouts/weekly", follow_redirects=False)
        self.assertEqual((response.status_code, response.headers["location"]), (302, "/"))


if __name__ == "__main__":
    unittest.main()

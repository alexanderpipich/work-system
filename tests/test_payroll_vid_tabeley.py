import os
import unittest
from datetime import date
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from schedule_grid import build_payroll_rows, days_between
from routers.payroll_runs import build_run_day_rows


def _rate(service, hourly_rate, **kwargs):
    return SimpleNamespace(
        service=service,
        hourly_rate=hourly_rate,
        active_from=kwargs.get("active_from"),
        active_to=kwargs.get("active_to"),
        format=kwargs.get("format", ""),
        city=kwargs.get("city", ""),
        store=kwargs.get("store", ""),
        employee_name=kwargs.get("employee_name", ""),
    )


def _shift(employee, store, service, shift_date, hours, request_type="Основные заказы", city="Москва", fmt="ГМ"):
    return SimpleNamespace(
        employee=employee,
        city=city,
        store=store,
        service=service,
        format=fmt,
        shift_date=shift_date,
        hours=hours,
        request_type=request_type,
    )


class PayrollDayRowsTests(unittest.TestCase):
    def setUp(self):
        self.start = date(2026, 7, 13)
        self.end = date(2026, 7, 19)
        self.days = days_between(self.start, self.end)

    def test_days_between_inclusive(self):
        self.assertEqual(len(self.days), 7)
        self.assertEqual(self.days[0], self.start)
        self.assertEqual(self.days[-1], self.end)

    def test_two_services_split_into_two_rows_same_totals(self):
        rates = [_rate("Услуга-А", 300), _rate("Услуга-Б", 500)]
        shifts = [
            _shift("Иванов", "Лента-1", "Услуга-А", date(2026, 7, 14), 8),
            _shift("Иванов", "Лента-1", "Услуга-А", date(2026, 7, 15), 3),
            _shift("Иванов", "Лента-1", "Услуга-Б", date(2026, 7, 14), 4),
        ]

        rows = build_payroll_rows(shifts, self.days, rates, include_city=False)

        # Одна и та же пара (сотрудник, магазин) с двумя услугами → две строки.
        self.assertEqual(len(rows), 2)
        services = sorted(r["service"] for r in rows)
        self.assertEqual(services, ["Услуга-А", "Услуга-Б"])

        # Итоги совпадают с наивным расчётом «по сменам».
        naive_hours = sum(s.hours for s in shifts)
        naive_amount = 8 * 300 + 3 * 300 + 4 * 500
        self.assertEqual(sum(r["hours"] for r in rows), naive_hours)
        self.assertEqual(sum(r["amount"] for r in rows), naive_amount)

        # У каждой услуги своя ЧТС.
        by_service = {r["service"]: r for r in rows}
        self.assertEqual(by_service["Услуга-А"]["rate_value"], 300)
        self.assertEqual(by_service["Услуга-Б"]["rate_value"], 500)

        # Разложение по дням совпадает с суммой за период.
        row_a = by_service["Услуга-А"]
        self.assertEqual(row_a["days"][date(2026, 7, 14)], 8)
        self.assertEqual(row_a["days"][date(2026, 7, 15)], 3)
        self.assertEqual(row_a["hours"], 11)

    def test_no_plan_shift_zero_amount_and_marked(self):
        rates = [_rate("Услуга-А", 300)]
        shifts = [
            _shift("Петров", "Лента-2", "Услуга-А", date(2026, 7, 16), 5, request_type="Смена без плана"),
        ]

        rows = build_payroll_rows(shifts, self.days, rates, include_city=False)

        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertTrue(row["is_no_plan"])
        self.assertTrue(row["has_no_plan"])
        self.assertEqual(row["amount"], 0)
        self.assertEqual(row["no_plan_hours"], 5)
        self.assertTrue(row["no_plan_days"][date(2026, 7, 16)])

    def test_missing_rate_counts(self):
        shifts = [
            _shift("Сидоров", "Лента-3", "Услуга-Х", date(2026, 7, 17), 6),
        ]
        rows = build_payroll_rows(shifts, self.days, [], include_city=False)
        self.assertEqual(rows[0]["amount"], 0)
        self.assertEqual(rows[0]["missing_rates"], 1)

    def test_manual_key_stays_at_employee_store_level(self):
        rates = [_rate("Услуга-А", 300), _rate("Услуга-Б", 500)]
        shifts = [
            _shift("Иванов", "Лента-1", "Услуга-А", date(2026, 7, 14), 8),
            _shift("Иванов", "Лента-1", "Услуга-Б", date(2026, 7, 14), 4),
        ]
        rows = build_payroll_rows(shifts, self.days, rates, include_city=False)
        # Обе строки одной пары (сотрудник, магазин) имеют один и тот же manual_key
        # (без услуги) — корректировки остаются на уровне сотрудник+магазин.
        keys = {r["manual_key"] for r in rows}
        self.assertEqual(keys, {"Иванов|||Лента-1"})


class RunDayRowsTests(unittest.TestCase):
    def test_run_aggregation_preserves_totals_and_corrections(self):
        run = SimpleNamespace(date_from=date(2026, 7, 13), date_to=date(2026, 7, 19))
        items = [
            SimpleNamespace(employee_name="Иванов", store="Лента-1", service="Услуга-А",
                            shift_date=date(2026, 7, 14), hours=8, rate=300, amount=2400, total_amount=2400),
            SimpleNamespace(employee_name="Иванов", store="Лента-1", service="Услуга-А",
                            shift_date=date(2026, 7, 15), hours=3, rate=300, amount=900, total_amount=1100),
            SimpleNamespace(employee_name="Иванов", store="Лента-1", service="Услуга-Б",
                            shift_date=date(2026, 7, 14), hours=4, rate=500, amount=2000, total_amount=2000),
        ]

        days, rows = build_run_day_rows(run, items)

        self.assertEqual(len(days), 7)
        # Две услуги → две строки; исторические суммы не пересчитываются.
        self.assertEqual(len(rows), 2)

        # Итоги строк = итоги по items (историчность прогона сохранена).
        self.assertEqual(sum(r["hours"] for r in rows), sum(i.hours for i in items))
        self.assertEqual(sum(r["total_amount"] for r in rows), sum(i.total_amount for i in items))

        by_service = {r["service"]: r for r in rows}
        row_a = by_service["Услуга-А"]
        self.assertEqual(row_a["hours"], 11)
        self.assertEqual(row_a["amount"], 3300)
        self.assertEqual(row_a["total_amount"], 3500)
        # Корректировки/ЛМК = total_amount − amount = 200.
        self.assertEqual(row_a["corrections"], 200)
        self.assertEqual(row_a["rate"], 300)
        self.assertEqual(row_a["days"][date(2026, 7, 14)], 8)
        self.assertEqual(row_a["days"][date(2026, 7, 15)], 3)


if __name__ == "__main__":
    unittest.main()

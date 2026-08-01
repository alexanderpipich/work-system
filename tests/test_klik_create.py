import os
import unittest
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import Rate, Service
from routers.rates import _resolve_service_link
from service_matrix import build_service_matrix
from utils import safe_return_to


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _env():
    return Environment(loader=FileSystemLoader("templates"), autoescape=select_autoescape(["html"]))


class ResolveServiceLinkTests(unittest.TestCase):
    def setUp(self):
        self.s = _session()

    def test_resolve_creates_and_returns_id_level(self):
        sid, level = _resolve_service_link(self.s, "2ур_Уборка")
        self.assertEqual(level, 2)
        svc = self.s.query(Service).filter(Service.name == "Уборка").one()
        self.assertEqual(sid, svc.id)

    def test_resolve_idempotent(self):
        sid1, _ = _resolve_service_link(self.s, "2ур_Уборка")
        sid2, _ = _resolve_service_link(self.s, "3ур_Уборка")
        self.assertEqual(sid1, sid2)  # та же услуга «Уборка», разные уровни

    def test_created_rate_clears_no_tariff(self):
        # Услуга «Уборка» есть в справочнике, тарифа нет → в no_tariff.
        svc = Service(name="Уборка", is_active=True)
        self.s.add(svc)
        self.s.commit()
        m0 = build_service_matrix([svc], [], [])
        self.assertIn("Уборка", m0["no_tariff_services"])

        # Создаём ставку как это делает create_rate (resolve service_id/level).
        sid, level = _resolve_service_link(self.s, "2ур_Уборка")
        self.s.add(Rate(service="2ур_Уборка", service_id=sid, level=level,
                        format="ГМ", city="ЛО", hourly_rate=300))
        self.s.commit()

        rate_rows = [{"service_id": r.service_id, "level": r.level, "city": r.city,
                      "format": r.format, "store": r.store, "employee_name": r.employee_name,
                      "hourly_rate": r.hourly_rate} for r in self.s.query(Rate).all()]
        m1 = build_service_matrix(self.s.query(Service).all(), rate_rows, [])
        self.assertNotIn("Уборка", m1["no_tariff_services"])  # ушла из «без тарифа»


class TemplateRenderTests(unittest.TestCase):
    def test_payroll_validation_errors_clickable(self):
        env = _env()
        errors = [
            {"type": "no_rate", "employee": "Иванов", "store": "Лента-1", "city": "ЛО",
             "service": "2ур_Уборка", "format": "ГМ", "date": "2026-07-20",
             "message": "Иванов / Лента-1 / 2026-07-20 — не найдена ЧТС"},
            {"type": "no_requisites", "employee": "Петров", "message": "Петров — отсутствуют активные реквизиты"},
        ]
        req = SimpleNamespace(url=SimpleNamespace(path="/admin/payroll"))
        h = env.get_template("payroll.html").render(
            rows=[], days=[], validation_errors=errors, employees=[], stores=[],
            selected_stores=[], employee_name="", date_from="a", date_to="b",
            total_hours=0, total_amount=0, legal_entities=[], message=None, error="Ошибки", request=req)
        self.assertIn("openRateModal", h)
        self.assertIn("openReqModal", h)
        self.assertIn('data-service="2ур_Уборка"', h)
        self.assertIn('data-employee="Петров"', h)
        self.assertIn('id="rate-modal"', h)
        self.assertIn('id="req-modal"', h)

    def test_payroll_modals_pass_return_to(self):
        # Экран ошибок приходит из POST /admin/payroll/fix — return_to обязан быть
        # GET-адресом табеля с тем же периодом, иначе возврат уронит 405.
        env = _env()
        req = SimpleNamespace(url=SimpleNamespace(path="/admin/payroll/fix", query=""))
        h = env.get_template("payroll.html").render(
            rows=[], days=[],
            validation_errors=[{"type": "no_rate", "employee": "Иванов", "store": "Лента-1",
                                "city": "ЛО", "service": "2ур_Уборка", "format": "ГМ",
                                "date": "2026-07-20", "message": "нет ЧТС"}],
            employees=[], stores=[], selected_stores=[], employee_name="Иванов Иван",
            date_from="2026-07-20", date_to="2026-07-26",
            total_hours=0, total_amount=0, legal_entities=[], message=None, error=None, request=req)
        expected = ('name="return_to" value="/admin/payroll?date_from=2026-07-20'
                    '&amp;date_to=2026-07-26&amp;employee_name=%D0%98')
        self.assertIn(expected, h)
        self.assertEqual(h.count('name="return_to"'), 2)  # обе модалки: ЧТС и реквизиты
        self.assertNotIn('value="/admin/payroll/fix"', h)

    def test_services_no_tariff_clickable(self):
        env = _env()
        req = SimpleNamespace(url=SimpleNamespace(path="/admin/services", query="city=%D0%9B%D0%9E"))
        h = env.get_template("service_matrix.html").render(
            rows=[], dup_groups=[], levels=[1, 2, 3, 4, 5],
            counters={"services": 1, "duplicates": 0, "key_errors": 0, "no_tariff_services": 1,
                      "unmatched_shift_services": 0, "typos": 0, "individual_rates": 0},
            no_tariff_services=["Уборка"],
            no_tariff_context={"Уборка": [{"service": "2ур_Уборка", "store": "Лента-1", "city": "ЛО",
                                           "format": "ГМ", "date": "20.07.2026", "employee": "Иванов"}]},
            unmatched_shift_services=[], cities=["ЛО"], formats=["ГМ"],
            selected_city="ЛО", selected_format="", search="", message=None, error=None,
            total_bases=1, shown_bases=1, request=req)
        self.assertIn("openRateModal", h)
        self.assertIn('data-service="2ур_Уборка"', h)
        self.assertIn("Встречалась: Лента-1", h)
        self.assertIn('id="rate-modal"', h)
        self.assertIn('name="return_to" value="/admin/services?city=%D0%9B%D0%9E"', h)


class SafeReturnToTests(unittest.TestCase):
    def test_local_path_kept(self):
        self.assertEqual(
            safe_return_to("/admin/payroll?date_from=2026-07-20", "/admin/rates"),
            "/admin/payroll?date_from=2026-07-20",
        )

    def test_empty_falls_back_to_default(self):
        self.assertEqual(safe_return_to("", "/admin/rates"), "/admin/rates")
        self.assertEqual(safe_return_to(None, "/admin/requisites"), "/admin/requisites")

    def test_external_targets_rejected(self):
        for evil in ("//evil.com", "https://evil.com", "http://evil.com/x",
                     "/\\evil.com", "evil.com", "/ok\r\nLocation: //evil.com"):
            self.assertEqual(safe_return_to(evil, "/admin/rates"), "/admin/rates", evil)


if __name__ == "__main__":
    unittest.main()

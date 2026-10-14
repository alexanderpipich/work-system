"""Форма договора по сменам за 14 дней: адрес места работы — основной магазин (Store.object_address),
ставка — самая частая ЧТС через price_shift без «Акции», должность без патента — из карточки."""

import os
import unittest
from datetime import timedelta

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from contract_data import format_rate, recent_work
from models import Country, HourlyBonus, LegalEntity, Rate, Shift, Store, User
from test_documents_contracts import EMP, _session, seed as seed_contracts
from test_predemo_p411 import _Client, _text
from time_helpers import business_today

ADDRESS = "г. Санкт-Петербург, пр. Энгельса, д. 154"
LE_ADDRESS = "СПб, ул. Бабушкина 40"  # work_address юрлица в посеве


def _shift(day, store, service, hours=8.0, request_type="Основные заказы"):
    return Shift(employee=EMP, store=store, format="ГМ", city="Санкт-Петербург", shift_date=day,
                 service=service, hours=hours, request_type=request_type)


def seed(session):
    seed_contracts(session)
    session.query(Shift).delete()  # смена посева — вне сценария
    session.add_all([Store(tk_number=660, display_name="Энгельса", object_address=ADDRESS),
                     Store(tk_number=623, display_name="Озерки", object_address="СПб, Озерки")])
    session.add_all([Rate(service="Выкладка", hourly_rate=333.0), Rate(service="Касса", hourly_rate=338.0)])
    today = business_today()
    for i in range(9):  # основной ТК 660: 9 смен по 333
        session.add(_shift(today - timedelta(days=i + 1), "ТК-660", "Выкладка"))
    for i in range(2):  # второй ТК 623: 2 смены по 338
        session.add(_shift(today - timedelta(days=i + 2), "ТК-623", "Касса"))
    session.add(_shift(today - timedelta(days=1), "ТК-623", "Касса", request_type="Смена без плана"))  # не считается
    session.add(_shift(today - timedelta(days=20), "ТК-623", "Касса"))  # старше 14 дней
    session.add(HourlyBonus(name="Акция", amount_per_hour=50.0, active_from=today - timedelta(days=30)))
    session.commit()


class ContractWorkTests(_Client):
    seed = staticmethod(seed)

    def make_session(self):
        return _session()

    def setUp(self):
        super().setUp()
        self._as(30)

    def _form(self):
        response = self.client.get("/admin/contracts/contract/1")
        self.assertEqual(response.status_code, 200)
        return response.text

    def test_main_store_and_frequent_rate(self):
        html = self._form()
        self.assertIn(ADDRESS, html)
        self.assertIn("ТК 660, 9 из 11 смен; также ТК 623, 2 смены", html)
        self.assertIn('name="rate" value="333,00"', html)  # без «Акции» (+50)
        self.assertIn("ЧТС по 9 из 11 смен; также 338 — 2 смены", html)
        self.assertNotIn(LE_ADDRESS, html)

    def test_recent_work_helper(self):
        db = self.Session()
        work = recent_work(db, db.get(User, 1), business_today())
        self.assertEqual((work["store"].tk_number, work["store_label"], work["rate"]), (660, "ТК 660", 333.0))
        self.assertEqual(format_rate(work["rate"]), "333,00")

    def test_rate_tie_broken_by_hours_and_individual_rate(self):
        db = self.Session()
        today = business_today()
        db.query(Shift).delete()
        for i in range(2):
            db.add(_shift(today - timedelta(days=i + 1), "ТК-660", "Выкладка", hours=8))
            db.add(_shift(today - timedelta(days=i + 3), "ТК-623", "Касса", hours=12))
        db.commit()
        work = recent_work(db, db.get(User, 1), today)
        self.assertEqual(work["rate"], 338.0)  # 2 и 2 смены — больше часов у 338
        self.assertEqual(work["store"].tk_number, 623)  # и магазин — по часам
        db.add(Rate(service="Касса", employee_name=EMP, hourly_rate=345.5))  # индивидуальная — как в выплатах
        db.commit()
        self.assertEqual(recent_work(db, db.get(User, 1), today)["rate"], 345.5)

    def test_shifts_without_rate_not_counted(self):
        db = self.Session()
        db.query(Rate).filter(Rate.service == "Выкладка").delete()
        db.commit()
        work = recent_work(db, db.get(User, 1), business_today())
        self.assertEqual(work["store"].tk_number, 660)  # магазин считается по всем сменам
        self.assertEqual((work["rate"], work["rate_hint"]), (338.0, "ЧТС по 2 из 2 смен"))

    def test_store_without_address_fixed_into_store(self):
        db = self.Session()
        store = db.query(Store).filter(Store.tk_number == 660).one()
        store.object_address = None
        db.commit()
        html = self._form()
        self.assertIn(f'name="fix:store:{store.id}:object_address"', html)
        self.client.post("/admin/contracts/contract/1", data={
            "rate": "333,00", "term_until": "2027-05-01", "action": "check",
            f"fix:store:{store.id}:object_address": ADDRESS})
        db = self.Session()
        self.assertEqual(db.get(Store, store.id).object_address, ADDRESS)
        self.assertEqual(db.query(LegalEntity).one().work_address, LE_ADDRESS)  # юрлицо не тронуто

    def test_no_recent_shifts_old_behaviour(self):
        db = self.Session()
        db.query(Shift).delete()
        db.commit()
        html = self._form()
        self.assertIn(LE_ADDRESS, html)  # адрес — из юрлица, как раньше
        self.assertIn('name="rate" value=""', html)
        self.assertIn("Смен со ставкой за 14 дней нет", html)
        self.assertIn("Ставка за час, ₽", html)
        self.assertNotIn("ЧТС по", html)

    def _russian(self, job_title):
        db = self.Session()
        user = db.get(User, 1)
        user.citizenship_country_id = db.query(Country).filter(Country.name == "Россия").one().id
        user.job_title = job_title
        db.commit()

    def test_position_with_patent_from_patent(self):
        self.assertIn('name="position" value="подсобный рабочий"', self._form())  # профессия по патенту в посеве
        self.assertIn("профессия по патенту", self._form())

    def test_position_without_patent_decoded_from_card(self):
        self._russian("РТЗ")
        html = self._form()
        self.assertIn('name="position" value="работник торгового зала"', html)
        self.assertIn("из карточки сотрудника: РТЗ", html)
        self._russian("ОКС")
        self.assertIn('name="position" value="кассир"', self._form())

    def test_position_empty_and_missing_without_title(self):
        for job_title, hint in ((None, "в карточке сотрудника должности нет — введите"),
                                ("ПЕКАРНЯ", "у должности «ПЕКАРНЯ» из карточки нет расшифровки — введите")):
            with self.subTest(job_title=job_title):
                self._russian(job_title)
                html = self._form()
                self.assertIn('name="position" value=""', html)
                self.assertIn('class="is-missing"', html)
                self.assertIn(hint, html)
                self.assertNotIn("подсобный рабочий", html)
                self.assertRegex(html, r'<tr class="is-missing">\s*<td class="fill-label">Должность</td>')

    def test_job_title_names(self):
        from models import JOB_TITLE_NAMES, JOB_TITLES, job_title_name
        self.assertEqual(job_title_name("ПУ"), "продавец универсал")
        self.assertEqual(job_title_name("пу", genitive=True), "продавца универсала")
        self.assertEqual(job_title_name("ПРЕСС", genitive=True), "прессовщика")
        self.assertEqual(job_title_name("ГАСТРОНОМ"), "")
        self.assertTrue(set(JOB_TITLE_NAMES) <= set(JOB_TITLES))
        # в списке должностей карточки — код с расшифровкой; значение — код
        html = self.client.get("/hr/documents/employee/1").text
        self.assertIn('<option value="РТЗ" >РТЗ — работник торгового зала</option>', html)
        self.assertIn('<option value="ГАСТРОНОМ" >ГАСТРОНОМ</option>', html)

    def test_recommendation_position_decoded(self):
        self._russian("МОЙКА")
        html = self.client.get("/admin/contracts/recommendation/1").text
        self.assertIn('name="position" value="мойщик"', html)

    def test_generated_contract_uses_store_and_rate(self):
        response = self.client.post("/admin/contracts/contract/1", data={
            "contract_number": "26-0101", "rate": "333,00", "term_until": "2027-05-01", "action": "generate_skip"})
        self.assertEqual(response.status_code, 200, response.text[:300])
        text = _text(response.content)
        self.assertIn(ADDRESS, text)
        self.assertIn("333,00 (триста тридцать три) рубля 00 копеек", text)
        self.assertNotIn(LE_ADDRESS, text)

    def test_typed_rate_kept(self):
        html = self.client.post("/admin/contracts/contract/1", data={
            "rate": "350", "term_until": "2027-05-01", "action": "check"}).text
        self.assertIn('name="rate" value="350"', html)
        self.assertNotIn("ЧТС по 9 из 11", html)  # подсказка — только к подставленной ставке


if __name__ == "__main__":
    unittest.main()

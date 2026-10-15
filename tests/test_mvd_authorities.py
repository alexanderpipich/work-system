"""Справочник «Подразделения МВД» — адресаты ходатайств: подбор по основному магазину за 14 дней
(закреплено в карточке ТК → город ТК в cities подразделения → по умолчанию региона), шапка «КОМУ»
ходатайства из выбранного подразделения, ввод на месте — в карточку подразделения, перенос из регионов."""

import io
import json
import os
import shutil
import subprocess
import unittest
from datetime import timedelta

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from docx import Document

from models import AuditLog, MvdAuthority, Region, Shift, Store, User
from contract_data import recent_work
from mvd_authorities import authority_for_store, authority_for_work, migrate_region_addressees
from reference_data import read_reference_files, seed_reference_data
from test_documents_contracts import EMP, _session, seed as seed_contracts
from test_predemo_p411 import UI_JS, _Client
from time_helpers import business_today

SPB_DEFAULT = "УВМ ГУ МВД России по СПб и ЛО"
MO_DEFAULT = "ГУ МВД России по Московской области"
BALASHIHA = "ОВМ МУ МВД России «Балашихинское»"


def seed(session):
    seed_contracts(session)  # СПб: регион, подразделение по умолчанию, ТК 1 (Санкт-Петербург) со сменой
    mo = Region(name="Москва и Московская область", cities="Москва, Химки, Балашиха", is_active=True)
    session.add(mo)
    session.flush()
    session.add_all([
        MvdAuthority(name=MO_DEFAULT, region_id=mo.id, addressee_dative="Начальнику ГУ МВД России по Московской области",
                     chief_rank_dative="Генерал-майору полиции", chief_name_dative="Сидорову С.С.",
                     is_region_default=True, is_active=True),
        MvdAuthority(name=BALASHIHA, region_id=mo.id, addressee_dative="Начальнику ОВМ МУ МВД России «Балашихинское»",
                     chief_rank_dative="Подполковнику полиции", chief_name_dative="Петрову П.П.",
                     cities="Балашиха, Железнодорожный", is_active=True),
    ])
    session.add(Store(tk_number=660, display_name="Балашиха", city="Балашиха", object_address="г. Балашиха, ш. Энтузиастов, 1"))
    session.commit()


def _authority(session, name):
    return session.query(MvdAuthority).filter(MvdAuthority.name == name).one()


def _store(session, tk):
    return session.query(Store).filter(Store.tk_number == tk).one()


class AuthorityChoiceTests(unittest.TestCase):
    def setUp(self):
        self.session = _session()()
        seed(self.session)

    def test_spb_store_gets_region_default(self):
        authority, how = authority_for_store(self.session, _store(self.session, 1))
        self.assertEqual(authority.name, SPB_DEFAULT)
        self.assertIn("по умолчанию региона", how)

    def test_mo_store_city_in_cities(self):
        authority, how = authority_for_store(self.session, _store(self.session, 660))
        self.assertEqual((authority.name, how), (BALASHIHA, "г. Балашиха"))

    def test_mo_store_other_city_region_default(self):
        store = _store(self.session, 660)
        store.city = "Химки"
        self.assertEqual(authority_for_store(self.session, store)[0].name, MO_DEFAULT)

    def test_manual_binding_beats_city(self):
        store = _store(self.session, 660)
        store.mvd_authority_id = _authority(self.session, MO_DEFAULT).id
        authority, how = authority_for_store(self.session, store)
        self.assertEqual((authority.name, how), (MO_DEFAULT, "закреплено в карточке магазина"))

    def test_employee_by_main_store(self):
        self.session.add_all([Shift(employee=EMP, store="ТК-660", format="ГМ", city="Москва", service="Выкладка", hours=8,
                               shift_date=business_today() - timedelta(days=d), request_type="Основные заказы")
                         for d in (1, 2)])
        self.session.commit()
        work = recent_work(self.session, self.session.get(User, 1), business_today())
        authority, hint = authority_for_work(self.session, work)
        self.assertEqual(authority.name, BALASHIHA)
        self.assertEqual(hint, "по ТК 660, г. Балашиха")

    def test_no_shifts_falls_back_to_employee_region(self):
        spb = self.session.query(Region).filter(Region.name == "СПб и ЛО").one()
        authority, hint = authority_for_work(self.session, None, spb)
        self.assertEqual(authority.name, SPB_DEFAULT)
        self.assertIn("смен за 14 дней нет", hint)
        self.assertEqual(authority_for_work(self.session, None, None)[0], None)


class MigrationTests(unittest.TestCase):
    def test_region_addressee_moved_once(self):
        session = _session()()
        region = Region(name="Санкт-Петербург и Ленинградская область", is_active=True,
                        uvm_addressee="Начальнику УВМ ГУ МВД России по Санкт-Петербургу и Ленинградской области",
                        uvm_rank="Полковнику полиции", uvm_person="Иванову И.В.")
        session.add_all([region, Region(name="Пустой", is_active=True)])
        session.commit()
        created = migrate_region_addressees(session)
        session.commit()
        self.assertEqual(len(created), 1)
        authority = session.query(MvdAuthority).one()
        self.assertEqual((authority.region_id, authority.is_region_default, authority.chief_name_dative,
                          authority.chief_rank_dative, authority.addressee_dative),
                         (region.id, True, "Иванову И.В.", "Полковнику полиции", region.uvm_addressee))
        self.assertEqual(migrate_region_addressees(session), [])  # повторно — ничего
        # имя — как в data/reference/mvd_authorities.json: сид справочника не задвоит
        stats = seed_reference_data(session, read_reference_files(), only=["mvd_authorities"])
        self.assertEqual(stats["mvd_authorities"]["inserted"], 0)
        self.assertEqual(session.query(MvdAuthority).count(), 1)

    def test_reference_seed_inserts_with_region(self):
        session = _session()()
        seed_reference_data(session, read_reference_files(), only=["regions", "mvd_authorities"])
        authority = session.query(MvdAuthority).one()
        self.assertEqual(session.get(Region, authority.region_id).name, "Санкт-Петербург и Ленинградская область")
        self.assertTrue(authority.is_region_default)


class PetitionFormTests(_Client):
    seed = staticmethod(seed)

    def make_session(self):
        return _session()

    def setUp(self):
        super().setUp()
        self._as(30)

    def test_form_preselected_by_store_with_hint(self):
        html = self.client.get("/admin/contracts/petition/1").text
        spb = _authority(self.Session(), SPB_DEFAULT)
        self.assertIn('<select name="mvd_authority_id" data-recheck="mvd">', html)
        self.assertIn(f'<option value="{spb.id}" selected>', html)
        self.assertIn("по ТК 1, по умолчанию региона «СПб и ЛО»", html)
        self.assertNotIn('name="fix:region:uvm', html)

    def test_header_from_selected_authority(self):
        balashiha = _authority(self.Session(), BALASHIHA)
        response = self.client.post("/admin/contracts/petition/1", data={
            "mvd_authority_id": balashiha.id, "petition_date": "2026-10-15", "action": "generate_skip"})
        self.assertEqual(response.status_code, 200, response.text[:300])
        text = "\n".join(p.text for p in Document(io.BytesIO(response.content)).paragraphs)
        self.assertIn("Начальнику ОВМ МУ МВД России «Балашихинское»", text)
        self.assertIn("Подполковнику полиции", text)
        self.assertIn("Петрову П.П.", text)
        self.assertNotIn("Санкт-Петербургу и Ленинградской", text.split("Прошу")[0].split("ОГРН")[-1])

    def test_fix_in_place_saved_to_authority_not_region(self):
        html = self.client.get("/admin/contracts/petition/1").text
        self.assertIn('name="fix:mvd:chief_name_dative"', html)  # у СПб-подразделения нет ФИО начальника
        self.client.post("/admin/contracts/petition/1", data={
            "petition_date": "2026-10-15", "action": "check", "fix:mvd:chief_name_dative": "Иванову И.В."})
        db = self.Session()
        self.assertEqual(_authority(db, SPB_DEFAULT).chief_name_dative, "Иванову И.В.")
        self.assertIsNone(db.query(Region).filter(Region.name == "СПб и ЛО").one().uvm_person)

    def test_region_form_has_no_addressee(self):
        html = self.client.get("/admin/regions").text
        self.assertNotIn('name="uvm_addressee"', html)
        self.assertIn("подразделений МВД: 1", html)

    def test_store_card_binding(self):
        db = self.Session()
        store, mo = _store(db, 660), _authority(db, MO_DEFAULT)
        self._as(40)
        html = self.client.get(f"/admin/stores/{store.id}").text
        self.assertIn(f"— по городу / региону: {BALASHIHA} —", html)
        self.client.post(f"/admin/stores/{store.id}/update", data={"city": "Балашиха", "is_active": "1",
                                                                  "mvd_authority_id": mo.id})
        self.assertEqual(_store(self.Session(), 660).mvd_authority_id, mo.id)
        self.client.post(f"/admin/stores/{store.id}/update", data={"city": "Балашиха", "is_active": "1"})
        self.assertEqual(_store(self.Session(), 660).mvd_authority_id, mo.id)  # поля нет в форме — не трогаем


class DirectoryPageTests(_Client):
    seed = staticmethod(seed)

    def make_session(self):
        return _session()

    def test_page_grouped_and_rights(self):
        self._as(30)  # руководитель: regions.manage
        html = self.client.get("/admin/mvd-authorities").text
        db = self.Session()
        mo = db.query(Region).filter(Region.name == "Москва и Московская область").one()
        spb = db.query(Region).filter(Region.name == "СПб и ЛО").one()
        balashiha, spb_default = _authority(db, BALASHIHA), _authority(db, SPB_DEFAULT)
        # группы по регионам: подразделение — под заголовком своего региона
        self.assertLess(html.index(f'id="region-{mo.id}"'), html.index(f'id="mvd-{balashiha.id}"'))
        self.assertLess(html.index(f'id="mvd-{balashiha.id}"'), html.index(f'id="region-{spb.id}"'))
        self.assertLess(html.index(f'id="region-{spb.id}"'), html.index(f'id="mvd-{spb_default.id}"'))
        self.assertIn("шапка «КОМУ» заполнена не полностью", html)  # СПб: нет ФИО начальника
        self._as(10)  # ТМ — без regions.manage
        self.assertNotEqual(self.client.get("/admin/mvd-authorities", follow_redirects=False).status_code, 200)

    def test_save_default_unique_per_region_and_audit(self):
        self._as(30)
        db = self.Session()
        balashiha = _authority(db, BALASHIHA)
        response = self.client.post("/admin/mvd-authorities/save", data={
            "authority_id": balashiha.id, "name": BALASHIHA, "region_id": balashiha.region_id,
            "is_region_default": "1", "is_active": "1", "address": "г. Балашиха, ул. Советская, 1"},
            follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        db = self.Session()
        self.assertTrue(_authority(db, BALASHIHA).is_region_default)
        self.assertFalse(_authority(db, MO_DEFAULT).is_region_default)
        self.assertEqual(_authority(db, BALASHIHA).chief_name_dative, "Петрову П.П.")  # поля нет — не тронуто
        logs = db.query(AuditLog).filter(AuditLog.entity_type == "mvd_authority").all()
        self.assertEqual(len(logs), 2)
        changed = next(json.loads(log.new_value) for log in logs if log.entity_name == BALASHIHA)
        self.assertEqual(set(changed), {"is_region_default", "address"})

    def test_create(self):
        self._as(30)
        region_id = self.Session().query(Region).filter(Region.name == "СПб и ЛО").one().id
        self.client.post("/admin/mvd-authorities/save", data={"name": "ОВМ УМВД по Всеволожскому району",
                                                              "region_id": region_id, "cities": "Всеволожск"})
        authority = _authority(self.Session(), "ОВМ УМВД по Всеволожскому району")
        self.assertEqual((authority.cities, authority.is_region_default, authority.is_active), ("Всеволожск", False, True))


RECHECK_MVD = r"""
const fs = require('fs');
const noop = () => {};
const fields = ['fix:mvd:chief_name_dative', 'fix:le:inn', 'petition_date'].map(name => ({ name, disabled: false }));
const appended = [];
const form = { elements: fields, submitted: false, appendChild(el) { appended.push(el); }, submit() { this.submitted = true; } };
const select = { form, listeners: {}, getAttribute: n => n === 'data-recheck' ? 'mvd' : null,
  addEventListener(t, f) { this.listeners[t] = f; } };
const stub = () => ({ classList: { add: noop, remove: noop, toggle: noop, contains: () => false }, style: {},
  setAttribute: noop, appendChild: noop, addEventListener: noop, querySelectorAll: () => [], querySelector: () => null });
global.window = { matchMedia: () => ({ matches: true, addEventListener: noop }), addEventListener: noop };
global.sessionStorage = { getItem: noop, setItem: noop };
global.document = { readyState: 'complete', body: stub(), documentElement: stub(), addEventListener: noop,
  createElement: () => ({}), getElementById: () => null, querySelector: () => null,
  querySelectorAll: sel => sel === 'form[data-recheck-form] select[data-recheck]' ? [select] : [] };
global.IntersectionObserver = function () { return { observe: noop }; };
eval(fs.readFileSync(process.argv[1], 'utf8'));
select.listeners.change();
console.log(JSON.stringify({ submitted: form.submitted, action: appended.map(e => [e.name, e.value]),
  disabled: fields.filter(f => f.disabled).map(f => f.name) }));
"""


@unittest.skipUnless(shutil.which("node"), "нужен node")
class RecheckMvdJsTests(unittest.TestCase):
    def test_addressee_change_rechecks_without_old_fixes(self):
        result = subprocess.run(["node", "-e", RECHECK_MVD, UI_JS], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"submitted": True, "action": [["action", "check"]],
                                                     "disabled": ["fix:mvd:chief_name_dative"]})


if __name__ == "__main__":
    unittest.main()

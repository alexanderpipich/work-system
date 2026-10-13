"""/admin/users: поля карточки по роли. Должность, закреплённый ТМ, дата рождения, пол — только
линейному персоналу (сотрудник, бригадир); «Магазин бригадира» — только бригадиру. Офисным ролям
поля не показываются, а при сохранении не трогаются (старые tm_id/должность из импорта остаются)."""

import datetime
import json
import os
import re
import shutil
import subprocess
import unittest
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from fastapi import Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base
from dependencies import current_user, get_db
from models import CitizenshipRegime, Country, User

SUPERADMIN = SimpleNamespace(id=1, role="superadmin", is_admin=True, employee_name="Админ", phone="70000000001",
                             economist_stores="", brigadier_store=None)
UI_JS = os.path.join(os.path.dirname(__file__), "..", "static", "ui.js")


def _card(html, user_id):
    """HTML одной карточки списка: от <details id="user-N"> до закрывающего </details>."""
    start = html.index(f'id="user-{user_id}"')
    return html[start:html.index("</details>", start)]


def _field_block(card, name):
    """Открывающий тег блока .field, в котором лежит поле name, и сам тег поля."""
    match = re.search(r'(<div class="field"[^>]*>)\s*<label[^>]*>[^<]*</label>\s*(<(?:input|select)[^>]*name="'
                      + name + r'"[^>]*>)', card)
    return match.groups() if match else (None, None)


class UserRoleFieldsTests(unittest.TestCase):
    def setUp(self):
        import main

        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine)
        session = self.Session()
        session.add(CitizenshipRegime(id=1, code="rf", name="РФ"))
        session.add(Country(id=1, name="Россия", regime_id=1, is_active=True))
        session.add(User(id=1, employee_name="Админ", phone="70000000001", password_hash="x", role="superadmin",
                         is_admin=True))
        session.add(User(id=10, employee_name="Альфа ТМ", phone="70000000010", password_hash="x", role="tm"))
        # ТМ с хвостами старого импорта: свой ТМ, должность, дата рождения, пол, магазин.
        session.add(User(id=11, employee_name="Бета ТМ", phone="70000000011", password_hash="x", role="tm",
                         tm_id=10, job_title="ПЕКАРНЯ", birth_date=datetime.date(1990, 5, 1), gender="f",
                         brigadier_store="Лента-1"))
        session.add(User(id=20, employee_name="Иванов Иван", role="employee", tm_id=10, job_title="РТЗ",
                         birth_date=datetime.date(2000, 1, 2), gender="m"))
        session.add(User(id=21, employee_name="Петров Бригадир", role="brigadier", tm_id=10,
                         brigadier_store="Лента-318"))
        session.commit()
        session.close()

        def override_db():
            db = self.Session()
            try:
                yield db
            finally:
                db.close()

        def override_user(request: Request):
            request.state.user = SUPERADMIN
            return SUPERADMIN

        self.app = main.app
        self.app.dependency_overrides[get_db] = override_db
        self.app.dependency_overrides[current_user] = override_user
        self.client = TestClient(self.app)

    def tearDown(self):
        self.app.dependency_overrides.pop(get_db, None)
        self.app.dependency_overrides.pop(current_user, None)

    def _user(self, user_id):
        return self.Session().query(User).filter(User.id == user_id).first()

    def test_tm_card_without_line_fields(self):
        card = _card(self.client.get("/admin/users").text, 11)
        summary = card[:card.index("form-block")]
        for label in ("Должность:", "Дата рождения:", "Пол:", "ТМ:", "Магазин бригадира:"):
            with self.subTest(label=label):
                self.assertNotIn(label, summary)
        # В форме правки — есть (для смены роли без перезагрузки), но скрыты и выключены.
        for name in ("job_title", "birth_date", "gender", "tm_id", "brigadier_store"):
            with self.subTest(name=name):
                block, field = _field_block(card, name)
                self.assertIsNotNone(block, name)
                self.assertIn(" hidden", block)
                self.assertIn(" disabled", field)
        self.assertIn('<select name="role" data-role-select>', card)

    def test_employee_card_with_line_fields(self):
        card = _card(self.client.get("/admin/users").text, 20)
        self.assertIn("Должность: <b>РТЗ</b>", card)
        for name in ("job_title", "birth_date", "gender", "tm_id"):
            with self.subTest(name=name):
                block, field = _field_block(card, name)
                self.assertNotIn(" hidden", block)
                self.assertNotIn(" disabled", field)
                self.assertIn('data-role-fields="employee brigadier"', block)
        block, field = _field_block(card, "brigadier_store")
        self.assertIn(" hidden", block)
        self.assertIn('<option value="m" selected>мужской</option>', card)

    def test_brigadier_card_has_store_and_line_fields(self):
        card = _card(self.client.get("/admin/users").text, 21)
        self.assertIn("Магазин бригадира: <b>Лента-318</b>", card)
        for name in ("brigadier_store", "job_title", "tm_id"):
            with self.subTest(name=name):
                block, _ = _field_block(card, name)
                self.assertNotIn(" hidden", block)

    def test_read_only_card_tm_empty_for_office_roles(self):
        # Просмотр без users.manage: строка «ТМ:» — только у линейного персонала.
        viewer = SimpleNamespace(id=5, role="economist", is_admin=False, employee_name="Эконом", phone="7",
                                 economist_stores="", brigadier_store=None)

        def override_user(request: Request):
            request.state.user = viewer
            return viewer

        self.app.dependency_overrides[current_user] = override_user
        html = self.client.get("/admin/users").text
        self.assertNotIn("ТМ:", _card(html, 11))
        self.assertIn("ТМ: <b>Альфа ТМ</b>", _card(html, 20))

    def test_saving_tm_keeps_old_line_fields(self):
        # Форма ТМ: скрытые поля выключены и не приходят; даже если пришли — не трогаем.
        for data in ({}, {"tm_id": "0", "job_title": "", "birth_date": "", "gender": "", "brigadier_store": ""}):
            with self.subTest(data=data):
                response = self.client.post("/admin/update-user", data={
                    "user_id": 11, "role": "tm", "citizenship_country_id": "1", **data}, follow_redirects=False)
                self.assertEqual(response.status_code, 302)
                user = self._user(11)
                self.assertEqual(user.tm_id, 10)
                self.assertEqual(user.job_title, "ПЕКАРНЯ")
                self.assertEqual(user.birth_date, datetime.date(1990, 5, 1))
                self.assertEqual(user.gender, "f")
                self.assertEqual(user.brigadier_store, "Лента-1")

    def test_saving_employee_updates_line_fields(self):
        response = self.client.post("/admin/update-user", data={
            "user_id": 20, "role": "employee", "citizenship_country_id": "1", "tm_id": "11",
            "job_title": "ПУ", "birth_date": "2001-03-04", "gender": "f", "brigadier_store": "Лента-9"},
            follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        user = self._user(20)
        self.assertEqual((user.tm_id, user.job_title, user.birth_date, user.gender),
                         (11, "ПУ", datetime.date(2001, 3, 4), "f"))
        self.assertIsNone(user.brigadier_store)  # магазин — только бригадиру

    def test_create_form_and_submit(self):
        html = self.client.get("/admin/create-user").text
        self.assertIn('<select name="role" id="role-select" data-role-select>', html)
        for name in ("job_title", "tm_id", "birth_date", "gender"):
            with self.subTest(name=name):
                block, _ = _field_block(html, name)
                self.assertIn('data-role-fields="employee brigadier"', block)
        block, field = _field_block(html, "brigadier_store")
        self.assertIn('data-role-fields="brigadier" hidden', block)
        common = {"citizenship_country_id": "1", "tm_id": "10", "job_title": "ОПРР", "birth_date": "1999-09-09",
                  "gender": "m", "brigadier_store": "Лента-5"}
        self.client.post("/admin/create-user", data={**common, "employee_name": "Новый Сотрудник", "role": "employee"})
        self.client.post("/admin/create-user", data={**common, "employee_name": "Новый Экономист", "role": "economist"})
        session = self.Session()
        employee = session.query(User).filter(User.employee_name == "Новый Сотрудник").one()
        self.assertEqual((employee.tm_id, employee.job_title, employee.gender), (10, "ОПРР", "m"))
        self.assertIsNone(employee.brigadier_store)
        economist = session.query(User).filter(User.employee_name == "Новый Экономист").one()
        self.assertEqual((economist.tm_id, economist.job_title, economist.birth_date, economist.gender,
                          economist.brigadier_store), (None, None, None, None, None))


# Смена роли в форме — ui.js (initRoleFields) на минимальной модели DOM в node.
NODE_HARNESS = r"""
const fs = require('fs');
function el(tag, attrs) {
  return { tag, attrs: attrs || {}, hidden: false, disabled: false, children: [], listeners: {},
    getAttribute(n) { return this.attrs[n]; },
    addEventListener(t, f) { this.listeners[t] = f; },
    querySelectorAll(sel) {
      if (sel === '[data-role-fields]') return this.children.filter(c => 'data-role-fields' in c.attrs);
      if (sel === 'input, select, textarea') return this.children;
      return [];
    } };
}
const form = el('form');
const blocks = {};
for (const [key, roles] of Object.entries(JSON.parse(process.argv[1]))) {
  const block = el('div', { 'data-role-fields': roles });
  block.children.push(el('input'));
  blocks[key] = block; form.children.push(block);
}
const select = el('select'); select.form = form; select.value = process.argv[2];
const noop = () => {};
const stub = () => ({ classList: { add: noop, remove: noop, toggle: noop, contains: () => false }, style: {},
  setAttribute: noop, appendChild: noop, addEventListener: noop, querySelectorAll: () => [], querySelector: () => null });
global.window = { matchMedia: () => ({ matches: true, addEventListener: noop }), addEventListener: noop };
global.sessionStorage = { getItem: noop, setItem: noop };
global.document = { readyState: 'complete', body: stub(), documentElement: stub(), addEventListener: noop,
  createElement: stub, getElementById: () => null, querySelector: () => null,
  querySelectorAll: sel => sel === 'select[data-role-select]' ? [select] : [] };
global.IntersectionObserver = function () { return { observe: noop }; };
eval(fs.readFileSync(process.argv[3], 'utf8'));
const state = () => Object.fromEntries(Object.entries(blocks).map(([k, b]) => [k, !b.hidden && !b.children[0].disabled]));
const out = [state()];
for (const role of process.argv.slice(4)) { select.value = role; select.listeners.change(); out.push(state()); }
console.log(JSON.stringify(out));
"""


@unittest.skipUnless(shutil.which("node"), "нужен node")
class RoleFieldsJsTests(unittest.TestCase):
    def test_role_change_toggles_fields(self):
        blocks = {"line": "employee brigadier", "store": "brigadier", "cities": "economist tm"}
        result = subprocess.run(["node", "-e", NODE_HARNESS, json.dumps(blocks), "employee", UI_JS,
                                 "tm", "brigadier", "economist", "employee"],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [
            {"line": True, "store": False, "cities": False},   # сотрудник
            {"line": False, "store": False, "cities": True},   # → ТМ
            {"line": True, "store": True, "cities": False},    # → бригадир
            {"line": False, "store": False, "cities": True},   # → экономист
            {"line": True, "store": False, "cities": False},   # → снова сотрудник
        ])


if __name__ == "__main__":
    unittest.main()

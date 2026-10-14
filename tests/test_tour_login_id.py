"""П5: флаг «тур закрыт до следующего входа» привязан ко входу (login_id в серверной сессии), а не к
вкладке. Режим always: пройти тур → перезагрузка — не стартует; выход и вход в той же вкладке — стартует."""

import json
import os
import re
import shutil
import subprocess
import unittest
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from sqlalchemy.orm import sessionmaker

from models import User
from test_demo_tours_p5 import seed
from test_payouts import _engine
from test_predemo_p411 import _Client
from utils import get_password_hash

TOUR_JS = os.path.join(os.path.dirname(__file__), "..", "static", "tour.js")


class LoginIdTests(_Client):
    seed = staticmethod(seed)

    def make_session(self):
        return sessionmaker(bind=_engine())

    def setUp(self):
        super().setUp()
        db = self.Session()
        db.get(User, 30).password_hash = get_password_hash("demo123")
        db.commit()
        self._as(30)

    def _login_and_config(self):
        response = self.client.post("/login", data={"phone": "70000000030", "password": "demo123"},
                                    follow_redirects=False)
        self.assertEqual(response.headers["location"], "/hr")
        with patch.dict(os.environ, {"TOUR_AUTOSTART": "always"}):
            html = self.client.get("/hr").text
        return json.loads(re.search(r"window\.WS_TOUR = (\{.*?\});", html).group(1))

    def test_each_login_gets_new_login_id(self):
        first = self._login_and_config()
        self.assertRegex(first["login_id"], r"^[0-9a-f]{32}$")
        self.assertTrue(first["autostart"])
        with patch.dict(os.environ, {"TOUR_AUTOSTART": "always"}):
            again = json.loads(re.search(r"window\.WS_TOUR = (\{.*?\});", self.client.get("/hr").text).group(1))
        self.assertEqual(again["login_id"], first["login_id"])  # тот же вход — тот же ключ
        self.client.get("/logout", follow_redirects=False)
        second = self._login_and_config()
        self.assertNotEqual(second["login_id"], first["login_id"])

    def test_login_page_clears_tour_keys(self):
        self.app.dependency_overrides.pop(self.current_user, None)
        html = self.client.get("/login").text
        self.assertIn("k.indexOf('ws-tour') === 0", html)


# Движок тура в node: заглушки DOM и fetch, общий sessionStorage на все «страницы» одной вкладки.
HARNESS = r"""
const fs = require('fs');
const src = fs.readFileSync(process.argv[1], 'utf8');
const store = {};
global.sessionStorage = {
  getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); },
  removeItem: k => { delete store[k]; }, key: i => Object.keys(store)[i], get length() { return Object.keys(store).length; },
};
const TOUR = { id: 'hr_lead', version: 1, start_url: '/hr', steps: [
  { type: 'screen', title: 'Первый', body: 'a' }, { type: 'screen', title: 'Второй', body: 'b' }] };
let calls, listeners, body;
function node(tag) {
  return { tag, children: [], attrs: {}, listeners: {}, classList: { add() {}, remove() {} }, style: {},
    set textContent(v) { this._text = v; }, get textContent() { return this._text || ''; },
    setAttribute(k, v) { this.attrs[k] = v; }, appendChild(c) { this.children.push(c); c.parent = this; return c; },
    insertBefore(c) { this.children.push(c); return c; }, addEventListener(t, f) { this.listeners[t] = f; },
    remove() { if (this.parent) this.parent.children = this.parent.children.filter(c => c !== this); },
    focus() {}, contains() { return true; },
    all() { return [this].concat(...this.children.map(c => c.all())); },
    querySelector(sel) { return this.all().find(n => n !== this && sel === '[data-tour-next]' && 'data-tour-next' in n.attrs) || null; },
    querySelectorAll(sel) { return this.all().filter(n => n !== this && n.tag === sel); } };
}
async function page(cfg, path) {
  calls = []; listeners = {}; body = node('body');
  global.location = { href: 'http://x' + path };
  global.history = { replaceState() {} };
  global.window = { WS_TOUR: cfg, matchMedia: () => ({ matches: false }), addEventListener() {}, removeEventListener() {} };
  global.document = { readyState: 'complete', body, createElement: node, querySelectorAll: () => [],
    addEventListener: (t, f) => { listeners[t] = f; }, removeEventListener() {}, activeElement: null };
  global.fetch = (url, opts) => { calls.push((opts && opts.method || 'GET') + ' ' + url);
    return Promise.resolve({ ok: true, json: () => Promise.resolve(JSON.parse(JSON.stringify(TOUR))) }); };
  eval(src);
  await new Promise(r => setTimeout(r, 0));
  const title = body.all().find(n => n.tag === 'h2');
  return { shown: title ? title.textContent : null, next: () => body.all().find(n => 'data-tour-next' in n.attrs).listeners.click() };
}
const cfg = login => ({ id: 'hr_lead', mode: 'always', start_url: '/hr', autostart: true, force: false, login_id: login });
(async () => {
  const out = {};
  let p = await page(cfg('A'), '/hr');                 // вход A — тур стартует
  out.first = p.shown;
  p.next(); await new Promise(r => setTimeout(r, 0));
  p = { next: null }; const second = body.all().find(n => n.tag === 'h2').textContent;
  body.all().find(n => 'data-tour-next' in n.attrs).listeners.click();  // «Готово» — тур пройден
  out.second = second; out.seenPosted = calls.includes('POST /tour/seen');
  out.closedKeys = Object.keys(store).filter(k => k.startsWith('ws-tour-closed'));
  out.reload = (await page(cfg('A'), '/hr')).shown;    // перезагрузка того же входа — не стартует
  out.relogin = (await page(cfg('B'), '/hr')).shown;   // выход и вход в той же вкладке — стартует
  out.closedAfterRelogin = Object.keys(store).filter(k => k.startsWith('ws-tour-closed'));
  // тур, брошенный на середине, после нового входа начинается сначала, а не со второго шага
  let c = await page(cfg('C'), '/hr?tour=1'); c.next(); await new Promise(r => setTimeout(r, 0));
  out.midState = JSON.parse(store['ws-tour']).step;
  out.afterMid = (await page(cfg('D'), '/hr')).shown;
  out.stateLogin = JSON.parse(store['ws-tour']).loginId;
  console.log(JSON.stringify(out));
})();
"""


@unittest.skipUnless(shutil.which("node"), "нужен node")
class TourEngineLoginTests(unittest.TestCase):
    def test_always_mode_restarts_after_relogin_not_after_reload(self):
        result = subprocess.run(["node", "-e", HARNESS, TOUR_JS], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        out = json.loads(result.stdout)
        self.assertEqual((out["first"], out["second"]), ("Первый", "Второй"))
        self.assertTrue(out["seenPosted"])
        self.assertEqual(out["closedKeys"], ["ws-tour-closed:hr_lead:A"])
        self.assertIsNone(out["reload"])
        self.assertEqual(out["relogin"], "Первый")
        self.assertEqual(out["closedAfterRelogin"], [])  # флаг прошлого входа удалён
        self.assertEqual(out["midState"], 1)
        self.assertEqual(out["afterMid"], "Первый")
        self.assertEqual(out["stateLogin"], "D")


if __name__ == "__main__":
    unittest.main()

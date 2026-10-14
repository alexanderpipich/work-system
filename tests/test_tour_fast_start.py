"""П5, правки тура: (1) tour.js стартует сразу (в начале body, без defer) — шаг element ждёт появления
якоря, пока страница догружается, документ разобран без якоря — шаг пропускается; (2) /tour/data
показывает руководителю, какие TOUR_* видит приложение и найден ли демо-сотрудник."""

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

from test_demo_tours_p5 import seed
from test_payouts import A, _engine
from test_predemo_p411 import _Client
from tours import tour_settings

TOUR_JS = os.path.join(os.path.dirname(__file__), "..", "static", "tour.js")


class TourPageTests(_Client):
    seed = staticmethod(seed)

    def make_session(self):
        return sessionmaker(bind=_engine())

    def test_script_at_body_start_without_defer(self):
        self._as(30)
        html = self.client.get("/hr").text
        script = re.search(r'<script src="/static/tour\.js\?v=\d+"( defer)?></script>', html)
        self.assertIsNotNone(script)
        self.assertIsNone(script.group(1))
        body = html.index("<body")
        self.assertLess(body, html.index("window.WS_TOUR"))
        self.assertLess(script.start(), html.index('class="topbar'))  # до шапки и таблиц

    def test_settings_in_tour_data(self):
        self._as(30)
        with patch.dict(os.environ, {"TOUR_AUTOSTART": "always", "TOUR_DEMO_EMPLOYEE": A}):
            settings = self.client.get("/tour/data").json()["settings"]
        self.assertEqual(settings, {"TOUR_AUTOSTART": "always", "autostart": "always",
                                    "TOUR_DEMO_EMPLOYEE": A, "demo_employee_found": True})
        with patch.dict(os.environ, {"TOUR_AUTOSTART": "", "TOUR_DEMO_EMPLOYEE": "Нет Такого"}):
            settings = self.client.get("/tour/data").json()["settings"]
        self.assertEqual((settings["autostart"], settings["demo_employee_found"]), ("first", False))
        self._as(1)  # сотруднику — без настроек и чужих ФИО
        self.assertNotIn("settings", self.client.get("/tour/data").json())

    def test_settings_without_env(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("TOUR_")}
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(tour_settings(), {"TOUR_AUTOSTART": None, "autostart": "first",
                                               "TOUR_DEMO_EMPLOYEE": None})


# Страница «грузится»: readyState = loading, якорь приходит позже (MutationObserver), DOMContentLoaded — вручную.
HARNESS = r"""
const fs = require('fs');
const src = fs.readFileSync(process.argv[1], 'utf8');
const store = {};
global.sessionStorage = {
  getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); },
  removeItem: k => { delete store[k]; }, key: i => Object.keys(store)[i], get length() { return Object.keys(store).length; },
};
const TOUR = { id: 'hr_lead', version: 1, start_url: '/hr', steps: [
  { type: 'screen', title: 'Обложка', body: 'a' },
  { type: 'element', anchor: 'late', placement: 'bottom', title: 'Поздний', body: 'b' },
  { type: 'element', anchor: 'never', placement: 'bottom', title: 'Нет такого', body: 'c' },
  { type: 'screen', title: 'Финал', body: 'd' }] };
function node(tag) {
  return { tag, children: [], attrs: {}, listeners: {}, classList: { add() {}, remove() {} }, style: {},
    offsetWidth: 300, offsetHeight: 200,
    set textContent(v) { this._text = v; }, get textContent() { return this._text || ''; },
    setAttribute(k, v) { this.attrs[k] = v; }, appendChild(c) { this.children.push(c); c.parent = this; return c; },
    insertBefore(c) { this.children.push(c); c.parent = this; return c; }, addEventListener(t, f) { this.listeners[t] = f; },
    remove() { if (this.parent) this.parent.children = this.parent.children.filter(c => c !== this); },
    focus() {}, contains() { return true; }, scrollIntoView() {},
    getClientRects() { return [1]; }, getBoundingClientRect() { return { top: 100, left: 10, bottom: 140, right: 300 }; },
    all() { return [this].concat(...this.children.map(c => c.all())); },
    querySelector(sel) { return this.all().find(n => n !== this && sel === '[data-tour-next]' && 'data-tour-next' in n.attrs) || null; },
    querySelectorAll(sel) { return this.all().filter(n => n !== this && n.tag === sel); } };
}
const anchors = {}, observers = [], docListeners = {}, delays = [];
const body = node('body');
global.location = { href: 'http://x/hr?tour=1' };
global.history = { replaceState() {} };
global.window = { WS_TOUR: { id: 'hr_lead', mode: 'off', start_url: '/hr', autostart: false, force: true, login_id: 'L' },
  matchMedia: () => ({ matches: false }), addEventListener() {}, removeEventListener() {}, innerHeight: 800, scrollBy() {} };
global.getComputedStyle = () => ({ position: 'static' });
global.requestAnimationFrame = f => setTimeout(f, 0);
global.cancelAnimationFrame = id => clearTimeout(id);
const realTimeout = setTimeout;
global.setTimeout = (f, ms) => { if (ms) delays.push(ms); return realTimeout(f, ms > 1000 ? 10 ** 7 : ms); };
global.MutationObserver = function (cb) { this.cb = cb; this.on = false; observers.push(this); };
MutationObserver.prototype.observe = function () { this.on = true; };
MutationObserver.prototype.disconnect = function () { this.on = false; };
global.document = { readyState: 'loading', body, documentElement: { clientWidth: 1200 }, createElement: node,
  querySelectorAll: sel => { const m = /data-tour="([^"]+)"/.exec(sel); return m && anchors[m[1]] ? [anchors[m[1]]] : []; },
  addEventListener: (t, f) => { (docListeners[t] = docListeners[t] || []).push(f); },
  removeEventListener: (t, f) => { docListeners[t] = (docListeners[t] || []).filter(g => g !== f); }, activeElement: null };
global.fetch = () => Promise.resolve({ ok: true, json: () => Promise.resolve(JSON.parse(JSON.stringify(TOUR))) });
const tick = () => new Promise(r => realTimeout(r, 5));
const shown = () => { const t = body.all().find(n => n.tag === 'h2'); return t ? t.textContent : null; };
const next = () => body.all().find(n => 'data-tour-next' in n.attrs).listeners.click();
(async () => {
  const out = {};
  eval(src);
  await tick();
  out.screenWhileLoading = shown();         // screen — сразу, документ ещё грузится
  next(); await tick();
  out.waiting = shown();                     // якоря ещё нет — карточки нет, ждём
  out.observing = observers.some(o => o.on);
  out.timeout = delays.includes(20000);
  anchors.late = node('div');                // пришла таблица
  observers.filter(o => o.on).forEach(o => o.cb([])); await tick();
  out.afterAnchor = shown();
  next(); await tick();
  out.waitingNever = shown();
  document.readyState = 'interactive';       // документ разобран — якоря «never» так и нет
  (docListeners.DOMContentLoaded || []).slice().forEach(f => f()); await tick();
  out.afterParsed = shown();
  out.skipped = JSON.parse(store['ws-tour']).skipped;
  out.count = body.all().find(n => n.tag === 'span' && /\//.test(n.textContent)).textContent;
  console.log(JSON.stringify(out));
  process.exit(0);
})();
"""


@unittest.skipUnless(shutil.which("node"), "нужен node")
class TourEngineFastStartTests(unittest.TestCase):
    def test_element_step_waits_for_anchor_while_loading(self):
        result = subprocess.run(["node", "-e", HARNESS, TOUR_JS], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        out = json.loads(result.stdout)
        self.assertEqual(out["screenWhileLoading"], "Обложка")
        self.assertIsNone(out["waiting"])
        self.assertTrue(out["observing"])
        self.assertTrue(out["timeout"])
        self.assertEqual(out["afterAnchor"], "Поздний")
        self.assertIsNone(out["waitingNever"])
        self.assertEqual(out["afterParsed"], "Финал")
        self.assertEqual(out["skipped"], [2])
        self.assertEqual(out["count"], "3 / 3")


if __name__ == "__main__":
    unittest.main()

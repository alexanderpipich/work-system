"""П5: настройки демо-тура в базе (страница /admin/tour-settings, только суперадмин) вместо
переменных окружения: режим для всех, демо-сотрудник, режим лично пользователю, «показать снова»."""

import json
import os
import re
import unittest
from datetime import datetime
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from sqlalchemy.orm import sessionmaker

from models import AuditLog, TourSettings, User
from navigation import build_navigation
from test_demo_tours_p5 import seed
from test_payouts import A, _engine
from test_predemo_p411 import _Client
from utils import get_password_hash

URL = "/admin/tour-settings"
NO_ENV = {"TOUR_AUTOSTART": "", "TOUR_DEMO_EMPLOYEE": ""}


class TourSettingsTests(_Client):
    seed = staticmethod(seed)

    def make_session(self):
        return sessionmaker(bind=_engine())

    def setUp(self):
        super().setUp()
        self._env = patch.dict(os.environ, NO_ENV)
        self._env.start()
        db = self.Session()
        for user_id in (1, 30):
            db.get(User, user_id).password_hash = get_password_hash("demo123")
        db.commit()
        self._as(40)  # суперадмин

    def tearDown(self):
        self._env.stop()
        super().tearDown()

    def _save(self, **data):
        return self.client.post(URL, data=data, follow_redirects=False)

    def _user_mode(self, **data):
        return self.client.post(URL + "/user", data=data, follow_redirects=False)

    def _login(self, phone):
        """Настоящий вход: current_user кладёт настройки тура в request.state."""
        self.app.dependency_overrides.pop(self.current_user, None)
        self.client.get("/logout", follow_redirects=False)
        response = self.client.post("/login", data={"phone": phone, "password": "demo123"}, follow_redirects=False)
        return response.headers["location"]

    def _config(self, path):
        html = self.client.get(path).text
        return json.loads(re.search(r"window\.WS_TOUR = (\{.*?\});", html).group(1))

    def test_page_superadmin_only(self):
        html = self.client.get(URL).text
        self.assertIn("Для всех", html)
        self.assertIn("Петрова HR", html)  # руководители в списке всегда
        self._as(30)
        self.assertNotEqual(self.client.get(URL, follow_redirects=False).status_code, 200)
        self._save(autostart_mode="off")  # руководителю сохранить нельзя
        self.assertIsNone(self.Session().query(TourSettings).first())
        self.assertTrue(self.Session().query(AuditLog).filter(AuditLog.action == "permission_denied",
                                                              AuditLog.entity_name == "tour.manage").count())

    def test_nav_card_only_for_superadmin(self):
        db = self.Session()
        def keys(user):
            return {card["key"] for group in build_navigation(user) for card in group["cards"]}
        self.assertIn("tour", keys(db.get(User, 40)))
        self.assertNotIn("tour", keys(db.get(User, 30)))

    def test_global_mode_and_demo_saved(self):
        self.assertEqual(self._save(autostart_mode="always", demo_employee="  абрамов   антон ").status_code, 302)
        row = self.Session().query(TourSettings).one()
        self.assertEqual((row.autostart_mode, row.demo_employee, row.updated_by), ("always", A, 40))
        log = self.Session().query(AuditLog).filter(AuditLog.action == "tour.settings").one()
        self.assertIn(A, log.new_value)
        html = self.client.get(URL).text
        self.assertIn("найден", html)

        self.assertEqual(self._login("70000000030"), "/hr")
        self.assertTrue(self._config("/hr")["autostart"])  # переменных нет — режим из базы
        data = self.client.get("/tour/data").json()
        self.assertEqual(len([s for s in data["steps"] if s["type"] != "navigate"]), 27)
        self.assertEqual(data["settings"]["source"], {"autostart": "настройки", "demo_employee": "настройки"})
        self.assertTrue(data["settings"]["demo_employee_found"])
        self.client.post("/tour/seen")
        self.assertTrue(self._config("/hr")["autostart"])  # always: и после «Готово» — на следующем входе
        # сотрудник — тот же общий режим
        self.assertEqual(self._login("70000000001"), "/cabinet")
        self.assertEqual(self._config("/cabinet")["mode"], "always")

    def test_settings_beat_env(self):
        self._save(autostart_mode="off")
        with patch.dict(os.environ, {"TOUR_AUTOSTART": "always"}):
            self._login("70000000030")
            config = self._config("/hr")
        self.assertEqual((config["mode"], config["autostart"]), ("off", False))

    def test_empty_falls_back_to_env(self):
        self._save(autostart_mode="", demo_employee="")
        with patch.dict(os.environ, {"TOUR_AUTOSTART": "always", "TOUR_DEMO_EMPLOYEE": A}):
            self._login("70000000030")
            self.assertEqual(self._config("/hr")["mode"], "always")
            data = self.client.get("/tour/data").json()
        self.assertEqual(data["settings"]["source"], {"autostart": "переменная", "demo_employee": "переменная"})

    def test_unknown_demo_employee_rejected(self):
        response = self._save(autostart_mode="always", demo_employee="Нет Такого")
        self.assertIn("error=", response.headers["location"])
        self.assertIsNone(self.Session().query(TourSettings).first())

    def test_personal_mode_beats_global(self):
        self._save(autostart_mode="always")
        self.assertEqual(self._user_mode(user_id=30, tour_mode="off").status_code, 302)
        self.assertEqual(self.Session().get(User, 30).tour_mode, "off")
        self.assertIn("Выключен", self.client.get(URL).text)
        # сотрудника добавляют по ФИО или телефону
        self.assertIn("message=", self._user_mode(target="70000000001", tour_mode="first").headers["location"])
        self.assertEqual(self.Session().get(User, 1).tour_mode, "first")
        self.assertIn("error=", self._user_mode(target="Пиунов Андрей", tour_mode="off").headers["location"])  # ТМ — без тура
        self.assertEqual(self.Session().query(AuditLog).filter(AuditLog.action == "tour.user_mode").count(), 2)

        self._login("70000000030")
        self.assertEqual(self._config("/hr")["mode"], "off")
        self._login("70000000001")
        self.assertEqual(self._config("/cabinet")["mode"], "first")

        self._as(40)
        self._user_mode(user_id=30, tour_mode="")  # «как у всех»
        self.assertIsNone(self.Session().get(User, 30).tour_mode)

    def test_show_again_resets_seen(self):
        db = self.Session()
        db.get(User, 30).tour_seen_at = datetime(2026, 10, 14, 12, 0)
        db.commit()
        self.assertIn("Показать снова", self.client.get(URL).text)
        self._user_mode(user_id=30, tour_mode="", reset_seen="1")
        self.assertIsNone(self.Session().get(User, 30).tour_seen_at)
        self._login("70000000030")
        self.assertTrue(self._config("/hr")["autostart"])  # режим first — тур снова сам


if __name__ == "__main__":
    unittest.main()

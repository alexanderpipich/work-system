"""Юрлицо по умолчанию для бланков (договор, ходатайство, рекомендация): флаг LegalEntity.is_default,
чекбокс на /admin/legal-entities (только у одного юрлица), порядок в contract_data.default_legal_entity."""

import os
import re
import unittest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from contract_data import default_legal_entity
from employee_profile import employee_profile
from models import AuditLog, LegalEntity, User
from test_documents_contracts import _session, seed as seed_contracts
from test_predemo_p411 import _Client

DEFAULT = "ООО «Альянс»"
OTHER = "ООО «Балтийский Дом»"


def seed(session):
    seed_contracts(session)  # «ООО «Новая»» — у сотрудника 1 в профиле
    session.add_all([
        LegalEntity(name=OTHER, full_name="Общество с ограниченной ответственностью «Балтийский Дом»", is_active=True),
        LegalEntity(name=DEFAULT, full_name="Общество с ограниченной ответственностью Управляющая компания «Альянс»",
                    is_active=True, is_default=True),
    ])
    session.commit()


class DefaultLegalEntityTests(_Client):
    seed = staticmethod(seed)

    def make_session(self):
        return _session()

    def setUp(self):
        super().setUp()
        self._as(30)  # руководитель: contracts.manage и legal_entities.manage

    def _entity(self, name):
        return self.Session().query(LegalEntity).filter(LegalEntity.name == name).one()

    def _clear_profile_entity(self):
        db = self.Session()
        db.get(User, 1).legal_entity = None
        db.commit()

    def _selected(self, html):
        select = re.search(r'<select name="legal_entity_id"[^>]*>(.*?)</select>', html, re.S).group(1)
        options = re.findall(r'<option value="(\d+)" ?(selected)?>([^<]*)</option>', select)
        return options, [name for _, sel, name in options if sel]

    def test_default_selected_in_contract_and_recommendation(self):
        self._clear_profile_entity()
        default_id = self._entity(DEFAULT).id
        for kind in ("contract", "recommendation"):
            with self.subTest(kind=kind):
                html = self.client.get(f"/admin/contracts/{kind}/1").text
                options, selected = self._selected(html)
                self.assertEqual(selected, [f"{DEFAULT} — по умолчанию"])
                self.assertEqual(int(options[1][0]), default_id)  # первым после «— выберите —»
                self.assertEqual(len(options), 4)  # «— выберите —» + все три активных
                self.assertIn("Управляющая компания «Альянс»", html)  # реквизиты подставлены

    def test_profile_entity_wins(self):
        html = self.client.get("/admin/contracts/contract/1").text
        _, selected = self._selected(html)
        self.assertEqual(selected, ["ООО «Новая»"])

    def test_order_of_fallbacks(self):
        db = self.Session()
        user = db.get(User, 1)
        user.legal_entity = None
        db.commit()
        profile = employee_profile(db, user)
        self.assertEqual(default_legal_entity(db, profile).name, DEFAULT)
        # неактивное юрлицо по умолчанию не подставляется; активных несколько → пусто
        db.query(LegalEntity).filter(LegalEntity.name == DEFAULT).one().is_active = False
        db.commit()
        self.assertIsNone(default_legal_entity(db, profile))
        # единственное активное — берётся оно
        db.query(LegalEntity).filter(LegalEntity.name == OTHER).one().is_active = False
        db.commit()
        self.assertEqual(default_legal_entity(db, profile).name, "ООО «Новая»")

    def test_manual_choice_kept(self):
        self._clear_profile_entity()
        other_id = self._entity(OTHER).id
        html = self.client.post("/admin/contracts/contract/1", data={
            "legal_entity_id": str(other_id), "action": "check"}).text
        _, selected = self._selected(html)
        self.assertEqual(selected, [OTHER])

    def _update(self, entity, is_default):
        data = {"entity_id": entity.id, "name": entity.name, "is_active": "1"}
        if is_default:
            data["is_default"] = "1"
        return self.client.post("/admin/legal-entities/update", data=data, follow_redirects=False)

    def test_checkbox_only_one_default(self):
        html = self.client.get("/admin/legal-entities").text
        self.assertEqual(len(re.findall(r'name="is_default" value="1" checked', html)), 1)
        self.assertIn("По умолчанию для документов", html)
        self.assertEqual(self._update(self._entity(OTHER), True).status_code, 302)
        db = self.Session()
        self.assertEqual([e.name for e in db.query(LegalEntity).filter(LegalEntity.is_default == True)], [OTHER])  # noqa: E712
        self.assertTrue(db.query(AuditLog).filter(AuditLog.entity_id == self._entity(DEFAULT).id,
                                                  AuditLog.comment == f"по умолчанию теперь {OTHER}").count())
        self._update(self._entity(OTHER), False)  # флажок снят
        self.assertEqual(self.Session().query(LegalEntity).filter(LegalEntity.is_default == True).count(), 0)  # noqa: E712

    def test_activate_keeps_default(self):
        db = self.Session()
        entity = db.query(LegalEntity).filter(LegalEntity.name == DEFAULT).one()
        entity.is_active = False
        db.commit()
        html = self.client.get("/admin/legal-entities").text
        self.assertIn('<input type="hidden" name="is_default" value="1">', html)  # форма «Активировать»
        self.client.post("/admin/legal-entities/update", data={
            "entity_id": entity.id, "name": entity.name, "is_active": "1", "is_default": "1"})
        entity = self._entity(DEFAULT)
        self.assertTrue(entity.is_active and entity.is_default)


if __name__ == "__main__":
    unittest.main()

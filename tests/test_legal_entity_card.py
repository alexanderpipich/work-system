"""Карточка юрлица /admin/legal-entities: одна форма «основное + реквизиты» с одной кнопкой «Сохранить»,
комментарий не затирается без поля в форме, адресов юрлица в форме нет, подсказки реквизитов
руководителя (static/le_suggest.js) — вычисляемые, принятие по → / Tab."""

import json
import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from models import AuditLog, LegalEntity
from test_documents_contracts import _session, seed
from test_predemo_p411 import _Client

URL = "/admin/legal-entities"
STATIC = Path(__file__).resolve().parent.parent / "static"


class LegalEntityCardTests(_Client):
    seed = staticmethod(seed)

    def make_session(self):
        return _session()

    def setUp(self):
        super().setUp()
        self._as(30)  # руководитель: legal_entities.manage
        db = self.Session()
        entity = db.query(LegalEntity).one()
        entity.comment = "договор с банком до 2027"
        db.commit()
        self.entity_id = entity.id

    def _entity(self):
        return self.Session().query(LegalEntity).one()

    def _save(self, **data):
        form = {"entity_id": self.entity_id, "name": "ООО «Новая»", "short_name": "ООО «Новая»",
                "inn": "7805595716", "is_active": "1"}
        form.update(data)
        return self.client.post(URL + "/update", data=form, follow_redirects=False)

    def test_one_form_with_labels_and_no_removed_fields(self):
        html = self.client.get(URL).text
        card = html[html.index('id="legal-entity-'):html.index("</form>", html.index('id="legal-entity-'))]
        for label in ("Наименование в системе", "Краткое наименование", "ИНН", "Статус",
                      "По умолчанию для документов", "Полное наименование", "ОГРН", "КПП", "Юридический адрес",
                      "Банк", "Расчётный счёт", "БИК", "Корр. счёт", "Должность руководителя (род. падеж)",
                      "Руководитель (им. падеж)", "Руководитель (род. падеж)", "Подпись руководителя"):
            self.assertIn(label, card)
        for name in ("comment", "actual_address", "work_address"):
            self.assertNotIn(f'name="{name}"', html)
        self.assertNotIn("Фактический адрес", html)
        self.assertNotIn("Хацкевич", html)  # статичные примеры из чужого шаблона убраны
        self.assertNotRegex(html, r"legal-entities/\d+/details")  # отдельной формы реквизитов нет
        self.assertEqual(len(re.findall(r'<button form="legal-entity-\d+"[^>]*>Сохранить</button>', html)), 1)
        self.assertEqual(len(re.findall(r"data-suggest-field", card)), 4)
        self.assertIn('name="full_name" rows="2" data-autogrow', card)
        self.assertIn("реквизиты не заполнены", self._without_ogrn_page())

    def _without_ogrn_page(self):
        db = self.Session()
        db.query(LegalEntity).one().ogrn = None
        db.commit()
        return self.client.get(URL).text

    def test_save_without_comment_keeps_comment_and_saves_details(self):
        response = self._save(full_name="Общество с ограниченной ответственностью «Новая-2»",
                              director_name="Владимиров Иван Петрович", director_short="И.П. Владимиров")
        self.assertEqual(response.status_code, 302)
        self.assertIn(f"entity={self.entity_id}", response.headers["location"])
        entity = self._entity()
        self.assertEqual(entity.comment, "договор с банком до 2027")
        self.assertEqual((entity.full_name, entity.director_name, entity.director_short),
                         ("Общество с ограниченной ответственностью «Новая-2»", "Владимиров Иван Петрович",
                          "И.П. Владимиров"))
        self.assertEqual(entity.ogrn, "1127847392243")  # поля, которых нет в запросе, не трогаются
        log = self.Session().query(AuditLog).filter(AuditLog.action == "legal_entity_updated").one()
        self.assertEqual(set(json.loads(log.new_value)), {"full_name", "director_name", "director_short"})

    def test_comment_still_saved_when_sent(self):
        self._save(comment="новый")
        self.assertEqual(self._entity().comment, "новый")

    def test_no_changes_no_audit(self):
        self._save()
        self.assertEqual(self.Session().query(AuditLog).filter(AuditLog.action == "legal_entity_updated").count(), 0)

    def test_saved_card_open(self):
        html = self.client.get(f"{URL}?entity={self.entity_id}").text
        self.assertRegex(html, rf'<details class="card le-card" id="le-{self.entity_id}" open>')


SUGGEST_HARNESS = r"""
global.petrovich = require(process.argv[1]);
const s = require(process.argv[2]);
function input(value, suggest, caret) {
    const attrs = suggest === undefined ? {} : {'data-suggest': suggest};
    return {value, selectionStart: caret ?? value.length, selectionEnd: caret ?? value.length,
            getAttribute: (k) => (k in attrs ? attrs[k] : null), dispatched: 0,
            setSelectionRange() {}, dispatchEvent() { this.dispatched++; }};
}
function key(name, shift) { return {key: name, shiftKey: !!shift, prevented: false, preventDefault() { this.prevented = true; }}; }
const out = {};
let el = input('', 'И.П. Владимиров'); let ev = key('ArrowRight');
out.arrow_empty = [s.accept(el, ev), el.value, ev.prevented];
el = input('', undefined); ev = key('ArrowRight');
out.arrow_no_suggest = [s.accept(el, ev), el.value, ev.prevented];
el = input('', 'И.П. Владимиров'); ev = key('Tab');
out.tab_empty = [s.accept(el, ev), el.value];
el = input('В.', 'И.П. Владимиров'); ev = key('Tab');
out.tab_filled = [s.accept(el, ev), el.value, ev.prevented];
el = input('генеральный директор', 'генерального директора'); ev = key('ArrowRight');
out.arrow_at_end = [s.accept(el, ev), el.value];
el = input('генеральный директор', 'генерального директора', 3); ev = key('ArrowRight');
out.arrow_mid = [s.accept(el, ev), el.value, ev.prevented];
el = input('', 'x'); ev = key('a');
out.other_key = [s.accept(el, ev), el.value];
out.signature = s.signature('Владимиров Иван Петрович');
out.genitive = s.toGenitive('Владимиров Иван Петрович');
out.nominative = s.toNominative('Шестака Сергея Николаевича');
out.no_middle = s.toGenitive('Владимиров Иван');
out.titles = [s.titleGenitive('Генеральный директор'), s.titleGenitive('директор'), s.titleGenitive('директор по персоналу')];
out.suggest = s.suggestions({director_name: 'Иванова Мария Сергеевна', director_name_genitive: '', director_short: '', director_title: ''});
out.suggest_empty = s.suggestions({director_name: '', director_name_genitive: '', director_short: '', director_title: ''});
console.log(JSON.stringify(out));
"""


@unittest.skipUnless(shutil.which("node"), "нужен node")
class SuggestJsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run(["node", "-e", SUGGEST_HARNESS, str(STATIC / "vendor" / "petrovich.min.js"),
                                 str(STATIC / "le_suggest.js")], capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr
        cls.out = json.loads(result.stdout)

    def test_arrow_inserts_suggest(self):
        self.assertEqual(self.out["arrow_empty"], [True, "И.П. Владимиров", True])
        self.assertEqual(self.out["arrow_at_end"], [True, "генерального директора"])

    def test_nothing_without_suggest_or_key(self):
        self.assertEqual(self.out["arrow_no_suggest"], [False, "", False])
        self.assertEqual(self.out["arrow_mid"], [False, "генеральный директор", False])  # курсор не в конце
        self.assertEqual(self.out["tab_filled"], [False, "В.", False])  # Tab — только в пустом поле
        self.assertEqual(self.out["other_key"], [False, ""])

    def test_tab_in_empty_field(self):
        self.assertEqual(self.out["tab_empty"], [True, "И.П. Владимиров"])

    def test_computed_values(self):
        self.assertEqual(self.out["signature"], "И.П. Владимиров")
        self.assertEqual(self.out["genitive"], "Владимирова Ивана Петровича")
        self.assertEqual(self.out["nominative"], "Шестак Сергей Николаевич")
        self.assertEqual(self.out["no_middle"], "")  # без отчества petrovich не определит пол — подсказки нет
        self.assertEqual(self.out["titles"], ["генерального директора", "директора", ""])
        self.assertEqual(self.out["suggest"], {"director_name": "", "director_name_genitive": "Ивановой Марии Сергеевны",
                                               "director_short": "М.С. Иванова", "director_title": ""})
        self.assertEqual(set(self.out["suggest_empty"].values()), {""})  # пустая карточка — подсказок нет


if __name__ == "__main__":
    unittest.main()

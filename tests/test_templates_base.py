import os
import re
import unittest

from jinja2 import ChainableUndefined, Environment, FileSystemLoader

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES = os.path.join(ROOT, "templates")
APP_CSS = os.path.join(ROOT, "static", "app.css")

PILOT = ["login.html", "rates.html", "cabinet.html", "admin_dashboard.html"]


def _env():
    return Environment(loader=FileSystemLoader(TEMPLATES), undefined=ChainableUndefined)


class _Request:
    url = "/"
    query_params = {}

    def url_for(self, *args, **kwargs):
        return "/"


def _context():
    return {
        "request": _Request(),
        "user": {"full_name": "Иванов И.И.", "role": "superadmin", "id": 1},
        "admin": {"full_name": "Иванов И.И.", "role": "superadmin", "id": 1},
        "rates": [], "services": [], "formats": [], "stores": [], "employees": [],
        "documents": [], "docs": [], "individual_count": 0, "base_count": 0,
        "layer": "all", "error": None, "message": None,
    }


class TemplatesCompileTests(unittest.TestCase):
    """Все шаблоны обязаны компилироваться — ловит опечатки при переводе волнами на base.html."""

    def test_all_templates_compile(self):
        env = _env()
        names = sorted(n for n in os.listdir(TEMPLATES) if n.endswith(".html"))
        self.assertTrue(names)
        for name in names:
            with self.subTest(template=name):
                env.get_template(name)


class PilotRendersOnBaseTests(unittest.TestCase):
    """Пилотные страницы отрисовываются через base.html и тянут единый app.css."""

    def test_pilot_pages_render_through_base(self):
        env = _env()
        for name in PILOT:
            with self.subTest(template=name):
                html = env.get_template(name).render(**_context())
                self.assertIn("<!DOCTYPE html>", html)
                self.assertIn("/static/app.css", html)
                self.assertNotIn("<style>\n        :root", html)


class PageWidthAlignmentTests(unittest.TestCase):
    """Топбар и quicknav — соседи .page, ширину они берут с body.

    Модификатор, поставленный только на .page, до них не докатывается, и лого уезжает
    от левого края контента. Значит у каждого модификатора должна быть пара body:has().
    """

    def test_every_page_modifier_has_body_rule(self):
        with open(APP_CSS, encoding="utf-8") as f:
            css = f.read()

        modifiers = set(re.findall(r"^\.(page-[a-z0-9-]+)\s*\{[^}]*--page-max", css, re.M))
        self.assertIn("page-wide", modifiers, "разметка ширин в app.css изменилась — тест устарел")

        for mod in sorted(modifiers):
            with self.subTest(modifier=mod):
                self.assertRegex(
                    css, r"body:has\(\.%s\)\s*\{[^}]*--page-max" % re.escape(mod),
                    "у .%s нет парного body:has(...) — шапка не выровняется по контенту" % mod,
                )

    def test_templates_use_only_known_modifiers(self):
        """Каждый page-* класс в шаблонах должен быть объявлен в app.css.

        Ширинные (те, что задают --page-max) обязаны иметь пару body:has(), иначе шапка
        отвяжется от контента. Прочие page-* — обычные утилиты вроде .page-pad-top,
        парного правила им не нужно, но объявленными быть обязаны — иначе опечатка
        в имени класса пройдёт молча.
        """
        with open(APP_CSS, encoding="utf-8") as f:
            css = f.read()

        width_mods = set(re.findall(r"^\.(page-[a-z0-9-]+)\s*\{[^}]*--page-max", css, re.M))
        paired = set(re.findall(r"body:has\(\.(page-[a-z0-9-]+)\)", css))
        declared = set(re.findall(r"\.(page-[a-z0-9-]+)\s*[,{]", css))

        for name in sorted(n for n in os.listdir(TEMPLATES) if n.endswith(".html")):
            with open(os.path.join(TEMPLATES, name), encoding="utf-8") as f:
                used = set(re.findall(r'class="[^"]*\b(page-[a-z0-9-]+)\b', f.read()))
            for mod in sorted(used):
                with self.subTest(template=name, modifier=mod):
                    self.assertIn(mod, declared,
                                  "%s: класс .%s нигде не объявлен в app.css" % (name, mod))
                    if mod in width_mods:
                        self.assertIn(mod, paired,
                                      "%s: у ширинного .%s нет body:has() — шапка уедет"
                                      % (name, mod))


class UiClassesExistInCssTests(unittest.TestCase):
    """Класс, который навешивает ui.js, обязан быть объявлен в app.css.

    Ловит целый класс молчаливых поломок: скрипт исправно добавляет класс,
    ошибок в консоли нет, а на экране ничего не происходит, потому что правила
    для этого класса не существует. Ровно так попап смены без плана не
    открывался — ui.js ставил .open, а .overlay.open в системе не было.
    """

    UI_JS = os.path.join(ROOT, "static", "ui.js")

    # Классы, которыми скрипт не управляет оформлением (служебные хуки).
    IGNORED = {"ripple", "ripple-layer"}

    def test_every_toggled_class_is_styled(self):
        with open(self.UI_JS, encoding="utf-8") as f:
            js = f.read()
        with open(APP_CSS, encoding="utf-8") as f:
            css = f.read()

        used = set(re.findall(r"classList\.(?:add|toggle|remove)\(\s*'([a-z0-9-]+)'", js))
        used |= set(re.findall(r'classList\.(?:add|toggle|remove)\(\s*"([a-z0-9-]+)"', js))
        used -= self.IGNORED
        self.assertTrue(used, "в ui.js не нашлось переключаемых классов — тест устарел")

        for name in sorted(used):
            with self.subTest(css_class=name):
                self.assertRegex(
                    css, r"\.%s\b" % re.escape(name),
                    "ui.js переключает .%s, но в app.css такого правила нет — "
                    "класс навесится, а на экране ничего не изменится" % name,
                )


if __name__ == "__main__":
    unittest.main()

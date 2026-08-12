"""Сверка перевода шаблона на base.html: правки должны быть только представленческими.

Сравнивает мультимножества значимых атрибутов и Jinja-выражений между версией из git
и текущей рабочей. Всё, что несёт логику (поля форм, action, id, data-*, ссылки,
Jinja-выражения), обязано совпасть один в один.

Ожидаемо исчезают только части каркаса, переехавшие в base.html — они в EXPECTED_LOST.

    python tools/check_migration.py                 # все изменённые шаблоны
    python tools/check_migration.py rates.html ...  # выборочно
    python tools/check_migration.py --base HEAD~1   # сравнить с другой ревизией
"""

import argparse
import collections
import re
import subprocess
import sys

PATTERNS = {
    "jinja": r"\{%-?\s*(?P<a>.*?)\s*-?%\}|\{\{\s*(?P<b>.*?)\s*\}\}",
    "name": r'\bname="([^"]*)"',
    "id": r'\bid="([^"]*)"',
    "data": r'\b(data-[a-zA-Z0-9_-]+="[^"]*")',
    # formaction/formmethod НЕ ловятся регекспом \baction= — внутри слова нет границы \b
    "action": r'(?<!form)\baction="([^"]*)"',
    "form_override": r'\b(form(?:action|method|enctype|target|novalidate)="[^"]*")',
    "href": r'\bhref="([^"]*)"',
    "value": r'\bvalue="([^"]*)"',
    "input_type": r'<input\b[^>]*\btype="([^"]*)"',
    "method": r'\bmethod="([^"]*)"',
    # Логика в атрибутах: потеря любого из них молча ломает поведение формы
    "handler": r'\b(on[a-z]+="[^"]*")',
    "enctype": r'\benctype="([^"]*)"',
    "label_for": r'\bfor="([^"]*)"',
    "constraint": r'\b((?:required|checked|selected|multiple|disabled|readonly|novalidate)(?:="[^"]*")?)(?=[\s/>])',
    "limits": r'\b((?:minlength|maxlength|min|max|step|pattern|accept)="[^"]*")',
    "placeholder": r'\bplaceholder="([^"]*)"',
    "span": r'\b((?:colspan|rowspan)="[^"]*")',
    "script_src": r'<script\b[^>]*\bsrc="([^"]*)"',
}

# Каркас, который по замыслу переезжает в base.html
EXPECTED_LOST = {
    "name": {"viewport"},
    "href": {"/static/favicon.ico?v=2", "/static/apple-touch-icon.png?v=2", "/logout"},
    "jinja": set(),
}

# Блоки base.html — их появление в новой версии ожидаемо
BLOCK_RE = re.compile(
    r"^(extends\s|block\s(title|head|body_class|topbar|topbar_class|topbar_actions|"
    r"brand_title|brand_subtitle|before_content|content|scripts)\b|endblock\b)"
)


def git_show(rev, path):
    out = subprocess.run(["git", "show", "%s:%s" % (rev, path)],
                         capture_output=True)
    if out.returncode != 0:
        return None
    return out.stdout.decode("utf-8")


def strip_style(text):
    return re.sub(r"<style\b.*?</style>", "", text, flags=re.S | re.I)


def collect(text, key):
    found = []
    for m in re.finditer(PATTERNS[key], text, flags=re.S):
        if key == "jinja":
            found.append(m.group("a") if m.group("a") is not None else m.group("b"))
        else:
            found.append(m.group(1))
    return collections.Counter(found)


def check(path, old_text, new_text):
    old_text, new_text = strip_style(old_text), strip_style(new_text)
    problems = []
    for key in PATTERNS:
        old, new = collect(old_text, key), collect(new_text, key)
        lost = old - new
        added = new - old

        for item in list(lost):
            if item in EXPECTED_LOST.get(key, set()):
                del lost[item]
        if key == "jinja":
            for item in list(added):
                if BLOCK_RE.match(item):
                    del added[item]

        for item, n in sorted(lost.items()):
            problems.append("  ПОТЕРЯНО  %-11s x%d  %s" % (key, n, item[:160]))
        for item, n in sorted(added.items()):
            problems.append("  ДОБАВЛЕНО %-11s x%d  %s" % (key, n, item[:160]))
    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*", help="имена шаблонов; по умолчанию — изменённые в git")
    ap.add_argument("--base", default="HEAD", help="ревизия для сравнения (по умолчанию HEAD)")
    args = ap.parse_args()

    if args.files:
        paths = ["templates/%s" % f.replace("templates/", "") for f in args.files]
    else:
        out = subprocess.run(["git", "diff", "--name-only", args.base, "--", "templates"],
                             capture_output=True, text=True, encoding="utf-8")
        # base.html — сам каркас, а не переведённая страница; партиал и include-обёртки
        # страницами не являются. Сверять их со «старой версией» бессмысленно.
        skip = {"base.html", "_export_buttons.html",
                "economist_adjustments.html", "economist_reports_dashboard.html"}
        paths = [p for p in out.stdout.split("\n")
                 if p.strip().endswith(".html") and p.split("/")[-1] not in skip]

    if not paths:
        print("нечего сверять")
        return 0

    failed = []
    for path in paths:
        old = git_show(args.base, path)
        if old is None:
            print("%-42s НОВЫЙ ФАЙЛ, сверять не с чем" % path.split("/")[-1])
            continue
        with open(path, encoding="utf-8") as f:
            new = f.read()
        problems = check(path, old, new)
        name = path.split("/")[-1]
        if problems:
            failed.append(name)
            print("%-42s РАСХОЖДЕНИЯ (%d)" % (name, len(problems)))
            for p in problems:
                print(p)
        else:
            print("%-42s ok" % name)

    print("\nитого: %d сверено, %d с расхождениями" % (len(paths), len(failed)))
    if failed:
        print("разобрать: %s" % ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

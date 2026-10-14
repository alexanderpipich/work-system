"""Демо-туры (П5): кабинет сотрудника и рабочий стол руководителя.

Тур — слой поверх существующих страниц: шаги лежат в `data/tours/<id>.json`, движок —
`static/tour.js`, якоря — атрибуты `data-tour="…"` в шаблонах. Сервер решает только,
какой тур положен пользователю, с какой страницы он стартует и запускать ли его сам:

- `employee` → тур `employee` на `/cabinet`; `hr_lead` → тур `hr_lead` на своём дашборде
  (`navigation.dashboard_url`); остальным ролям тура нет;
- `TOUR_AUTOSTART` = `always` (каждый вход; «Пропустить» — до следующего входа, флаг в
  sessionStorage) | `first` (пока пуст `User.tour_seen_at`) | `off`; по умолчанию `first`;
- `?tour=1` на стартовой странице запускает тур с первого шага при любом режиме;
- `TOUR_DEMO_EMPLOYEE` — ФИО демо-сотрудника: подставляется в `{demo_employee}` адресов шагов;
  шаги с `"requires": "demo_employee"` без переменной выбрасываются, `url_demo` заменяет `url`.

`tour_context(request)` — Jinja-глобал для `templates/_tour.html` (как `menu_context`);
в базу не ходит: пользователь — из `request.state.user`.
"""

import json
import os
from pathlib import Path
from urllib.parse import quote

from navigation import dashboard_url
from rbac import ROLE_EMPLOYEE, ROLE_HR_LEAD, canonical_role
from utils import normalize_person_name, normalize_text

TOURS_DIR = Path(__file__).resolve().parent / "data" / "tours"
TOUR_IDS = ("employee", "hr_lead")
AUTOSTART_MODES = ("always", "first", "off")
DEFAULT_AUTOSTART = "first"
STEP_TYPES = ("screen", "element", "navigate")
START = "@start"  # navigate на стартовую страницу тура (у руководителя она зависит от роли)


def autostart_mode():
    mode = (os.getenv("TOUR_AUTOSTART") or "").strip().lower()
    return mode if mode in AUTOSTART_MODES else DEFAULT_AUTOSTART


def demo_employee():
    """ФИО демо-сотрудника тура руководителя (TOUR_DEMO_EMPLOYEE) или ''."""
    return normalize_text(" ".join((os.getenv("TOUR_DEMO_EMPLOYEE") or "").split()))


def load_tour(tour_id):
    if tour_id not in TOUR_IDS:
        return None
    return json.loads((TOURS_DIR / f"{tour_id}.json").read_text(encoding="utf-8"))


def tour_id_for(user):
    role = canonical_role(user) if user is not None else None
    if role == ROLE_EMPLOYEE:
        return "employee"
    if role == ROLE_HR_LEAD:
        return "hr_lead"
    return None


def start_url_for(user, tour_id):
    return "/cabinet" if tour_id == "employee" else dashboard_url(user)


def tour_for_user(user):
    """Тур пользователя со стартовой страницей и разрешёнными `@start`, или None."""
    tour_id = tour_id_for(user)
    if tour_id is None:
        return None
    tour = load_tour(tour_id)
    start = start_url_for(user, tour_id)
    tour["start_url"] = start
    demo = demo_employee()
    steps = []
    for step in tour["steps"]:
        if step.pop("requires", None) == "demo_employee" and not demo:
            continue
        url_demo = step.pop("url_demo", None)
        if url_demo and demo:
            step["url"] = url_demo
        if step["type"] == "navigate":
            step["url"] = start if step["url"] == START else step["url"].replace("{demo_employee}", quote(demo))
        steps.append(step)
    tour["steps"] = steps
    return tour


def build_tour_context(user, path, query_tour=False, mode=None):
    tour_id = tour_id_for(user)
    if tour_id is None:
        return None
    mode = mode or autostart_mode()
    start = start_url_for(user, tour_id)
    on_start = path.rstrip("/") == start.rstrip("/")
    if mode == "always":
        autostart = on_start
    elif mode == "first":
        autostart = on_start and getattr(user, "tour_seen_at", None) is None
    else:
        autostart = False
    return {
        "id": tour_id,
        "mode": mode,
        "start_url": start,
        "help_url": start + "?tour=1",
        "autostart": autostart,
        "force": on_start and query_tour,
        # строка демо-сотрудника на /admin/contracts — якоря шагов «Договор» и «Рекомендация»
        "demo_norm": normalize_person_name(demo_employee()) if tour_id == "hr_lead" and demo_employee() else "",
    }


def tour_context(request):
    if request is None:
        return None
    user = getattr(request.state, "user", None)
    return build_tour_context(user, request.url.path, request.query_params.get("tour") == "1")


def install_tour_globals(modules):
    """`tour_context` во всех окружениях Jinja роутеров (у каждого свой Jinja2Templates)."""
    from fastapi.templating import Jinja2Templates

    for module in modules:
        templates = getattr(module, "templates", None)
        if isinstance(templates, Jinja2Templates):
            templates.env.globals["tour_context"] = tour_context

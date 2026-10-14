"""Демо-туры (П5): кабинет сотрудника и рабочий стол руководителя.

Тур — слой поверх существующих страниц: шаги лежат в `data/tours/<id>.json`, движок —
`static/tour.js`, якоря — атрибуты `data-tour="…"` в шаблонах. Сервер решает только,
какой тур положен пользователю, с какой страницы он стартует и запускать ли его сам:

- `employee` → тур `employee` на `/cabinet`; `hr_lead` → тур `hr_lead` на своём дашборде
  (`navigation.dashboard_url`); остальным ролям тура нет;
- `TOUR_AUTOSTART` = `always` (каждый вход; «Пропустить» — до следующего входа, флаг в
  sessionStorage) | `first` (пока пуст `User.tour_seen_at`) | `off`; по умолчанию `first`;
- `?tour=1` на стартовой странице запускает тур с первого шага при любом режиме.

`tour_context(request)` — Jinja-глобал для `templates/_tour.html` (как `menu_context`);
в базу не ходит: пользователь — из `request.state.user`.
"""

import json
import os
from pathlib import Path

from navigation import dashboard_url
from rbac import ROLE_EMPLOYEE, ROLE_HR_LEAD, canonical_role

TOURS_DIR = Path(__file__).resolve().parent / "data" / "tours"
TOUR_IDS = ("employee", "hr_lead")
AUTOSTART_MODES = ("always", "first", "off")
DEFAULT_AUTOSTART = "first"
STEP_TYPES = ("screen", "element", "navigate")
START = "@start"  # navigate на стартовую страницу тура (у руководителя она зависит от роли)


def autostart_mode():
    mode = (os.getenv("TOUR_AUTOSTART") or "").strip().lower()
    return mode if mode in AUTOSTART_MODES else DEFAULT_AUTOSTART


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
    for step in tour["steps"]:
        if step["type"] == "navigate" and step["url"] == START:
            step["url"] = start
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

"""Демо-туры (П5): кабинет сотрудника, рабочий стол руководителя и кадровика (П5.2).

Тур — слой поверх существующих страниц: шаги лежат в `data/tours/<id>.json`, движок —
`static/tour.js`, якоря — атрибуты `data-tour="…"` в шаблонах. Сервер решает только,
какой тур положен пользователю, с какой страницы он стартует и запускать ли его сам:

- `employee` → тур `employee` на `/cabinet`; `hr_lead` / `hr_clerk` → тур своей роли на своём
  дашборде (`navigation.dashboard_url`); остальным ролям тура нет;
- режим автозапуска: `always` (каждый вход; «Пропустить» — до следующего входа, флаг в
  sessionStorage) | `first` (пока пуст `User.tour_seen_at`) | `off`. Откуда берётся — по порядку:
  `User.tour_mode` (лично для пользователя) → `TourSettings.autostart_mode` (страница
  «Демо-тур», `routers/tour.py`) → переменная `TOUR_AUTOSTART` → `first`;
- `?tour=1` на стартовой странице запускает тур с первого шага при любом режиме;
- демо-сотрудник (`TourSettings.demo_employee`, иначе `TOUR_DEMO_EMPLOYEE`) — ФИО, подставляется
  в `{demo_employee}` адресов шагов; шаги с `"requires": "demo_employee"` без него выбрасываются,
  `url_demo` заменяет `url`.

`tour_context(request)` — Jinja-глобал для `templates/_tour.html` (как `menu_context`);
в базу не ходит: пользователь — из `request.state.user`, настройки — из
`request.state.tour_settings` (их кладёт `dependencies.current_user`, см. `load_settings`).
"""

import json
import os
from pathlib import Path
from urllib.parse import quote

from navigation import dashboard_url
from rbac import ROLE_EMPLOYEE, ROLE_HR_CLERK, ROLE_HR_LEAD, canonical_role
from utils import normalize_person_name, normalize_text

TOURS_DIR = Path(__file__).resolve().parent / "data" / "tours"
TOUR_IDS = ("employee", "hr_lead", "hr_clerk")
# Туры с демо-сотрудником (шаги «requires»: «demo_employee», строка на /admin/contracts).
DEMO_TOURS = ("hr_lead", "hr_clerk")
AUTOSTART_MODES = ("always", "first", "off")
DEFAULT_AUTOSTART = "first"
MODE_LABELS = {"always": "При каждом входе", "first": "Только первый раз", "off": "Выключен"}
STEP_TYPES = ("screen", "element", "navigate")
START = "@start"  # navigate на стартовую страницу тура (у руководителя она зависит от роли)


def _mode(value):
    value = (value or "").strip().lower()
    return value if value in AUTOSTART_MODES else ""


def _name(value):
    return normalize_text(" ".join((value or "").split()))


def autostart_mode():
    """Режим из переменной TOUR_AUTOSTART (запасной вариант, если в настройках пусто)."""
    return _mode(os.getenv("TOUR_AUTOSTART")) or DEFAULT_AUTOSTART


def load_settings(session):
    """Настройки со страницы «Демо-тур» словарём (не ORM-объект: живут дольше сессии) или None."""
    from models import TourSettings

    row = session.query(TourSettings).order_by(TourSettings.id).first()
    if row is None:
        return None
    return {"autostart_mode": _mode(row.autostart_mode), "demo_employee": _name(row.demo_employee)}


def global_mode(settings=None):
    """Режим для всех: настройка на странице, иначе переменная, иначе first."""
    return (settings or {}).get("autostart_mode") or autostart_mode()


def mode_for(user, settings=None):
    """Режим пользователя: личный (User.tour_mode), иначе общий."""
    return _mode(getattr(user, "tour_mode", None)) or global_mode(settings)


def demo_employee(settings=None):
    """ФИО демо-сотрудника туров руководителя и кадровика: настройка на странице, иначе TOUR_DEMO_EMPLOYEE, иначе ''."""
    return (settings or {}).get("demo_employee") or _name(os.getenv("TOUR_DEMO_EMPLOYEE"))


def find_demo_user(session, name):
    """Сотрудник с этим ФИО (сравнение без регистра и е/ё) или None."""
    from models import User

    needle = normalize_person_name(name)
    if not needle:
        return None
    for user in session.query(User).filter(User.employee_name.isnot(None)).all():
        if normalize_person_name(user.employee_name) == needle:
            return user
    return None


def tour_settings(session=None):
    """Что действует сейчас и откуда — для проверки на проде (/tour/data, лог запуска)."""
    settings = load_settings(session) if session is not None else None
    raw = os.getenv("TOUR_AUTOSTART")
    demo = demo_employee(settings)
    result = {
        "TOUR_AUTOSTART": raw if raw is not None else None,
        "autostart": global_mode(settings),
        "TOUR_DEMO_EMPLOYEE": demo or None,
    }
    if session is not None:
        result["source"] = {
            "autostart": "настройки" if (settings or {}).get("autostart_mode") else
                         ("переменная" if _mode(raw) else "по умолчанию"),
            "demo_employee": "настройки" if (settings or {}).get("demo_employee") else
                             ("переменная" if demo else "не задан"),
        }
        if demo:
            result["demo_employee_found"] = find_demo_user(session, demo) is not None
    return result


def log_tour_settings():
    import logging

    try:
        from database import SessionLocal

        session = SessionLocal()
        try:
            report = tour_settings(session)
        finally:
            session.close()
    except Exception:  # лог не должен ронять запуск
        report = tour_settings()
    logging.getLogger("uvicorn.error").info("tour settings: %s", json.dumps(report, ensure_ascii=False))


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
    if role == ROLE_HR_CLERK:
        return "hr_clerk"
    return None


def start_url_for(user, tour_id):
    return "/cabinet" if tour_id == "employee" else dashboard_url(user)


def tour_for_user(user, settings=None):
    """Тур пользователя со стартовой страницей и разрешёнными `@start`, или None."""
    tour_id = tour_id_for(user)
    if tour_id is None:
        return None
    tour = load_tour(tour_id)
    start = start_url_for(user, tour_id)
    tour["start_url"] = start
    demo = demo_employee(settings)
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


def build_tour_context(user, path, query_tour=False, mode=None, login_id="", settings=None):
    tour_id = tour_id_for(user)
    if tour_id is None:
        return None
    mode = mode or mode_for(user, settings)
    start = start_url_for(user, tour_id)
    on_start = path.rstrip("/") == start.rstrip("/")
    if mode == "always":
        autostart = on_start
    elif mode == "first":
        autostart = on_start and getattr(user, "tour_seen_at", None) is None
    else:
        autostart = False
    demo = demo_employee(settings) if tour_id in DEMO_TOURS else ""
    return {
        "id": tour_id,
        "mode": mode,
        "start_url": start,
        "help_url": start + "?tour=1",
        "autostart": autostart,
        "force": on_start and query_tour,
        # ключ флага «закрыт до следующего входа»: новый вход — новый ключ, тур снова стартует
        "login_id": login_id or "",
        # строка демо-сотрудника на /admin/contracts — якоря шагов «Договор», «Ходатайство», «Рекомендация»
        "demo_norm": normalize_person_name(demo) if demo else "",
    }


def tour_context(request):
    if request is None:
        return None
    user = getattr(request.state, "user", None)
    login_id = request.session.get("login_id", "") if "session" in request.scope else ""
    return build_tour_context(user, request.url.path, request.query_params.get("tour") == "1", login_id=login_id,
                              settings=getattr(request.state, "tour_settings", None))


def install_tour_globals(modules):
    """`tour_context` во всех окружениях Jinja роутеров (у каждого свой Jinja2Templates)."""
    from fastapi.templating import Jinja2Templates

    for module in modules:
        templates = getattr(module, "templates", None)
        if isinstance(templates, Jinja2Templates):
            templates.env.globals["tour_context"] = tour_context

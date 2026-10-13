"""Боковое меню на каждой странице офисных ролей (П4.10).

Один источник данных для всех шаблонов, наследующих `base.html`: Jinja-глобал
`menu_context(request)` берёт пользователя из `request.state.user` (его кладёт
`dependencies.current_user`), строит меню из реестра (`navigation.build_menu`) и
кэширует результат на время запроса в `request.state.menu`. Обработчики не правятся.

В базу функция не ходит — только права и реестр, поэтому на каждой странице дёшево.
"""

from urllib.parse import parse_qsl, urlsplit

from navigation import DASHBOARD_PATHS, build_menu, build_navigation, dashboard_url
from rbac import ROLE_EMPLOYEE, canonical_role, has_permission, role_label

# Кабинет сотрудника — без полосы, даже если туда зашла офисная роль.
CABINET_PREFIXES = ("/cabinet", "/employee_docs", "/vacancies", "/support")
NO_MENU_PATHS = {"/login", "/logout"}

_UNSET = object()


def _path_matches(path, prefix):
    prefix = prefix.rstrip("/") or "/"
    return path == prefix or path.startswith(prefix + "/")


def mark_current(menu, path, query=""):
    """Подсветка текущего раздела вне дашборда: подраздел, чей `url` (для этого
    пользователя — он уже такой в build_menu) — самое длинное совпадение с началом
    пути; при равных путях — тот, чьи параметры все есть в запросе (больше — лучше). Его группа
    становится активной. Ничего не нашлось — ничего не подсвечено."""
    params = set(parse_qsl(query))
    best, best_score = None, None
    for group in menu:
        for item in group["items"]:
            if not item["available"]:
                continue
            url = urlsplit(item["url"])
            if not _path_matches(path, url.path):
                continue
            item_params = set(parse_qsl(url.query))
            # Длиннее путь; при равном — параметры подраздела все есть в запросе, и их больше.
            matched = item_params <= params
            score = (len(url.path.rstrip("/")), matched, len(item_params) if matched else -len(item_params))
            if best_score is None or score > best_score:
                best, best_score = (group, item), score
    for group in menu:
        group["active"] = best is not None and group is best[0]
        for item in group["items"]:
            item["current"] = best is not None and item is best[1]
    return best


def quick_links(user, groups):
    """Быстрые кнопки выдвижного меню: те же, что на мобильном дашборде, без плашек
    (плашки считаются по базе — это только дашборд)."""
    from routers.dashboards import mobile_quick_links

    return mobile_quick_links(user, groups, [])


def build_menu_context(user, path, query=""):
    if user is None or canonical_role(user) == ROLE_EMPLOYEE:
        return None
    if path in NO_MENU_PATHS or any(_path_matches(path, prefix) for prefix in CABINET_PREFIXES):
        return None
    groups = build_navigation(user)
    menu = build_menu(groups)
    on_dashboard = path.rstrip("/") in DASHBOARD_PATHS
    if not on_dashboard:
        mark_current(menu, path, query)
    return {
        "menu": menu,
        "user": user,
        "role_label": role_label(canonical_role(user)),
        # Клик по группе: на дашборде — прокрутка к секции, вне его — на свой дашборд к якорю.
        "home": "" if on_dashboard else dashboard_url(user),
        "dashboard": dashboard_url(user),  # логотип ведёт на рабочий стол (П4.11 B1)
        "on_dashboard": on_dashboard,
        "quick": quick_links(user, groups),
        "open_key": "payouts" if has_permission(user, "weekly.view") else None,
    }


def menu_context(request):
    """Меню для текущего запроса или None (сотрудник, кабинет, вход). Один расчёт на запрос."""
    if request is None:
        return None
    state = request.state
    cached = getattr(state, "menu", _UNSET)
    if cached is not _UNSET:
        return cached
    result = build_menu_context(getattr(state, "user", None), request.url.path, request.url.query)
    state.menu = result
    return result


def install_menu_globals(modules):
    """Регистрирует `menu_context` во всех окружениях Jinja: у каждого роутера свой
    `Jinja2Templates`, а `base.html` у них общий."""
    from fastapi.templating import Jinja2Templates

    for module in modules:
        templates = getattr(module, "templates", None)
        if isinstance(templates, Jinja2Templates):
            templates.env.globals["menu_context"] = menu_context

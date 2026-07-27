from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from audit_helpers import create_audit_log
from dependencies import get_db
from models import Rate, Service, Shift
from rbac import require_permission
from service_matrix import build_service_matrix, normalize_service_base, parse_service_name
from utils import normalize_text


router = APIRouter()
templates = Jinja2Templates(directory="templates")
_rates_manage = require_permission("rates.manage")


def _is_base_rate(rate):
    return not normalize_text(rate.store) and not normalize_text(rate.employee_name)


def _base_key(rate):
    return (rate.level, normalize_text(rate.city), normalize_text(rate.format))


def _distinct_values(session, *columns):
    values = set()
    for column in columns:
        for row in session.query(column).distinct().all():
            value = normalize_text(row[0])
            if value:
                values.add(value)
    return sorted(values)


@router.get("/admin/services", response_class=HTMLResponse)
def admin_services(
    request: Request,
    city: str = "",
    fmt: str = "",
    q: str = "",
    message: str = "",
    error: str = "",
    session: Session = Depends(get_db),
    user=Depends(_rates_manage),
):
    """Диагностическая матрица услуг: строка = базовая услуга, колонки = уровни
    1..5 + «без уровня». Только чтение — правка ставок на /admin/rates."""
    city = normalize_text(city)
    fmt = normalize_text(fmt)
    q = normalize_text(q)

    cities = _distinct_values(session, Rate.city, Shift.city)
    formats = _distinct_values(session, Rate.format, Shift.format)

    # Регион — измерение сетки: при «все регионы» одна услуга+уровень в ЛО и СПб
    # выглядела бы мнимым дублем. Дефолт — первый регион (чистая сетка «Тарифы по
    # уровням»); ALL_REGIONS — явный выбор «все», клетка честно считает по регионам.
    ALL_REGIONS = "__all__"
    if city == "" and cities:
        city = cities[0]
    show_all_regions = city == ALL_REGIONS or not cities

    rate_query = session.query(Rate)
    shift_query = session.query(Shift.service).distinct()

    if city and not show_all_regions:
        rate_query = rate_query.filter(Rate.city == city)
        shift_query = shift_query.filter(Shift.city == city)
    if fmt:
        rate_query = rate_query.filter(Rate.format == fmt)
        shift_query = shift_query.filter(Shift.format == fmt)

    services = session.query(Service).order_by(Service.name.asc()).all()
    # «Есть в тарифах» / «без тарифа» — по НАЛИЧИЮ Rate у услуги глобально (до фильтра региона).
    rated_service_ids = {
        row[0]
        for row in session.query(Rate.service_id).filter(Rate.service_id.isnot(None)).distinct().all()
    }

    rate_rows = [
        {
            "service_id": rate.service_id,
            "level": rate.level,
            "city": rate.city,
            "format": rate.format,
            "store": rate.store,
            "employee_name": rate.employee_name,
            "hourly_rate": rate.hourly_rate,
        }
        for rate in rate_query.all()
    ]
    shift_services = [row[0] for row in shift_query.all()]

    matrix = build_service_matrix(services, rate_rows, shift_services, rated_service_ids)

    rows = matrix["rows"]
    if q:
        needle = normalize_service_base(q)
        rows = [
            row
            for row in rows
            if needle in row["base_key"]
            or any(needle in normalize_service_base(alias) for alias in row["alias_list"])
        ]

    # Группы дублей написания (уникально по base_key) — для секции слияния.
    seen_dup = set()
    dup_groups = []
    for row in matrix["rows"]:
        if row["is_duplicate"] and row["base_key"] not in seen_dup:
            seen_dup.add(row["base_key"])
            dup_groups.append({"base_key": row["base_key"], "variants": row["dup_group"]})

    # Контекст «где встречалась» для услуг без тарифа: до 5 последних смен (магазин/
    # дата/ФИО) + точный текст услуги смены — для предзаполнения модалки создания ставки.
    no_tariff = matrix["no_tariff_services"]
    no_tariff_context = {name: [] for name in no_tariff}
    if no_tariff:
        base_to_name = {normalize_service_base(name): name for name in no_tariff}
        recent = (
            session.query(Shift.service, Shift.store, Shift.city, Shift.format, Shift.shift_date, Shift.employee)
            .order_by(Shift.shift_date.desc())
            .limit(3000)
            .all()
        )
        for svc, store, city_v, fmt, day, emp in recent:
            _, base = parse_service_name(svc)
            name = base_to_name.get(normalize_service_base(base))
            if name and len(no_tariff_context[name]) < 5:
                no_tariff_context[name].append({
                    "service": svc, "store": store, "city": city_v, "format": fmt,
                    "date": day.strftime("%d.%m.%Y") if day else "", "employee": emp,
                })

    return templates.TemplateResponse(
        request,
        "service_matrix.html",
        {
            "rows": rows,
            "dup_groups": dup_groups,
            "levels": matrix["levels"],
            "counters": matrix["counters"],
            "no_tariff_services": matrix["no_tariff_services"],
            "no_tariff_context": no_tariff_context,
            "unmatched_shift_services": matrix["unmatched_shift_services"],
            "cities": cities,
            "formats": formats,
            "selected_city": city,
            "selected_format": fmt,
            "search": q,
            "message": message or None,
            "error": error or None,
            "total_bases": len(matrix["rows"]),
            "shown_bases": len(rows),
        },
    )


def _services_redirect(city, fmt, message="", error=""):
    params = {}
    if city:
        params["city"] = city
    if fmt:
        params["fmt"] = fmt
    if message:
        params["message"] = message
    if error:
        params["error"] = error
    return RedirectResponse(f"/admin/services?{urlencode(params)}", status_code=302)


@router.post("/admin/services/merge")
def merge_services(
    request: Request,
    canon_id: int = Form(...),
    merge_ids: list[int] = Form(default=[]),
    city: str = Form(default=""),
    fmt: str = Form(default=""),
    session: Session = Depends(get_db),
    user=Depends(_rates_manage),
):
    """Слияние дублей написания: сливаемые услуги D → канон C.

    Rate D перепривязываются на C, имена D уходят в C.aliases (смены с текстом D
    продолжают резолвиться в C), записи D удаляются. Необратимо — с проверкой
    инварианта (две разные базовые цены на один ключ блокируют слияние) и аудитом.
    """
    canon = session.query(Service).filter(Service.id == canon_id).first()
    if not canon:
        return _services_redirect(city, fmt, error="Канон-услуга не найдена")

    dups = [
        s for s in session.query(Service).filter(Service.id.in_(merge_ids or [])).all()
        if s.id != canon_id
    ]
    if not dups:
        return _services_redirect(city, fmt, error="Не выбрано, что объединять (кроме канона)")

    # Инвариант: после слияния на ключ (уровень+регион+формат) базовой сетки не
    # должно быть двух РАЗНЫХ цен. Проверяем до записи.
    prices_by_key = {}
    for service in [canon, *dups]:
        for rate in session.query(Rate).filter(Rate.service_id == service.id).all():
            if _is_base_rate(rate):
                prices_by_key.setdefault(_base_key(rate), set()).add(round(rate.hourly_rate or 0, 2))
    conflict_keys = [key for key, prices in prices_by_key.items() if len(prices) > 1]
    if conflict_keys:
        sample = conflict_keys[0]
        return _services_redirect(
            city, fmt,
            error=(
                f"Слияние заблокировано: разные базовые цены на один ключ "
                f"(уровень {sample[0]}, {sample[1]}, {sample[2]}) — "
                f"{', '.join(str(p) for p in sorted(prices_by_key[sample]))} ₽. "
                "Исправьте ставки на /admin/rates и повторите."
            ),
        )

    # Слияние. Перепривязка Rate; базовые дубли на один ключ (цена равна) схлопываем.
    existing_aliases = [a.strip() for a in (canon.aliases or "").split(",") if a.strip()]

    def add_alias(name):
        name = normalize_text(name)
        if name and name != canon.name and name not in existing_aliases:
            existing_aliases.append(name)

    canon_base_keys = {
        _base_key(r)
        for r in session.query(Rate).filter(Rate.service_id == canon.id).all()
        if _is_base_rate(r)
    }
    total_repointed = 0
    total_collapsed = 0
    merged_names = []
    for dup in dups:
        merged_names.append(dup.name)
        for rate in session.query(Rate).filter(Rate.service_id == dup.id).all():
            if _is_base_rate(rate) and _base_key(rate) in canon_base_keys:
                # Такой же ключ уже есть у канона (цена совпадает по инварианту) — схлопываем.
                session.delete(rate)
                total_collapsed += 1
            else:
                rate.service_id = canon.id
                if _is_base_rate(rate):
                    canon_base_keys.add(_base_key(rate))
                total_repointed += 1
        add_alias(dup.name)
        for alias in (dup.aliases or "").split(","):
            add_alias(alias)
        session.delete(dup)

    canon.aliases = ", ".join(existing_aliases) or None
    session.flush()
    create_audit_log(
        session, request, user, "services_merged", "service", canon.id, canon.name,
        new_value={
            "canon": canon.name,
            "merged": merged_names,
            "rates_repointed": total_repointed,
            "rates_collapsed": total_collapsed,
            "aliases": canon.aliases,
        },
    )
    session.commit()
    return _services_redirect(
        city, fmt,
        message=(
            f"Объединено: {', '.join(merged_names)} → «{canon.name}». "
            f"Перепривязано ставок: {total_repointed}, схлопнуто дублей: {total_collapsed}."
        ),
    )

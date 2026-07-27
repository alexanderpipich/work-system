import re
from datetime import datetime

import pandas as pd
from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from access import accessible_employee_names, apply_shift_scope
from audit_helpers import create_audit_log
from dependencies import get_db
from models import Rate, Service, Shift
from rbac import canonical_role, require_permission
from service_catalog import get_or_create_service
from service_matrix import normalize_service_base, parse_service_name
from utils import normalize_format, normalize_text


# --- Загрузка базовой тарифной сетки из Excel -------------------------------
# Файл "Тарифы_по_уровням.xlsx", лист "ставки": 8 колонок —
#   РЕГИОН | ТК | УСЛУГА | 1 уровень | 2 уровень | 3 уровень | 4 уровень | 5 уровень.
# РЕГИОН → Rate.city (матчится со столбцом "Город" отчёта = Shift.city)
# ТК     → Rate.format (ГМ/СМ/…; жёсткое условие при подборе)
# УСЛУГА → базовое имя услуги (БЕЗ префикса уровня) → Service.name + Rate.service_id
# "N уровень" → Rate.hourly_rate для Rate.level = N (уровень из КОЛОНКИ, не из текста)

TARIFF_LEVELS = [1, 2, 3, 4, 5]
TARIFF_REGION_HDR = "РЕГИОН"
TARIFF_TK_HDR = "ТК"
TARIFF_SERVICE_HDR = "УСЛУГА"
TARIFF_PERFORMER_HDR = "{n} уровень"
TARIFF_SHEET = "ставки"
TARIFF_HEADER_ROW = 1  # 1-indexed строка заголовков (в новом файле — строка 1)


def _tariff_find_col(columns, target):
    target_norm = re.sub(r"\s+", " ", str(target)).strip().lower()
    for col in columns:
        if col is None:
            continue
        if re.sub(r"\s+", " ", str(col)).strip().lower() == target_norm:
            return col
    return None


def _duplicate_spelling(rows):
    """Пары/группы разных написаний одной услуги (Вингараж с пробелом/подчёркиванием):
    схлопываются одной нормализацией, но исходные имена различаются. Только показать."""
    groups = {}
    for row in rows:
        name = row.get("service_name") or ""
        if name:
            groups.setdefault(normalize_service_base(name), set()).add(name)
    return sorted([sorted(variants) for variants in groups.values() if len(variants) > 1])


def parse_tariff_grid(file_obj, sheet=TARIFF_SHEET, header_row=TARIFF_HEADER_ROW):
    """Развернуть тарифный Excel в плоский список строк ставок.

    Возвращает (rows, conflicts), где rows — список dict с ключами
    city/format/service/hourly_rate, а conflicts — список ключей
    (city, format, service) с несколькими разными ставками.
    """
    df = pd.read_excel(file_obj, sheet_name=sheet, header=header_row - 1)
    columns = list(df.columns)

    region_c = _tariff_find_col(columns, TARIFF_REGION_HDR)
    tk_c = _tariff_find_col(columns, TARIFF_TK_HDR)
    service_c = _tariff_find_col(columns, TARIFF_SERVICE_HDR)
    perf_cols = {
        n: _tariff_find_col(columns, TARIFF_PERFORMER_HDR.format(n=n))
        for n in TARIFF_LEVELS
    }

    missing = []
    if region_c is None:
        missing.append(TARIFF_REGION_HDR)
    if tk_c is None:
        missing.append(TARIFF_TK_HDR)
    if service_c is None:
        missing.append(TARIFF_SERVICE_HDR)
    for n, col in perf_cols.items():
        if col is None:
            missing.append(TARIFF_PERFORMER_HDR.format(n=n))
    if missing:
        raise ValueError("Не найдены колонки: " + ", ".join(missing))

    rows = []
    for _, record in df.iterrows():
        region = record[region_c]
        tk = record[tk_c]
        service = record[service_c]

        if pd.isna(region) or pd.isna(service):
            continue

        city = normalize_text(region)
        fmt = normalize_format(tk) if not pd.isna(tk) else ""
        service_name = normalize_text(service)
        if not city or not service_name:
            continue

        for n in TARIFF_LEVELS:
            value = record[perf_cols[n]]
            if pd.isna(value):
                continue
            try:
                hourly_rate = round(float(value), 2)
            except (TypeError, ValueError):
                continue
            if hourly_rate <= 0:
                continue
            rows.append({
                "city": city,
                "format": fmt or None,
                # service (текст "Nур_имя") оставлен для фолбэка подбора (этап 2)
                # и сверки; уровень теперь берётся из КОЛОНКИ в поле level.
                "service": f"{n}ур_{service_name}",
                "service_name": service_name,
                "level": n,
                "hourly_rate": hourly_rate,
            })

    # выявить конфликты: один ключ city+format+услуга+уровень → разные ставки.
    # service ("Nур_имя") уже кодирует уровень, поэтому ключ по service level-aware.
    by_key = {}
    for row in rows:
        key = (row["city"], row["format"] or "", row["service"])
        by_key.setdefault(key, set()).add(row["hourly_rate"])
    conflicts = [
        {"city": k[0], "format": k[1], "service": k[2], "rates": sorted(v)}
        for k, v in by_key.items()
        if len(v) > 1
    ]

    return rows, conflicts


router = APIRouter()
templates = Jinja2Templates(directory="templates")
require_rate_hard_delete = require_permission("rates.hard_delete", audit_denied=True)
require_rate_view = require_permission("rates.view", audit_denied=True)
_rates_manage = require_permission("rates.manage")


def _rate_payload(rate):
    return {
        "service": rate.service,
        "format": rate.format,
        "city": rate.city,
        "store": rate.store,
        "employee_name": rate.employee_name,
        "hourly_rate": rate.hourly_rate,
        "active_from": rate.active_from,
        "active_to": rate.active_to,
        "comment": rate.comment,
    }


def rates_query(session):
    return session.query(Rate).order_by(
        Rate.employee_name.desc().nullslast(),
        Rate.store.desc().nullslast(),
        Rate.format.desc().nullslast(),
        Rate.service.asc()
    )


# Пусто/NULL у store/employee_name = «не задан» (нормализуем оба, иначе базовая с
# пустой строкой попала бы в индивидуальные).
_HAS_STORE = and_(Rate.store != None, Rate.store != "")          # noqa: E711
_HAS_EMPLOYEE = and_(Rate.employee_name != None, Rate.employee_name != "")  # noqa: E711
_INDIVIDUAL = or_(_HAS_STORE, _HAS_EMPLOYEE)
_BASE = and_(
    or_(Rate.store == None, Rate.store == ""),          # noqa: E711
    or_(Rate.employee_name == None, Rate.employee_name == ""),  # noqa: E711
)


def _resolve_service_link(session, service_text):
    """Текст услуги (возможно с префиксом `Nур_`) → (service_id, level) через
    справочник Service. Делает РУЧНУЮ ставку модель-консистентной (как загрузчик
    тарифов, этап 3): подбор находит её по service_id+level, а услуга уходит из
    «без тарифа» в матрице. Услугу заводит, если её ещё нет (дубли не склеивает)."""
    level, base = parse_service_name(service_text)
    service = get_or_create_service(session, base) if base else None
    return (service.id if service else None), level


def _apply_layer(query, layer):
    """Фильтр списка ЧТС по слою. layer: all|individual|store|employee|base."""
    if layer == "individual":
        return query.filter(_INDIVIDUAL)
    if layer == "store":
        return query.filter(and_(_HAS_STORE, or_(Rate.employee_name == None, Rate.employee_name == "")))  # noqa: E711
    if layer == "employee":
        return query.filter(_HAS_EMPLOYEE)
    if layer == "base":
        return query.filter(_BASE)
    return query


@router.get("/economist/rates", response_class=HTMLResponse)
@router.get("/hr/rates", response_class=HTMLResponse)
def economist_rates(
    request: Request,
    layer: str = "all",
    session: Session = Depends(get_db),
    user=Depends(require_rate_view),
):
    role = canonical_role(user)
    if request.url.path.startswith("/hr") and role not in {"hr_lead", "hr_manager"}:
        return RedirectResponse("/", status_code=302)
    if request.url.path.startswith("/economist") and role not in {"economist", "superadmin"}:
        return RedirectResponse("/", status_code=302)
    layer = layer if layer in _ALLOWED_LAYERS else "all"
    scoped = rates_query(session)
    if role == "hr_manager":
        scoped_stores = [
            row[0]
            for row in apply_shift_scope(session.query(Shift.store).distinct(), session, user, Shift).all()
            if row[0]
        ]
        scoped_employees = accessible_employee_names(session, user)
        scoped = scoped.filter(or_(
            and_(Rate.store == None, Rate.employee_name == None),
            Rate.store.in_(scoped_stores or ["__none__"]),
            and_(
                Rate.store == None,
                Rate.employee_name.in_(scoped_employees or ["__none__"]),
            ),
        ))
    rates = _apply_layer(scoped, layer).all()
    rates_base = "/hr/rates" if request.url.path.startswith("/hr") else "/economist/rates"

    return templates.TemplateResponse(
        request,
        "economist_rates.html",
        {
            "rates": rates,
            "layer": layer,
            "rates_base": rates_base,
            "individual_count": scoped.filter(_INDIVIDUAL).count(),
            "base_count": scoped.filter(_BASE).count(),
            "message": None,
            "error": None,
            "read_only": request.url.path.startswith("/hr")
        }
    )


@router.post("/economist/rates", response_class=HTMLResponse)
def economist_create_rate(
    request: Request,
    service: str = Form(...),
    format: str = Form(default=""),
    city: str = Form(default=""),
    store: str = Form(default=""),
    employee_name: str = Form(default=""),
    hourly_rate: float = Form(...),
    active_from: str = Form(default=""),
    active_to: str = Form(default=""),
    comment: str = Form(default=""),
    session: Session = Depends(get_db),
    user=Depends(_rates_manage),
):
    active_from_date = None
    active_to_date = None

    if active_from:
        active_from_date = datetime.strptime(active_from, "%Y-%m-%d").date()

    if active_to:
        active_to_date = datetime.strptime(active_to, "%Y-%m-%d").date()

    _service_clean = normalize_text(service)
    _service_id, _level = _resolve_service_link(session, _service_clean)
    rate = Rate(
        service=_service_clean,
        service_id=_service_id,
        level=_level,
        format=normalize_format(format) or None,
        city=normalize_text(city) or None,
        store=normalize_text(store) or None,
        employee_name=normalize_text(employee_name) or None,
        hourly_rate=hourly_rate,
        active_from=active_from_date,
        active_to=active_to_date,
        comment=normalize_text(comment) or None
    )

    session.add(rate)
    session.flush()
    create_audit_log(
        session,
        request,
        user,
        "rate_created",
        "rate",
        rate.id,
        f"{rate.service} / {rate.format or ''} / {rate.store or ''} / {rate.employee_name or ''}",
        new_value=_rate_payload(rate),
    )
    session.commit()

    return RedirectResponse(url="/economist/rates", status_code=302)


@router.post("/economist/rates/update", response_class=HTMLResponse)
def economist_update_rate(
    request: Request,
    rate_id: int = Form(...),
    service: str = Form(...),
    format: str = Form(default=""),
    city: str = Form(default=""),
    store: str = Form(default=""),
    employee_name: str = Form(default=""),
    hourly_rate: float = Form(...),
    active_from: str = Form(default=""),
    active_to: str = Form(default=""),
    comment: str = Form(default=""),
    session: Session = Depends(get_db),
    user=Depends(_rates_manage),
):
    rate = session.query(Rate).filter(Rate.id == rate_id).first()

    if not rate:
        return RedirectResponse(url="/economist/rates", status_code=302)

    old_value = _rate_payload(rate)
    active_from_date = None
    active_to_date = None

    if active_from:
        active_from_date = datetime.strptime(active_from, "%Y-%m-%d").date()

    if active_to:
        active_to_date = datetime.strptime(active_to, "%Y-%m-%d").date()

    rate.service = normalize_text(service)
    rate.service_id, rate.level = _resolve_service_link(session, rate.service)
    rate.format = normalize_format(format) or None
    rate.city = normalize_text(city) or None
    rate.store = normalize_text(store) or None
    rate.employee_name = normalize_text(employee_name) or None
    rate.hourly_rate = hourly_rate
    rate.active_from = active_from_date
    rate.active_to = active_to_date
    rate.comment = normalize_text(comment) or None

    create_audit_log(
        session,
        request,
        user,
        "rate_updated",
        "rate",
        rate.id,
        f"{rate.service} / {rate.format or ''} / {rate.store or ''} / {rate.employee_name or ''}",
        old_value=old_value,
        new_value=_rate_payload(rate),
    )
    session.commit()

    return RedirectResponse(url="/economist/rates", status_code=302)


@router.post("/economist/rates/delete", response_class=HTMLResponse)
def economist_delete_rate(
    request: Request,
    rate_id: int = Form(...),
    session: Session = Depends(get_db),
    user=Depends(require_rate_hard_delete),
):
    rate = session.query(Rate).filter(Rate.id == rate_id).first()

    if rate:
        create_audit_log(
            session,
            request,
            user,
            "rate_deleted",
            "rate",
            rate.id,
            f"{rate.service} / {rate.format or ''} / {rate.store or ''} / {rate.employee_name or ''}",
            old_value=_rate_payload(rate),
        )
        session.delete(rate)
        session.commit()

    return RedirectResponse(url="/economist/rates", status_code=302)


_ALLOWED_LAYERS = {"all", "individual", "store", "employee", "base"}


@router.get("/admin/rates", response_class=HTMLResponse)
def admin_rates(
    request: Request,
    layer: str = "all",
    session: Session = Depends(get_db),
    user=Depends(_rates_manage),
):
    """Список ЧТС с фильтром по слою. `layer`: all | individual | store | employee | base.
    «individual» = неканонические (store или employee заполнены). Подбор/загрузчик не трогаем."""
    layer = layer if layer in _ALLOWED_LAYERS else "all"
    scoped = rates_query(session)
    rates = _apply_layer(scoped, layer).all()

    return templates.TemplateResponse(
        request,
        "rates.html",
        {
            "rates": rates,
            "layer": layer,
            "rates_base": "/admin/rates",
            "individual_count": scoped.filter(_INDIVIDUAL).count(),
            "base_count": scoped.filter(_BASE).count(),
            "message": None,
            "error": None
        }
    )


@router.post("/admin/rates", response_class=HTMLResponse)
def create_rate(
    request: Request,
    service: str = Form(...),
    format: str = Form(default=""),
    city: str = Form(default=""),
    store: str = Form(default=""),
    employee_name: str = Form(default=""),
    hourly_rate: float = Form(...),
    active_from: str = Form(default=""),
    active_to: str = Form(default=""),
    comment: str = Form(default=""),
    session: Session = Depends(get_db),
    user=Depends(_rates_manage),
):
    service_clean = normalize_text(service)
    format_clean = normalize_format(format) or None
    city_clean = normalize_text(city) or None
    store_clean = normalize_text(store) or None
    employee_name_clean = normalize_text(employee_name) or None
    comment_clean = normalize_text(comment) or None

    active_from_date = None
    active_to_date = None

    try:
        if active_from:
            active_from_date = datetime.strptime(active_from, "%Y-%m-%d").date()
        if active_to:
            active_to_date = datetime.strptime(active_to, "%Y-%m-%d").date()
    except ValueError:
        rates = session.query(Rate).order_by(Rate.service.asc()).all()
        return templates.TemplateResponse(
            request,
            "rates.html",
            {
                "rates": rates,
                "message": None,
                "error": "Некорректный формат даты"
            }
        )

    if hourly_rate <= 0:
        rates = session.query(Rate).order_by(Rate.service.asc()).all()
        return templates.TemplateResponse(
            request,
            "rates.html",
            {
                "rates": rates,
                "message": None,
                "error": "ЧТС должна быть больше нуля"
            }
        )

    service_id, level = _resolve_service_link(session, service_clean)
    rate = Rate(
        service=service_clean,
        service_id=service_id,
        level=level,
        format=format_clean,
        city=city_clean,
        store=store_clean,
        employee_name=employee_name_clean,
        hourly_rate=hourly_rate,
        active_from=active_from_date,
        active_to=active_to_date,
        comment=comment_clean
    )

    session.add(rate)
    session.flush()
    create_audit_log(
        session,
        request,
        user,
        "rate_created",
        "rate",
        rate.id,
        f"{rate.service} / {rate.format or ''} / {rate.store or ''} / {rate.employee_name or ''}",
        new_value=_rate_payload(rate),
    )
    session.commit()

    return RedirectResponse(url="/admin/rates", status_code=302)


@router.post("/admin/rates/update", response_class=HTMLResponse)
def update_rate(
    request: Request,
    rate_id: int = Form(...),
    service: str = Form(...),
    format: str = Form(default=""),
    city: str = Form(default=""),
    store: str = Form(default=""),
    employee_name: str = Form(default=""),
    hourly_rate: float = Form(...),
    active_from: str = Form(default=""),
    active_to: str = Form(default=""),
    comment: str = Form(default=""),
    session: Session = Depends(get_db),
    user=Depends(_rates_manage),
):
    rate = session.query(Rate).filter(Rate.id == rate_id).first()
    if not rate:
        return RedirectResponse(url="/admin/rates", status_code=302)

    old_value = _rate_payload(rate)
    active_from_date = None
    active_to_date = None

    if active_from:
        active_from_date = datetime.strptime(active_from, "%Y-%m-%d").date()
    if active_to:
        active_to_date = datetime.strptime(active_to, "%Y-%m-%d").date()

    rate.service = normalize_text(service)
    rate.service_id, rate.level = _resolve_service_link(session, rate.service)
    rate.format = normalize_format(format) or None
    rate.city = normalize_text(city) or None
    rate.store = normalize_text(store) or None
    rate.employee_name = normalize_text(employee_name) or None
    rate.hourly_rate = hourly_rate
    rate.active_from = active_from_date
    rate.active_to = active_to_date
    rate.comment = normalize_text(comment) or None

    create_audit_log(
        session,
        request,
        user,
        "rate_updated",
        "rate",
        rate.id,
        f"{rate.service} / {rate.format or ''} / {rate.store or ''} / {rate.employee_name or ''}",
        old_value=old_value,
        new_value=_rate_payload(rate),
    )
    session.commit()

    return RedirectResponse(url="/admin/rates", status_code=302)


@router.post("/admin/rates/delete", response_class=HTMLResponse)
def delete_rate(
    request: Request,
    rate_id: int = Form(...),
    session: Session = Depends(get_db),
    admin=Depends(require_rate_hard_delete),
):
    rate = session.query(Rate).filter(Rate.id == rate_id).first()
    if rate:
        create_audit_log(
            session,
            request,
            admin,
            "rate_deleted",
            "rate",
            rate.id,
            f"{rate.service} / {rate.format or ''} / {rate.store or ''} / {rate.employee_name or ''}",
            old_value=_rate_payload(rate),
        )
        session.delete(rate)
        session.commit()

    return RedirectResponse(url="/admin/rates", status_code=302)



# --- Загрузка тарифной сетки: предпросмотр + применение ----------------------

@router.post("/admin/rates/upload", response_class=HTMLResponse)
async def upload_rates(
    request: Request,
    file: UploadFile = File(...),
    mode: str = Form(default="preview"),  # "preview" | "append" | "replace"
    session: Session = Depends(get_db),
    user=Depends(_rates_manage),
):
    def _render(ctx):
        rates = rates_query(session).all()
        base = {"rates": rates, "message": None, "error": None}
        base.update(ctx)
        return templates.TemplateResponse(request, "rates.html", base)

    try:
        contents = await file.read()
        import io
        rows, conflicts = parse_tariff_grid(io.BytesIO(contents))
    except ValueError as exc:
        return _render({"error": f"Ошибка разбора файла: {exc}"})
    except Exception as exc:  # noqa: BLE001
        return _render({"error": f"Не удалось прочитать файл: {exc}"})

    if not rows:
        return _render({"error": "В файле не найдено ни одной ставки"})

    # Предпросмотр: ничего не пишем, показываем сводку
    if mode == "preview":
        cities = sorted({r["city"] for r in rows})
        formats = sorted({r["format"] or "—" for r in rows})
        preview = {
            "count": len(rows),
            "cities": cities,
            "formats": formats,
            "conflicts": conflicts,
            "duplicate_spelling": _duplicate_spelling(rows),
            "sample": rows[:20],
        }
        return _render({"rates_preview": preview, "message": None})

    # Применение: конфликты блокируют запись (детерминизм подбора)
    # Инвариант базовой сетки: на ключ (регион+формат+услуга+уровень) ровно ОДНА цена.
    # Две РАЗНЫЕ цены на один ключ — ошибка целостности, файл НЕ применяем.
    if conflicts:
        return _render({
            "error": (
                f"Загрузка отменена: {len(conflicts)} дубль(ей) ключа "
                f"регион+формат+услуга+уровень с РАЗНОЙ ценой (нарушен инвариант «одна "
                f"цена на ключ»). Разная цена допустима только по магазину/сотруднику. "
                "Исправьте цены в файле и повторите."
            ),
            "rates_preview": {
                "count": len(rows), "cities": [], "formats": [],
                "conflicts": conflicts, "duplicate_spelling": [], "sample": [],
            },
        })

    # Одинаковая цена на один ключ — просто схлопнуть в одну строку (не плодить
    # дубль ключа в базовой сетке). Разные цены уже отсечены конфликтом выше.
    seen_keys = set()
    unique_rows = []
    for row in rows:
        key = (row["city"], row["format"] or "", row["service"])
        if key in seen_keys:
            continue
        seen_keys.add(key)
        unique_rows.append(row)
    rows = unique_rows

    if mode == "replace":
        # Удаляем только строки базовой сетки (без store и employee_name),
        # чтобы не затронуть индивидуальные ставки по ТК/сотрудникам.
        deleted = (
            session.query(Rate)
            .filter(Rate.store == None, Rate.employee_name == None)  # noqa: E711
            .delete(synchronize_session=False)
        )
    else:
        deleted = 0

    created = 0
    services_before = session.query(Service).count()
    for row in rows:
        # Услуга из колонки УСЛУГА заводится в справочник (тариф = источник услуг);
        # дубли написания НЕ склеиваются. service_id + level — новая модель;
        # текст service ("Nур_имя") пишем как раньше для фолбэка подбора (этап 2).
        service = get_or_create_service(session, row["service_name"])
        rate = Rate(
            service=row["service"],
            service_id=service.id if service else None,
            level=row["level"],
            format=row["format"],
            city=row["city"],
            store=None,
            employee_name=None,
            hourly_rate=row["hourly_rate"],
        )
        session.add(rate)
        created += 1

    session.flush()
    services_created = session.query(Service).count() - services_before
    duplicate_spelling = _duplicate_spelling(rows)
    create_audit_log(
        session,
        request,
        user,
        "rates_bulk_uploaded",
        "rate",
        None,
        f"mode={mode}; создано={created}; услуг заведено={services_created}; удалено={deleted}",
        new_value={
            "mode": mode,
            "created": created,
            "services_created": services_created,
            "deleted": deleted,
        },
    )
    session.commit()

    message = (
        f"Загрузка завершена ({mode}). Создано ставок: {created}"
        f"; заведено новых услуг: {services_created}"
        + (f"; удалено базовых: {deleted}" if mode == "replace" else "")
    )
    if duplicate_spelling:
        variants = "; ".join(" / ".join(pair) for pair in duplicate_spelling)
        message += f". ⚠ Дубли написания ({len(duplicate_spelling)}): {variants}"
    return _render({"message": message})

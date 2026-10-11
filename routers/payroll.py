from datetime import datetime, timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from access import apply_shift_scope, get_economist_cities, get_user_cities, get_user_stores
from audit_helpers import create_audit_log
from dependencies import get_db
from legal_entity_helpers import active_legal_entities
from lmk_charges import apply_lmk_charges_to_rows
from manual_adjustments import (
    apply_manual_adjustments_to_rows,
    save_manual_adjustments,
)
from models import PayrollRun, Requisite, Shift
from payouts_helpers import period_runs_for
from payroll_run_helpers import (bonus_per_hour, build_run_items, half_month_bounds, is_half_month,
                                 load_hourly_bonuses, payable_shifts)
from payroll_adjustments import apply_auto_adjustments_to_rows
from referral_helpers import apply_confirmed_payouts_to_run, pending_payouts
from schedule_grid import build_payroll_rows, days_between
from service_catalog import build_service_resolver
from shift_helpers import is_no_plan_shift
from time_helpers import business_today, now_utc
from rbac import ROLE_HR_LEAD, ROLE_TM, canonical_role, is_superadmin, require_permission
from utils import load_rates, normalize_text, pick_rate


router = APIRouter()
templates = Jinja2Templates(directory="templates")
require_payroll_view = require_permission("payroll.view", audit_denied=True)
_payroll_manage = require_permission("payroll.manage")

# Запоминаем последний выбор магазинов на /admin/payroll в сессии, чтобы не
# сбрасывать его на «все» при каждом заходе. "__all__" = компактный признак
# «выбраны все» (не раздуваем cookie полным списком ТК).
PAYROLL_STORES_SESSION_KEY = "admin_payroll_selected_stores"
PAYROLL_STORES_ALL = "__all__"


PERIOD_REFUSAL = (
    "Табель фиксируется за 1–15 или 16–конец месяца. "
    "Недельные выплаты — в разделе «Выплаты → Еженедельные авансы»."
)


def period_comment_or_refusal(user, start_date, end_date, comment):
    """П3: табель — только полмесяца. (комментарий, отказ). Суперадмину произвольный
    период разрешён, в комментарии остаётся пометка."""
    comment = normalize_text(comment)
    if is_half_month(start_date, end_date):
        return comment, None
    if is_superadmin(user):
        return ("[произвольный период] " + comment).strip(), None
    return comment, PERIOD_REFUSAL


def half_month_links(day):
    """Кнопки «01–15 / 16–конец»: прошлый и текущий месяц относительно `day`."""
    previous_month_last = day.replace(day=1) - timedelta(days=1)
    anchors = (previous_month_last.replace(day=1), previous_month_last, day.replace(day=1), day.replace(day=16))
    links = []
    for anchor in anchors:
        start, end = half_month_bounds(anchor)
        links.append((f"{start:%d}–{end:%d.%m}", start, end))
    return links


def payroll_redirect_url(base_path, date_from, date_to, employee_name="", stores=None, message=""):
    params = {
        "date_from": date_from,
        "date_to": date_to,
    }
    if employee_name:
        params["employee_name"] = employee_name
    if message:
        params["message"] = message

    query_parts = [urlencode(params)]
    for store in stores or []:
        query_parts.append(urlencode({"stores": store}))

    return f"{base_path}?{'&'.join(part for part in query_parts if part)}"


@router.get("/economist/payroll", response_class=HTMLResponse)
@router.get("/hr/payroll", response_class=HTMLResponse)
def economist_payroll(
    request: Request,
    date_from: str = "",
    date_to: str = "",
    employee_name: str = "",
    stores: list[str] | None = Query(default=None),
    stores_submitted: str = "",
    message: str = "",
    session: Session = Depends(get_db),
    user=Depends(require_payroll_view),
):
    role = canonical_role(user)
    if request.url.path.startswith("/economist") and role not in {"economist", "superadmin"}:
        return RedirectResponse("/", status_code=302)
    if request.url.path.startswith("/hr") and role not in {ROLE_HR_LEAD, ROLE_TM}:
        return RedirectResponse("/", status_code=302)

    # Роут общий для /economist/payroll и /hr/payroll (разные роли и наборы
    # городов) — выбор магазинов держим в РАЗДЕЛЬНЫХ ключах сессии, чтобы он не
    # протекал между ролями. "все" храним компактным сентинелом PAYROLL_STORES_ALL.
    stores_scope = "hr" if request.url.path.startswith("/hr") else "economist"
    stores_session_key = f"payroll_selected_stores:{stores_scope}"
    stores_was_submitted = stores_submitted == "1"

    allowed_cities = get_user_cities(session, user)

    if allowed_cities == []:
        return templates.TemplateResponse(
            request,
            "economist_payroll.html",
            {
                "user": user,
                "allowed_cities": allowed_cities,
                "rows": [],
                "date_from": date_from,
                "date_to": date_to,
                "employee_name": employee_name,
                "employees": [],
                "stores": [],
                "selected_stores": stores or [],
                "total_hours": 0,
                "total_amount": 0,
                "legal_entities": active_legal_entities(session),
                "error": "Для пользователя не назначены города",
                "message": message or None
            }
        )

    today = business_today()

    if not date_from and not date_to:
        current_week_monday = today - timedelta(days=today.weekday())
        default_date_to = current_week_monday - timedelta(days=1)
        default_date_from = default_date_to - timedelta(days=6)

        date_from = default_date_from.strftime("%Y-%m-%d")
        date_to = default_date_to.strftime("%Y-%m-%d")

    shifts_query = session.query(Shift)

    shifts_query = apply_shift_scope(shifts_query, session, user, Shift)

    try:
        if date_from:
            shifts_query = shifts_query.filter(
                Shift.shift_date >= datetime.strptime(date_from, "%Y-%m-%d").date()
            )
        if date_to:
            shifts_query = shifts_query.filter(
                Shift.shift_date <= datetime.strptime(date_to, "%Y-%m-%d").date()
            )
    except ValueError:
        return templates.TemplateResponse(
            request,
            "economist_payroll.html",
            {
                "user": user,
                "allowed_cities": allowed_cities,
                "rows": [],
                "date_from": date_from,
                "date_to": date_to,
                "employee_name": employee_name,
                "employees": [],
                "stores": [],
                "selected_stores": stores or [],
                "total_hours": 0,
                "total_amount": 0,
                "legal_entities": active_legal_entities(session),
                "error": "Некорректный формат даты",
                "message": message or None
            }
        )

    start_date = datetime.strptime(date_from, "%Y-%m-%d").date()
    end_date = datetime.strptime(date_to, "%Y-%m-%d").date()

    if employee_name.strip():
        shifts_query = shifts_query.filter(Shift.employee == employee_name.strip())

    if stores:
        shifts_query = shifts_query.filter(Shift.store.in_(stores))

    shifts = shifts_query.order_by(
        Shift.city.asc(),
        Shift.store.asc(),
        Shift.employee.asc(),
        Shift.shift_date.asc()
    ).all()

    employees_query = session.query(Shift.employee).distinct()

    stores_query = session.query(Shift.store).distinct()

    employees_query = apply_shift_scope(employees_query, session, user, Shift)
    stores_query = apply_shift_scope(stores_query, session, user, Shift)

    employee_list = [
        e[0] for e in employees_query.order_by(Shift.employee.asc()).all()
    ]

    store_list = [
        s[0] for s in stores_query.order_by(Shift.store.asc()).all()
    ]

    # Отправка формы — запомнить выбор магазинов в сессии (список отмеченных,
    # либо [] если ни одной). Все доступные храним сентинелом «__all__».
    if stores_was_submitted:
        submitted_stores = stores if stores is not None else []
        if store_list and set(submitted_stores) == set(store_list):
            request.session[stores_session_key] = PAYROLL_STORES_ALL
        else:
            request.session[stores_session_key] = submitted_stores

    if stores is None and stores_was_submitted and not employee_name.strip():
        # Форма отправлена без единой галочки — показать «ничего».
        stores = []
        shifts = []

    if stores is None and not stores_was_submitted:
        # Обычный заход (без отправки формы) — восстановить прошлый выбор из
        # сессии; если ничего не запомнено или сентинел «все» — по умолчанию
        # все доступные магазины.
        remembered = request.session.get(stores_session_key)
        if isinstance(remembered, list):
            # Пересечь со скоупом: если у пользователя сузились города, в сессии
            # могут остаться недоступные ТК — их отсеиваем, не показываем чужое.
            store_set = set(store_list)
            stores = [s for s in remembered if s in store_set]
        else:
            stores = store_list
        if stores:
            shifts_query = shifts_query.filter(Shift.store.in_(stores))
            shifts = shifts_query.order_by(
                Shift.city.asc(),
                Shift.store.asc(),
                Shift.employee.asc(),
                Shift.shift_date.asc()
            ).all()
        else:
            shifts = []

    rates = load_rates(session)
    resolve = build_service_resolver(session)
    shifts = payable_shifts(shifts, resolve)  # комплектация и др. — не из timebook
    bonuses = load_hourly_bonuses(session)
    payroll_map = {}

    for shift in shifts:
        shift_is_no_plan = is_no_plan_shift(shift)
        rate = pick_rate(rates, shift, resolve=resolve)
        rate_value = rate.hourly_rate if rate else 0
        amount = 0 if shift_is_no_plan else (shift.hours * rate_value if rate else 0)
        # П4.4: надбавка к часу входит в начисленное — как в зафиксированном табеле.
        if amount and bonuses:
            amount += shift.hours * bonus_per_hour(bonuses, shift.shift_date)

        key = (shift.employee, shift.city, shift.store, shift_is_no_plan)

        if key not in payroll_map:
            payroll_map[key] = {
                "employee_name": shift.employee,
                "city": shift.city,
                "store": shift.store,
                "request_type": shift.request_type,
                "is_no_plan": shift_is_no_plan,
                "hours": 0,
                "amount": 0,
                "missing_rates": 0,
                "no_plan_hours": 0,
                "has_no_plan": False,
                "manual_key": f"{shift.employee}|||{shift.store}"
            }

        payroll_map[key]["hours"] += shift.hours
        payroll_map[key]["amount"] += amount

        if shift_is_no_plan:
            payroll_map[key]["no_plan_hours"] += shift.hours
            payroll_map[key]["has_no_plan"] = True

        if not rate and not is_no_plan_shift(shift):
            payroll_map[key]["missing_rates"] += 1

    rows = list(payroll_map.values())
    rows.sort(key=lambda x: (x["city"], x["store"], x["employee_name"], x["is_no_plan"]))

    for row in rows:
        row["lmk_amount"] = 0

    apply_auto_adjustments_to_rows(session, rows)
    apply_manual_adjustments_to_rows(session, rows, start_date, end_date)

    total_hours = sum(row["hours"] for row in rows)
    total_amount = sum(row["total_amount"] for row in rows)

    return templates.TemplateResponse(
        request,
        "economist_payroll.html",
        {
            "user": user,
            "allowed_cities": allowed_cities,
            "rows": rows,
            "date_from": date_from,
            "date_to": date_to,
            "employee_name": employee_name,
            "employees": employee_list,
            "stores": store_list,
            "selected_stores": stores or [],
            "total_hours": total_hours,
            "total_amount": total_amount,
            "legal_entities": active_legal_entities(session),
            "error": None,
            "message": message or None
        }
    )



@router.post("/economist/payroll/manual-adjustments/save")
def economist_save_manual_adjustments(
    request: Request,
    date_from: str = Form(...),
    date_to: str = Form(...),
    employee_name: str = Form(default=""),
    stores: list[str] | None = Form(default=None),
    manual_keys: list[str] | None = Form(default=None),
    manual_amounts: list[str] | None = Form(default=None),
    manual_comments: list[str] | None = Form(default=None),
    session: Session = Depends(get_db),
    user=Depends(_payroll_manage),
):
    allowed_cities = get_economist_cities(user)
    if allowed_cities == []:
        return RedirectResponse(url="/economist/payroll", status_code=302)

    start_date = datetime.strptime(date_from, "%Y-%m-%d").date()
    end_date = datetime.strptime(date_to, "%Y-%m-%d").date()

    result = save_manual_adjustments(
        session,
        user_id=user.id,
        date_from=start_date,
        date_to=end_date,
        manual_keys=manual_keys,
        manual_amounts=manual_amounts,
        manual_comments=manual_comments,
        allowed_cities=None if user.is_admin else allowed_cities,
        request=request,
        user=user,
    )

    message = (
        f"Ручные корректировки сохранены: {result['saved']}. "
        f"Удалено: {result['deleted']}. Пропущено: {result['skipped']}."
    )
    return RedirectResponse(
        url=payroll_redirect_url(
            "/economist/payroll",
            date_from,
            date_to,
            employee_name=employee_name,
            stores=stores,
            message=message,
        ),
        status_code=302,
    )



@router.post("/economist/payroll/fix")
def economist_fix_payroll(
    request: Request,
    date_from: str = Form(...),
    date_to: str = Form(...),
    employee_name: str = Form(default=""),
    legal_entity: str = Form(default=""),
    comment: str = Form(default=""),
    stores: list[str] | None = Form(default=None),
    manual_keys: list[str] | None = Form(default=None),
    manual_amounts: list[str] | None = Form(default=None),
    manual_comments: list[str] | None = Form(default=None),
    session: Session = Depends(get_db),
    user=Depends(_payroll_manage),
):
    allowed_cities = get_economist_cities(user)

    if allowed_cities == []:
        return RedirectResponse(url="/economist/payroll", status_code=302)

    start_date = datetime.strptime(date_from, "%Y-%m-%d").date()
    end_date = datetime.strptime(date_to, "%Y-%m-%d").date()

    comment, refusal = period_comment_or_refusal(user, start_date, end_date, comment)
    if refusal:
        return RedirectResponse(
            url=payroll_redirect_url("/economist/payroll", date_from, date_to, employee_name, stores, refusal),
            status_code=302,
        )

    save_manual_adjustments(
        session,
        user_id=user.id,
        date_from=start_date,
        date_to=end_date,
        manual_keys=manual_keys,
        manual_amounts=manual_amounts,
        manual_comments=manual_comments,
        allowed_cities=None if user.is_admin else allowed_cities,
        request=request,
        user=user,
    )

    shifts_query = session.query(Shift).filter(
        Shift.shift_date >= start_date,
        Shift.shift_date <= end_date
    )

    if not user.is_admin and allowed_cities is not None:
        shifts_query = shifts_query.filter(
            Shift.city.in_(allowed_cities)
        )

    if stores:
        shifts_query = shifts_query.filter(
            Shift.store.in_(stores)
        )

    if employee_name.strip():
        shifts_query = shifts_query.filter(Shift.employee == employee_name.strip())

    shifts = shifts_query.order_by(
        Shift.employee.asc(),
        Shift.store.asc(),
        Shift.service.asc(),
        Shift.shift_date.asc()
    ).all()

    rates = load_rates(session)
    resolve = build_service_resolver(session)
    shifts = payable_shifts(shifts, resolve)  # комплектация и др. — не из timebook
    validation_errors = []
    checked_employees = set()

    for shift in shifts:
        shift_is_no_plan = is_no_plan_shift(shift)
        rate = pick_rate(rates, shift, resolve=resolve)

        if not rate and not is_no_plan_shift(shift):
            validation_errors.append(
                f"{shift.employee} / {shift.store} / {shift.shift_date} — не найдена ЧТС"
            )

        employee_key = normalize_text(shift.employee)

        if employee_key not in checked_employees:
            checked_employees.add(employee_key)

            requisite = session.query(Requisite).filter(
                Requisite.employee_name == employee_key,
                Requisite.is_active == True
            ).first()

            if not requisite:
                validation_errors.append(
                    f"{shift.employee} — отсутствуют активные реквизиты"
                )

            elif not requisite.is_verified:
                validation_errors.append(
                    f"{shift.employee} — реквизиты не проверены"
                )

    if validation_errors:
        return templates.TemplateResponse(
            request,
            "economist_payroll.html",
            {
                "user": user,
                "allowed_cities": allowed_cities,
                "rows": [],
                "date_from": date_from,
                "date_to": date_to,
                "employee_name": "",
                "employees": [],
                "stores": stores or [],
                "selected_stores": stores or [],
                "total_hours": 0,
                "total_amount": 0,
                "legal_entities": active_legal_entities(session),
                "error": "Обнаружены ошибки перед фиксацией",
                "message": None,
                "validation_errors": validation_errors
            }
        )

    run = PayrollRun(
        date_from=start_date,
        date_to=end_date,
        legal_entity=normalize_text(legal_entity) or None,
        status="fixed",
        created_by=user.id,
        fixed_by=user.id,
        created_at=now_utc(),
        fixed_at=now_utc(),
        comment=normalize_text(comment) or None
    )

    session.add(run)
    session.commit()
    session.refresh(run)

    # Расчёт строк — общий с фиксацией админа и выплатами (П3); у экономиста
    # исторически без ЛМК. Уже оплаченные смены (аванс) вычитаются.
    build_run_items(
        session, run, shifts,
        date_from=start_date, date_to=end_date, rates=rates, resolve=resolve,
        apply_lmk=False, apply_auto=True, manual="store", link_paid=True,
    )

    # АПД: подтверждённые премии (ещё не привязанные) → строкой в этот табель.
    apply_confirmed_payouts_to_run(session, request, user, run.id)

    create_audit_log(
        session,
        request,
        user,
        "payroll_run_created",
        "payroll_run",
        run.id,
        f"{run.date_from} - {run.date_to}",
        new_value={
            "status": run.status,
            "date_from": run.date_from,
            "date_to": run.date_to,
            "legal_entity": run.legal_entity,
            "items_count": len(shifts),
        },
        comment=run.comment,
    )
    session.commit()

    return RedirectResponse(
        url=f"/economist/payroll/runs/{run.id}",
        status_code=302
    )



@router.get("/admin/payroll", response_class=HTMLResponse)
def admin_payroll(
    request: Request,
    date_from: str = "",
    date_to: str = "",
    employee_name: str = "",
    stores: list[str] | None = Query(default=None),
    stores_submitted: str = "",
    message: str = "",
    session: Session = Depends(get_db),
    user=Depends(_payroll_manage),
):
    today = business_today()

    if not date_from and not date_to:
        current_week_monday = today - timedelta(days=today.weekday())
        default_date_to = current_week_monday - timedelta(days=1)
        default_date_from = default_date_to - timedelta(days=6)

        date_from = default_date_from.strftime("%Y-%m-%d")
        date_to = default_date_to.strftime("%Y-%m-%d")

    shifts_query = session.query(Shift)

    try:
        if date_from:
            shifts_query = shifts_query.filter(
                Shift.shift_date >= datetime.strptime(date_from, "%Y-%m-%d").date()
            )
        if date_to:
            shifts_query = shifts_query.filter(
                Shift.shift_date <= datetime.strptime(date_to, "%Y-%m-%d").date()
            )
    except ValueError:
        all_stores = session.query(Shift.store).distinct().order_by(Shift.store.asc()).all()
        store_list = [s[0] for s in all_stores]

        employees = session.query(Shift.employee).distinct().order_by(Shift.employee.asc()).all()
        employee_list = [e[0] for e in employees]

        return templates.TemplateResponse(
            request,
            "payroll.html",
            {
                "rows": [],
                "days": [],
                "date_from": date_from,
                "date_to": date_to,
                "employee_name": employee_name,
                "employees": employee_list,
                "stores": store_list,
                "selected_stores": stores or [],
                "total_hours": 0,
                "total_amount": 0,
                "legal_entities": active_legal_entities(session),
                "error": "Некорректный формат даты",
                "message": message or None
            }
        )

    start_date = datetime.strptime(date_from, "%Y-%m-%d").date()
    end_date = datetime.strptime(date_to, "%Y-%m-%d").date()

    if employee_name.strip():
        shifts_query = shifts_query.filter(Shift.employee == employee_name.strip())

    stores_was_submitted = stores_submitted == "1"

    if stores:
        shifts_query = shifts_query.filter(Shift.store.in_(stores))

    shifts = shifts_query.order_by(
        Shift.employee.asc(),
        Shift.store.asc(),
        Shift.shift_date.asc()
    ).all()

    employees = session.query(Shift.employee).distinct().order_by(Shift.employee.asc()).all()
    employee_list = [e[0] for e in employees]

    all_stores = session.query(Shift.store).distinct().order_by(Shift.store.asc()).all()
    store_list = [s[0] for s in all_stores]

    # Отправка формы — запомнить выбор магазинов в сессии (raw stores: список
    # отмеченных, либо None если не отмечено ни одной). "все" храним сентинелом.
    if stores_was_submitted:
        submitted_stores = stores if stores is not None else []
        if store_list and set(submitted_stores) == set(store_list):
            request.session[PAYROLL_STORES_SESSION_KEY] = PAYROLL_STORES_ALL
        else:
            request.session[PAYROLL_STORES_SESSION_KEY] = submitted_stores

    if stores is None and stores_was_submitted and not employee_name.strip():
        stores = []
        shifts = []

    if stores is None and not stores_was_submitted:
        # Обычный заход (без отправки формы) — восстановить прошлый выбор из
        # сессии; если ничего не запомнено — по умолчанию все магазины.
        remembered = request.session.get(PAYROLL_STORES_SESSION_KEY)
        if isinstance(remembered, list):
            stores = remembered
        else:
            stores = store_list
        if stores:
            shifts_query = shifts_query.filter(Shift.store.in_(stores))
            shifts = shifts_query.order_by(
                Shift.employee.asc(),
                Shift.store.asc(),
                Shift.shift_date.asc()
            ).all()
        else:
            shifts = []

    rates = load_rates(session)
    resolve = build_service_resolver(session)
    shifts = payable_shifts(shifts, resolve)  # комплектация и др. — не из timebook

    # Табель «по дням» (вид_табелей): строка = ФИО+Магазин+Услуга, часы по дням
    # периода. Расчёт сумм 1:1 как раньше — меняется только гранулярность строк,
    # итоги обязаны совпасть. Сетка по дням — общий механизм из schedule_grid.
    days = days_between(start_date, end_date)
    rows = build_payroll_rows(shifts, days, rates, include_city=False, resolve=resolve)
    rows.sort(key=lambda x: (x["employee_name"], x["store"], x["service"] or "", x["is_no_plan"]))

    for row in rows:
        row["lmk_amount"] = 0

    apply_auto_adjustments_to_rows(session, rows)
    apply_manual_adjustments_to_rows(session, rows, start_date, end_date)
    apply_lmk_charges_to_rows(session, rows, start_date, end_date)

    total_hours = sum(row["hours"] for row in rows)
    total_amount = sum(row["total_amount"] for row in rows)

    return templates.TemplateResponse(
        request,
        "payroll.html",
        {
            # П3: кнопки полумесяцев и табели за выбранный период.
            "period_links": half_month_links(start_date),
            "is_half_month_period": is_half_month(start_date, end_date),
            "period_runs": period_runs_for(session, start_date, end_date),
            "rows": rows,
            "days": days,
            "date_from": date_from,
            "date_to": date_to,
            "employee_name": employee_name,
            "employees": employee_list,
            "stores": store_list,
            "selected_stores": stores or [],
            "total_hours": total_hours,
            "total_amount": total_amount,
            "legal_entities": active_legal_entities(session),
            "error": None,
            "message": message or None
        }
    )




@router.post("/admin/payroll/manual-adjustments/save")
def admin_save_manual_adjustments(
    request: Request,
    date_from: str = Form(...),
    date_to: str = Form(...),
    employee_name: str = Form(default=""),
    stores: list[str] | None = Form(default=None),
    manual_keys: list[str] | None = Form(default=None),
    manual_amounts: list[str] | None = Form(default=None),
    manual_comments: list[str] | None = Form(default=None),
    session: Session = Depends(get_db),
    user=Depends(_payroll_manage),
):
    start_date = datetime.strptime(date_from, "%Y-%m-%d").date()
    end_date = datetime.strptime(date_to, "%Y-%m-%d").date()

    result = save_manual_adjustments(
        session,
        user_id=user.id,
        date_from=start_date,
        date_to=end_date,
        manual_keys=manual_keys,
        manual_amounts=manual_amounts,
        manual_comments=manual_comments,
        request=request,
        user=user,
    )

    message = (
        f"Ручные корректировки сохранены: {result['saved']}. "
        f"Удалено: {result['deleted']}."
    )
    return RedirectResponse(
        url=payroll_redirect_url(
            "/admin/payroll",
            date_from,
            date_to,
            employee_name=employee_name,
            stores=stores,
            message=message,
        ),
        status_code=302,
    )



@router.post("/admin/payroll/fix")
def fix_payroll(
    request: Request,
    date_from: str = Form(...),
    date_to: str = Form(...),
    employee_name: str = Form(default=""),
    legal_entity: str = Form(default=""),
    comment: str = Form(default=""),
    stores: list[str] | None = Form(default=None),
    manual_keys: list[str] | None = Form(default=None),
    manual_amounts: list[str] | None = Form(default=None),
    manual_comments: list[str] | None = Form(default=None),
    session: Session = Depends(get_db),
    user=Depends(_payroll_manage),
):
    start_date = datetime.strptime(date_from, "%Y-%m-%d").date()
    end_date = datetime.strptime(date_to, "%Y-%m-%d").date()

    comment, refusal = period_comment_or_refusal(user, start_date, end_date, comment)
    if refusal:
        return RedirectResponse(
            url=payroll_redirect_url("/admin/payroll", date_from, date_to, employee_name, stores, refusal),
            status_code=302,
        )

    save_manual_adjustments(
        session,
        user_id=user.id,
        date_from=start_date,
        date_to=end_date,
        manual_keys=manual_keys,
        manual_amounts=manual_amounts,
        manual_comments=manual_comments,
        request=request,
        user=user,
    )

    shifts_query = session.query(Shift).filter(
        Shift.shift_date >= start_date,
        Shift.shift_date <= end_date
    )

    if employee_name.strip():
        shifts_query = shifts_query.filter(Shift.employee == employee_name.strip())

    if stores:
        shifts_query = shifts_query.filter(Shift.store.in_(stores))

    shifts = shifts_query.all()

    rates = load_rates(session)
    resolve = build_service_resolver(session)
    shifts = payable_shifts(shifts, resolve)  # комплектация и др. — не из timebook
    validation_errors = []

    # АПД: pending-премии блокируют формирование табеля, пока не подтвердишь/отменишь.
    referral_pending = pending_payouts(session)

    checked_employees = set()

    for shift in shifts:

        # Проверка ЧТС
        rate = pick_rate(rates, shift, resolve=resolve)

        if not rate and not is_no_plan_shift(shift):
            # Кликабельная структура: клик → модалка создания ЧТС с предзаполнением.
            validation_errors.append({
                "type": "no_rate",
                "employee": shift.employee,
                "store": shift.store or "",
                "city": shift.city or "",
                "service": shift.service or "",
                "format": shift.format or "",
                "date": shift.shift_date.strftime("%Y-%m-%d") if shift.shift_date else "",
                "message": f"{shift.employee} / {shift.store} / {shift.shift_date} — не найдена ЧТС",
            })

        # Проверка реквизитов сотрудника
        employee_key = normalize_text(shift.employee)

        if employee_key not in checked_employees:

            checked_employees.add(employee_key)

            requisite = session.query(Requisite).filter(
                Requisite.employee_name == employee_key,
                Requisite.is_active == True
            ).first()

            if not requisite:
                validation_errors.append({
                    "type": "no_requisites",
                    "employee": shift.employee,
                    "message": f"{shift.employee} — отсутствуют активные реквизиты",
                })

            elif not requisite.is_verified:
                validation_errors.append({
                    "type": "unverified_requisites",
                    "employee": shift.employee,
                    "message": f"{shift.employee} — реквизиты не проверены",
                })

    if validation_errors or referral_pending:

        employees = sorted({
            normalize_text(s.employee)
            for s in session.query(Shift.employee).distinct().all()
            if s[0]
        })

        stores = sorted({
            normalize_text(s.store)
            for s in session.query(Shift.store).distinct().all()
            if s[0]
        })

        return templates.TemplateResponse(
            request,
            "payroll.html",
            {
                "referral_pending": referral_pending,
                "rows": [],
                "days": [],
                "employees": employees,
                "stores": stores,
                "selected_stores": [],
                "employee_name": "",
                "date_from": date_from,
                "date_to": date_to,
                "total_hours": 0,
                "total_amount": 0,
                "legal_entities": active_legal_entities(session),
                "message": None,
                "error": (
                    "Обнаружены ошибки перед фиксацией" if validation_errors
                    else "Требуется решение по премиям АПД перед фиксацией"
                ),
                "validation_errors": validation_errors
            }
        )

    run = PayrollRun(
        date_from=start_date,
        date_to=end_date,
        legal_entity=normalize_text(legal_entity) or None,
        status="fixed",
        created_by=user.id,
        fixed_by=user.id,
        created_at=now_utc(),
        fixed_at=now_utc(),
        comment=normalize_text(comment) or None
    )

    session.add(run)
    session.commit()
    session.refresh(run)

    shifts_query = session.query(Shift).filter(
        Shift.shift_date >= start_date,
        Shift.shift_date <= end_date
    )

    if employee_name.strip():
        shifts_query = shifts_query.filter(Shift.employee == employee_name.strip())

    if stores:
        shifts_query = shifts_query.filter(Shift.store.in_(stores))

    shifts = shifts_query.order_by(
        Shift.employee.asc(),
        Shift.store.asc(),
        Shift.service.asc(),
        Shift.shift_date.asc()
    ).all()

    build_run_items(
        session, run, shifts,
        date_from=start_date, date_to=end_date, rates=rates, resolve=resolve,
        apply_lmk=True, apply_auto=True, manual="store", link_paid=True,
    )

    # АПД: подтверждённые премии (ещё не привязанные) → строкой в этот табель.
    apply_confirmed_payouts_to_run(session, request, user, run.id)

    create_audit_log(
        session,
        request,
        user,
        "payroll_run_created",
        "payroll_run",
        run.id,
        f"{run.date_from} - {run.date_to}",
        new_value={
            "status": run.status,
            "date_from": run.date_from,
            "date_to": run.date_to,
            "legal_entity": run.legal_entity,
            "items_count": len(shifts),
        },
        comment=run.comment,
    )
    session.commit()

    return RedirectResponse(
        url=f"/admin/payroll/runs/{run.id}",
        status_code=302
    )




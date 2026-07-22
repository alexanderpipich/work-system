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
from lmk_charges import apply_lmk_charges_to_rows, get_lmk_charge_for_employee
from manual_adjustments import (
    apply_manual_adjustments_to_rows,
    get_manual_adjustments_map,
    save_manual_adjustments,
)
from models import PayrollRun, PayrollRunItem, Requisite, Shift
from payroll_adjustments import apply_auto_adjustments_to_rows, get_payroll_auto_adjustments
from shift_helpers import is_no_plan_shift
from time_helpers import business_today, now_utc
from rbac import canonical_role, require_permission
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
    message: str = "",
    session: Session = Depends(get_db),
    user=Depends(require_payroll_view),
):
    role = canonical_role(user)
    if request.url.path.startswith("/economist") and role not in {"economist", "superadmin"}:
        return RedirectResponse("/", status_code=302)
    if request.url.path.startswith("/hr") and role not in {"hr_lead", "hr_manager"}:
        return RedirectResponse("/", status_code=302)
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

    if stores is None:
        stores = store_list
        shifts_query = shifts_query.filter(Shift.store.in_(stores))
        shifts = shifts_query.order_by(
            Shift.city.asc(),
            Shift.store.asc(),
            Shift.employee.asc(),
            Shift.shift_date.asc()
        ).all()

    rates = load_rates(session)
    payroll_map = {}

    for shift in shifts:
        shift_is_no_plan = is_no_plan_shift(shift)
        rate = pick_rate(rates, shift)
        rate_value = rate.hourly_rate if rate else 0
        amount = 0 if shift_is_no_plan else (shift.hours * rate_value if rate else 0)

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

    if not user.is_admin:
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
    validation_errors = []
    checked_employees = set()

    for shift in shifts:
        shift_is_no_plan = is_no_plan_shift(shift)
        rate = pick_rate(rates, shift)

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

    manual_map = get_manual_adjustments_map(session, start_date, end_date)
    used_manual_keys = set()
    used_auto_keys = set()

    for shift in shifts:
        shift_is_no_plan = is_no_plan_shift(shift)
        rate = pick_rate(rates, shift)
        rate_value = rate.hourly_rate if rate else 0
        amount = 0 if shift_is_no_plan else shift.hours * rate_value
        manual_key = (normalize_text(shift.employee), normalize_text(shift.store))
        other_amount = 0
        auto_amount = 0

        if manual_key not in used_manual_keys:
            manual_adjustment = manual_map.get(manual_key)
            other_amount = manual_adjustment.amount if manual_adjustment else 0
            used_manual_keys.add(manual_key)

        if manual_key not in used_auto_keys:
            auto_amount = get_payroll_auto_adjustments(
                session,
                shift.employee,
                shift.store,
            )["approved_amount"]
            used_auto_keys.add(manual_key)

        item = PayrollRunItem(
            run_id=run.id,
            employee_name=shift.employee,
            store=shift.store,
            service=shift.service,
            shift_date=shift.shift_date,
            hours=shift.hours,
            rate=0 if is_no_plan_shift(shift) else rate_value,
            amount=amount,
            other_amount=other_amount,
            auto_adjustments_amount=auto_amount,
            manual_adjustments_amount=other_amount,
            lmk_amount=0,
            total_amount=amount + other_amount + auto_amount,
            comment=None if (rate or is_no_plan_shift(shift)) else "Не найдена ЧТС"
        )

        session.add(item)

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
    payroll_map = {}

    for shift in shifts:
        shift_is_no_plan = is_no_plan_shift(shift)
        rate = pick_rate(rates, shift)
        rate_value = rate.hourly_rate if rate else 0
        amount = 0 if shift_is_no_plan else (shift.hours * rate_value if rate else 0)

        key = (shift.employee, shift.store, shift_is_no_plan)

        if key not in payroll_map:
            payroll_map[key] = {
                "employee_name": shift.employee,
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
    rows.sort(key=lambda x: (x["employee_name"], x["store"], x["is_no_plan"]))

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
    validation_errors = []

    checked_employees = set()

    for shift in shifts:

        # Проверка ЧТС
        rate = pick_rate(rates, shift)

        if not rate and not is_no_plan_shift(shift):
            validation_errors.append(
                f"{shift.employee} / {shift.store} / {shift.shift_date} — не найдена ЧТС"
            )

        # Проверка реквизитов сотрудника
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
                "rows": [],
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
                "error": "Обнаружены ошибки перед фиксацией",
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

    manual_map = get_manual_adjustments_map(session, start_date, end_date)

    used_manual_keys = set()
    used_auto_keys = set()
    used_lmk_employees = set()

    for shift in shifts:

        rate = pick_rate(rates, shift)

        rate_value = rate.hourly_rate if rate else 0

        amount = 0 if is_no_plan_shift(shift) else shift.hours * rate_value
        manual_key = (normalize_text(shift.employee), normalize_text(shift.store))
        other_amount = 0
        auto_amount = 0
        lmk_amount = 0
        lmk_charge = None

        if manual_key not in used_manual_keys:
            manual_adjustment = manual_map.get(manual_key)
            other_amount = manual_adjustment.amount if manual_adjustment else 0
            used_manual_keys.add(manual_key)

        if manual_key not in used_auto_keys:
            auto_amount = get_payroll_auto_adjustments(
                session,
                shift.employee,
                shift.store,
            )["approved_amount"]
            used_auto_keys.add(manual_key)

        employee_lmk_key = normalize_text(shift.employee)
        if employee_lmk_key not in used_lmk_employees:
            lmk_charge, lmk_amount = get_lmk_charge_for_employee(
                session,
                shift.employee,
                start_date,
                end_date,
            )
            if lmk_amount:
                used_lmk_employees.add(employee_lmk_key)

        item = PayrollRunItem(
            run_id=run.id,
            employee_name=shift.employee,
            store=shift.store,
            service=shift.service,
            shift_date=shift.shift_date,
            hours=shift.hours,
            rate=0 if is_no_plan_shift(shift) else rate_value,
            amount=amount,
            other_amount=other_amount,
            auto_adjustments_amount=auto_amount,
            manual_adjustments_amount=other_amount,
            lmk_amount=lmk_amount,
            total_amount=amount + other_amount + auto_amount - lmk_amount,
            comment=None if (rate or is_no_plan_shift(shift)) else "Не найдена ЧТС"
        )

        session.add(item)

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




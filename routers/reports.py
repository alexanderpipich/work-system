from datetime import date, datetime, timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import and_, distinct, func
from sqlalchemy.orm import Session

from access import accessible_employee_names, get_economist_cities
from dependencies import get_db, require_admin_user, require_economist_user
from document_helpers import (
    STATUS_LABELS,
    build_document_registry_rows,
    computed_document_status,
    economist_employee_names,
    employee_names,
)
from rbac import canonical_role, require_permission
from models import (
    DocumentType,
    EmployeeDocument,
    ManualPayrollAdjustment,
    MedicalBookCharge,
    MedicalBookPayment,
    PayrollAdjustment,
    PayrollRun,
    PayrollRunItem,
    Shift,
    User,
)
from time_helpers import business_today
from utils import normalize_text


router = APIRouter()
templates = Jinja2Templates(directory="templates")
require_reports_view = require_permission("reports.view", audit_denied=True)
HR_REPORTS = {"documents", "missing-documents", "expired-documents"}


REPORT_CARDS = [
    ("hours-by-city", "Часы по городам", "Смены, часы, сотрудники и сумма payroll по городам"),
    ("hours-by-store", "Часы по магазинам", "Часы и выплаты по магазинам с фильтром по городу"),
    ("payroll-by-employee", "Выплаты по сотрудникам", "Разбивка payroll по сотрудникам"),
    ("payroll-by-legal-entity", "Выплаты по юрлицам", "Суммы payroll по юридическим лицам"),
    ("auto-adjustments", "Автокорректировки", "Pending, approved и applied auto adjustments"),
    ("manual-adjustments", "Ручные корректировки", "Ручные суммы, статусы и примененные табели"),
    ("lmk", "ЛМК удержания", "Остатки, удержано и история списаний"),
    ("documents", "Документы", "Статусы загруженных документов сотрудников"),
    ("missing-documents", "Отсутствующие документы", "Обязательные документы, которых не хватает"),
    ("expired-documents", "Истекающие документы", "Истекшие и истекающие в ближайшие 30 дней"),
]


def _today():
    return business_today()


def _parse_date(value, default):
    try:
        return datetime.strptime(value, "%Y-%m-%d").date() if value else default
    except ValueError:
        return default


def _filters(request):
    today = _today()
    default_from = today - timedelta(days=30)
    return {
        "date_from": _parse_date(request.query_params.get("date_from"), default_from),
        "date_to": _parse_date(request.query_params.get("date_to"), today),
        "city": normalize_text(request.query_params.get("city")),
        "store": normalize_text(request.query_params.get("store")),
        "status": normalize_text(request.query_params.get("status")) or "all",
    }


def _base_context(request, base_path, back_url, title, filters, **extra):
    context = {
        "base_path": base_path,
        "back_url": back_url,
        "title": title,
        "filters": filters,
        "rows": [],
        "totals": {},
        "columns": [],
        "report_kind": "",
    }
    context.update(extra)
    return context


def _scope_allowed_cities(user, economist):
    if not economist or canonical_role(user) in {"superadmin", "hr_lead"}:
        return None
    return get_economist_cities(user)


def _apply_shift_filters(query, filters, allowed_cities=None):
    query = query.filter(
        Shift.shift_date >= filters["date_from"],
        Shift.shift_date <= filters["date_to"],
    )
    if allowed_cities is not None:
        query = query.filter(Shift.city.in_(allowed_cities or ["__none__"]))
    if filters["city"]:
        query = query.filter(Shift.city == filters["city"])
    if filters["store"]:
        query = query.filter(Shift.store == filters["store"])
    return query


def _shift_item_join_condition():
    return and_(
        Shift.employee == PayrollRunItem.employee_name,
        Shift.store == PayrollRunItem.store,
        Shift.service == PayrollRunItem.service,
        Shift.shift_date == PayrollRunItem.shift_date,
    )


def _adjustment_shift_join_condition():
    return and_(
        Shift.employee == PayrollAdjustment.employee_name,
        Shift.store == PayrollAdjustment.store,
        Shift.service == PayrollAdjustment.service,
        Shift.shift_date == PayrollAdjustment.shift_date,
    )


def _cities(session, allowed_cities=None):
    query = session.query(Shift.city).filter(Shift.city != None).distinct()
    if allowed_cities is not None:
        query = query.filter(Shift.city.in_(allowed_cities or ["__none__"]))
    return [row[0] for row in query.order_by(Shift.city.asc()).all() if row[0]]


def _stores(session, allowed_cities=None):
    query = session.query(Shift.store).filter(Shift.store != None).distinct()
    if allowed_cities is not None:
        query = query.filter(Shift.city.in_(allowed_cities or ["__none__"]))
    return [row[0] for row in query.order_by(Shift.store.asc()).all() if row[0]]


def _money(value):
    return round(value or 0, 2)


def _hours_by_city(session, filters, allowed_cities):
    city_expr = func.coalesce(Shift.city, "Не указано")
    query = session.query(
        city_expr.label("city"),
        func.count(Shift.id).label("shift_count"),
        func.coalesce(func.sum(Shift.hours), 0).label("hours"),
        func.count(distinct(Shift.employee)).label("employees_count"),
    )
    query = _apply_shift_filters(query, filters, allowed_cities).group_by(city_expr)

    payroll_query = session.query(
        city_expr.label("city"),
        func.coalesce(func.sum(PayrollRunItem.total_amount), 0).label("payroll_amount"),
    ).join(PayrollRunItem, _shift_item_join_condition())
    payroll_query = _apply_shift_filters(payroll_query, filters, allowed_cities).group_by(city_expr)
    payroll_by_city = {row.city: row.payroll_amount for row in payroll_query.all()}

    rows = []
    for row in query.order_by(city_expr.asc()).all():
        rows.append({
            "city": row.city,
            "shift_count": row.shift_count,
            "hours": row.hours,
            "employees_count": row.employees_count,
            "payroll_amount": _money(payroll_by_city.get(row.city)),
        })
    return rows


def _hours_by_store(session, filters, allowed_cities):
    query = session.query(
        Shift.store.label("store"),
        func.coalesce(Shift.city, "Не указано").label("city"),
        func.count(Shift.id).label("shift_count"),
        func.coalesce(func.sum(Shift.hours), 0).label("hours"),
        func.count(distinct(Shift.employee)).label("employees_count"),
    )
    query = _apply_shift_filters(query, filters, allowed_cities).group_by(Shift.store, Shift.city)

    payroll_query = session.query(
        Shift.store.label("store"),
        func.coalesce(Shift.city, "Не указано").label("city"),
        func.coalesce(func.sum(PayrollRunItem.total_amount), 0).label("payroll_amount"),
    ).join(PayrollRunItem, _shift_item_join_condition())
    payroll_query = _apply_shift_filters(payroll_query, filters, allowed_cities).group_by(Shift.store, Shift.city)
    payroll = {(row.store, row.city): row.payroll_amount for row in payroll_query.all()}

    rows = []
    for row in query.order_by(Shift.city.asc(), Shift.store.asc()).all():
        rows.append({
            "store": row.store,
            "city": row.city,
            "shift_count": row.shift_count,
            "hours": row.hours,
            "employees_count": row.employees_count,
            "payroll_amount": _money(payroll.get((row.store, row.city))),
        })
    return rows


def _payroll_base_query(session, filters, allowed_cities):
    query = session.query(PayrollRunItem).join(
        PayrollRun,
        PayrollRun.id == PayrollRunItem.run_id,
    ).outerjoin(Shift, _shift_item_join_condition())
    query = query.filter(
        PayrollRunItem.shift_date >= filters["date_from"],
        PayrollRunItem.shift_date <= filters["date_to"],
    )
    if filters["status"] != "all":
        query = query.filter(PayrollRun.status == filters["status"])
    if allowed_cities is not None:
        query = query.filter(Shift.city.in_(allowed_cities or ["__none__"]))
    if filters["city"]:
        query = query.filter(Shift.city == filters["city"])
    if filters["store"]:
        query = query.filter(PayrollRunItem.store == filters["store"])
    return query


def _payroll_by_employee(session, filters, allowed_cities):
    query = _payroll_base_query(session, filters, allowed_cities).with_entities(
        PayrollRunItem.employee_name.label("employee_name"),
        func.coalesce(func.sum(PayrollRunItem.hours), 0).label("hours"),
        func.coalesce(func.sum(PayrollRunItem.amount), 0).label("amount"),
        func.coalesce(func.sum(PayrollRunItem.auto_adjustments_amount), 0).label("auto_amount"),
        func.coalesce(func.sum(PayrollRunItem.manual_adjustments_amount), 0).label("manual_amount"),
        func.coalesce(func.sum(PayrollRunItem.lmk_amount), 0).label("lmk_amount"),
        func.coalesce(func.sum(PayrollRunItem.total_amount), 0).label("total_amount"),
    ).group_by(PayrollRunItem.employee_name)

    return [row._asdict() for row in query.order_by(PayrollRunItem.employee_name.asc()).all()]


def _payroll_by_legal_entity(session, filters, allowed_cities):
    legal_expr = func.coalesce(PayrollRun.legal_entity, User.legal_entity, "Не указано")
    query = _payroll_base_query(session, filters, allowed_cities).outerjoin(
        User,
        User.employee_name == PayrollRunItem.employee_name,
    ).with_entities(
        legal_expr.label("legal_entity"),
        func.count(distinct(PayrollRunItem.employee_name)).label("employees_count"),
        func.coalesce(func.sum(PayrollRunItem.hours), 0).label("hours"),
        func.coalesce(func.sum(PayrollRunItem.amount), 0).label("amount"),
        func.coalesce(func.sum(PayrollRunItem.auto_adjustments_amount + PayrollRunItem.manual_adjustments_amount), 0).label("adjustments_amount"),
        func.coalesce(func.sum(PayrollRunItem.lmk_amount), 0).label("lmk_amount"),
        func.coalesce(func.sum(PayrollRunItem.total_amount), 0).label("total_amount"),
    ).group_by(legal_expr)

    return [row._asdict() for row in query.order_by(legal_expr.asc()).all()]


def _auto_adjustments(session, filters, allowed_cities):
    query = session.query(PayrollAdjustment)
    if allowed_cities is not None or filters["city"] or filters["store"]:
        query = query.join(Shift, _adjustment_shift_join_condition())
    query = query.filter(
        PayrollAdjustment.shift_date >= filters["date_from"],
        PayrollAdjustment.shift_date <= filters["date_to"],
    )
    if filters["status"] != "all":
        query = query.filter(PayrollAdjustment.status == filters["status"])
    if allowed_cities is not None:
        query = query.filter(Shift.city.in_(allowed_cities or ["__none__"]))
    if filters["city"]:
        query = query.filter(Shift.city == filters["city"])
    if filters["store"]:
        query = query.filter(PayrollAdjustment.store == filters["store"])

    total_query = query.with_entities(
        PayrollAdjustment.status.label("status"),
        func.coalesce(func.sum(PayrollAdjustment.diff_amount), 0).label("amount"),
        func.coalesce(func.sum(PayrollAdjustment.diff_hours), 0).label("hours"),
        func.count(PayrollAdjustment.id).label("count"),
    ).group_by(PayrollAdjustment.status)

    totals = {row.status: row._asdict() for row in total_query.all()}
    rows = query.order_by(PayrollAdjustment.created_at.desc(), PayrollAdjustment.id.desc()).limit(500).all()
    return rows, totals


def _manual_adjustments(session, filters, allowed_cities):
    query = session.query(ManualPayrollAdjustment)
    joined_shift = False
    if allowed_cities is not None or filters["city"] or filters["store"]:
        query = query.join(
            Shift,
            and_(
                Shift.employee == ManualPayrollAdjustment.employee_name,
                Shift.store == ManualPayrollAdjustment.store,
                Shift.shift_date >= ManualPayrollAdjustment.date_from,
                Shift.shift_date <= ManualPayrollAdjustment.date_to,
            ),
        )
        joined_shift = True
    query = query.filter(
        ManualPayrollAdjustment.date_from <= filters["date_to"],
        ManualPayrollAdjustment.date_to >= filters["date_from"],
    )
    if filters["status"] != "all":
        query = query.filter(ManualPayrollAdjustment.status == filters["status"])
    if allowed_cities is not None:
        query = query.filter(Shift.city.in_(allowed_cities or ["__none__"]))
    if filters["city"]:
        query = query.filter(Shift.city == filters["city"])
    if filters["store"]:
        query = query.filter(ManualPayrollAdjustment.store == filters["store"])

    if joined_shift:
        scoped_ids = query.with_entities(ManualPayrollAdjustment.id).distinct().subquery()
        scoped_query = session.query(ManualPayrollAdjustment).join(
            scoped_ids,
            scoped_ids.c.id == ManualPayrollAdjustment.id,
        )
    else:
        scoped_query = query

    total_query = scoped_query.with_entities(
        ManualPayrollAdjustment.status.label("status"),
        func.coalesce(func.sum(ManualPayrollAdjustment.amount), 0).label("amount"),
        func.count(distinct(ManualPayrollAdjustment.id)).label("count"),
    ).group_by(ManualPayrollAdjustment.status)
    totals = {row.status: row._asdict() for row in total_query.all()}
    rows = scoped_query.order_by(ManualPayrollAdjustment.created_at.desc(), ManualPayrollAdjustment.id.desc()).limit(500).all()
    return rows, totals


def _lmk(session, allowed_cities):
    employee_filter = None
    if allowed_cities is not None:
        employee_filter = economist_employee_names(session, allowed_cities)

    charge_query = session.query(MedicalBookCharge)
    payment_query = session.query(MedicalBookPayment)
    if employee_filter is not None:
        charge_query = charge_query.filter(MedicalBookCharge.employee_name.in_(employee_filter or ["__none__"]))
        payment_query = payment_query.filter(MedicalBookPayment.employee_name.in_(employee_filter or ["__none__"]))

    rows = charge_query.order_by(MedicalBookCharge.employee_name.asc(), MedicalBookCharge.id.desc()).limit(500).all()
    paid_total = payment_query.with_entities(func.coalesce(func.sum(MedicalBookPayment.amount), 0)).scalar() or 0
    remaining_total = charge_query.with_entities(func.coalesce(func.sum(MedicalBookCharge.remaining_amount), 0)).scalar() or 0
    return rows, {"paid_total": paid_total, "remaining_total": remaining_total}


def _document_employee_scope(session, allowed_cities):
    return employee_names(session) if allowed_cities is None else economist_employee_names(session, allowed_cities)


def _documents_report(session, allowed_cities, scoped_employees=None):
    employees = scoped_employees if scoped_employees is not None else _document_employee_scope(session, allowed_cities)
    rows = build_document_registry_rows(session, employees, status="all")
    return rows


def _missing_documents_report(session, allowed_cities, scoped_employees=None):
    rows = [
        row for row in _documents_report(session, allowed_cities, scoped_employees)
        if row["status"] in {"missing", "rejected", "archived"}
    ]
    grouped = {}
    for row in rows:
        bucket = grouped.setdefault(row["employee_name"], {
            "employee_name": row["employee_name"],
            "citizenship": row["citizenship"],
            "missing_documents": [],
        })
        bucket["missing_documents"].append(row["type"].name)
    return list(grouped.values())


def _expired_documents_report(session, allowed_cities, scoped_employees=None):
    today = _today()
    rows = []
    for row in _documents_report(session, allowed_cities, scoped_employees):
        document = row["document"]
        if not document or document.is_permanent or not document.expiry_date:
            continue
        days_left = (document.expiry_date - today).days
        if days_left <= 30:
            rows.append({
                "employee_name": row["employee_name"],
                "document_name": row["type"].name,
                "expiry_date": document.expiry_date,
                "days_left": days_left,
                "status": "expired" if days_left < 0 else "expires_soon",
            })
    return rows


def _dashboard(request, user, economist=False):
    hr_view = request.url.path.startswith("/hr")
    base_path = "/hr/reports" if hr_view else ("/economist/reports" if economist else "/admin/reports")
    back_url = "/hr" if hr_view else ("/economist" if economist else "/admin")
    template = "economist_reports_dashboard.html" if economist else "reports_dashboard.html"
    cards = [card for card in REPORT_CARDS if card[0] in HR_REPORTS] if hr_view else REPORT_CARDS
    return templates.TemplateResponse(
        request, template,
        {"user": user, "cards": cards, "base_path": base_path, "back_url": back_url},
    )


def _render_report(request, session, user, report, economist=False):
    if request.url.path.startswith("/hr") and report not in HR_REPORTS:
        return RedirectResponse(url="/hr/reports", status_code=302)
    hr_view = request.url.path.startswith("/hr")
    filters = _filters(request)
    allowed_cities = _scope_allowed_cities(user, economist)
    scoped_employees = accessible_employee_names(session, user) if hr_view and canonical_role(user) == "hr_manager" else None
    base_path = "/hr/reports" if hr_view else ("/economist/reports" if economist else "/admin/reports")
    back_url = base_path
    common = {
        "cities": _cities(session, allowed_cities),
        "stores": _stores(session, allowed_cities),
        "statuses": ["all", "fixed", "sent", "closed", "pending", "approved", "applied", "active", "completed", "cancelled", "rejected"],
    }

    if report == "hours-by-city":
        rows = _hours_by_city(session, filters, allowed_cities)
        context = _base_context(request, base_path, back_url, "Часы по городам", filters, rows=rows, columns=[
            ("city", "Город"), ("shift_count", "Смен"), ("hours", "Часы"), ("employees_count", "Сотрудников"), ("payroll_amount", "Payroll"),
        ], report_kind="table", **common)
    elif report == "hours-by-store":
        rows = _hours_by_store(session, filters, allowed_cities)
        context = _base_context(request, base_path, back_url, "Часы по магазинам", filters, rows=rows, columns=[
            ("store", "Магазин"), ("city", "Город"), ("shift_count", "Смен"), ("hours", "Часы"), ("employees_count", "Сотрудников"), ("payroll_amount", "Payroll"),
        ], report_kind="table", **common)
    elif report == "payroll-by-employee":
        rows = _payroll_by_employee(session, filters, allowed_cities)
        context = _base_context(request, base_path, back_url, "Выплаты по сотрудникам", filters, rows=rows, columns=[
            ("employee_name", "Сотрудник"), ("hours", "Часы"), ("amount", "Основная сумма"), ("auto_amount", "Авто"), ("manual_amount", "Ручные"), ("lmk_amount", "ЛМК"), ("total_amount", "Итого"),
        ], report_kind="table", **common)
    elif report == "payroll-by-legal-entity":
        rows = _payroll_by_legal_entity(session, filters, allowed_cities)
        context = _base_context(request, base_path, back_url, "Выплаты по юрлицам", filters, rows=rows, columns=[
            ("legal_entity", "Юрлицо"), ("employees_count", "Сотрудников"), ("hours", "Часы"), ("amount", "Основная сумма"), ("adjustments_amount", "Корректировки"), ("lmk_amount", "ЛМК"), ("total_amount", "Итого"),
        ], report_kind="table", **common)
    elif report == "auto-adjustments":
        rows, totals = _auto_adjustments(session, filters, allowed_cities)
        context = _base_context(request, base_path, back_url, "Автокорректировки", filters, rows=rows, totals=totals, report_kind="auto_adjustments", **common)
    elif report == "manual-adjustments":
        rows, totals = _manual_adjustments(session, filters, allowed_cities)
        context = _base_context(request, base_path, back_url, "Ручные корректировки", filters, rows=rows, totals=totals, report_kind="manual_adjustments", **common)
    elif report == "lmk":
        rows, totals = _lmk(session, allowed_cities)
        context = _base_context(request, base_path, back_url, "ЛМК удержания", filters, rows=rows, totals=totals, report_kind="lmk", **common)
    elif report == "documents":
        rows = _documents_report(session, allowed_cities, scoped_employees)
        context = _base_context(request, base_path, back_url, "Документы", filters, rows=rows, report_kind="documents", **common)
    elif report == "missing-documents":
        rows = _missing_documents_report(session, allowed_cities, scoped_employees)
        context = _base_context(request, base_path, back_url, "Отсутствующие документы", filters, rows=rows, report_kind="missing_documents", **common)
    elif report == "expired-documents":
        rows = _expired_documents_report(session, allowed_cities, scoped_employees)
        context = _base_context(request, base_path, back_url, "Истекающие документы", filters, rows=rows, report_kind="expired_documents", **common)
    else:
        return RedirectResponse(url=base_path, status_code=302)

    return templates.TemplateResponse(request, "report_table.html", context)



@router.get("/admin/reports", response_class=HTMLResponse)
def admin_reports(
    request: Request,
    admin=Depends(require_admin_user),
):
    return _dashboard(request, admin, economist=False)


@router.get("/economist/reports", response_class=HTMLResponse)
def economist_reports(
    request: Request,
    user=Depends(require_economist_user),
):
    return _dashboard(request, user, economist=True)


@router.get("/admin/reports/{report}", response_class=HTMLResponse)
def admin_report(
    request: Request,
    report: str,
    session: Session = Depends(get_db),
    admin=Depends(require_admin_user),
):
    return _render_report(request, session, admin, report, economist=False)


@router.get("/economist/reports/{report}", response_class=HTMLResponse)
def economist_report(
    request: Request,
    report: str,
    session: Session = Depends(get_db),
    user=Depends(require_economist_user),
):
    return _render_report(request, session, user, report, economist=True)

@router.get("/hr/reports", response_class=HTMLResponse)
def hr_reports(request: Request, user=Depends(require_reports_view)):
    if canonical_role(user) not in {"hr_lead", "hr_manager"}:
        return RedirectResponse(url="/", status_code=302)
    return _dashboard(request, user, economist=True)


@router.get("/hr/reports/{report}", response_class=HTMLResponse)
def hr_report(request: Request, report: str, session: Session = Depends(get_db), user=Depends(require_reports_view)):
    if canonical_role(user) not in {"hr_lead", "hr_manager"}:
        return RedirectResponse(url="/", status_code=302)
    return _render_report(request, session, user, report, economist=True)

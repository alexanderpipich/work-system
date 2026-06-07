from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import and_, distinct, func
from sqlalchemy.orm import Session

from access import get_economist_cities
from dependencies import get_db, require_admin_user, require_economist_user
from document_helpers import build_document_registry_rows, economist_employee_names, employee_names
from models import (
    DocumentType,
    MedicalBookCharge,
    MedicalBookPayment,
    PayrollAdjustment,
    PayrollRun,
    PayrollRunItem,
    Requisite,
    Shift,
)
from time_helpers import business_today


router = APIRouter()
templates = Jinja2Templates(directory="templates")


def _today():
    return business_today()


def _parse_date(value, default):
    try:
        return datetime.strptime(value, "%Y-%m-%d").date() if value else default
    except ValueError:
        return default


def _filters(request):
    today = _today()
    return {
        "date_from": _parse_date(request.query_params.get("date_from"), today - timedelta(days=56)),
        "date_to": _parse_date(request.query_params.get("date_to"), today),
    }


def _allowed_cities(user, economist):
    if not economist or user.is_admin:
        return None
    return get_economist_cities(user)


def _employee_scope(session, allowed_cities):
    if allowed_cities is None:
        return employee_names(session)
    return economist_employee_names(session, allowed_cities)


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


def _scope_shift_query(query, allowed_cities):
    if allowed_cities is None:
        return query
    return query.filter(Shift.city.in_(allowed_cities or ["__none__"]))


def _scope_payroll_query(query, allowed_cities):
    if allowed_cities is None:
        return query
    return query.join(Shift, _shift_item_join_condition()).filter(
        Shift.city.in_(allowed_cities or ["__none__"])
    )


def _scope_adjustment_query(query, allowed_cities):
    if allowed_cities is None:
        return query
    return query.join(Shift, _adjustment_shift_join_condition()).filter(
        Shift.city.in_(allowed_cities or ["__none__"])
    )


def _kpi(session, filters, allowed_cities, employees):
    week_from = _today() - timedelta(days=6)

    active_employees_query = session.query(func.count(distinct(Shift.employee))).filter(
        Shift.shift_date >= filters["date_from"],
        Shift.shift_date <= filters["date_to"],
    )
    active_employees = _scope_shift_query(active_employees_query, allowed_cities).scalar() or 0

    hours_week_query = session.query(func.coalesce(func.sum(Shift.hours), 0)).filter(
        Shift.shift_date >= week_from,
        Shift.shift_date <= _today(),
    )
    hours_week = _scope_shift_query(hours_week_query, allowed_cities).scalar() or 0

    payroll_query = session.query(func.coalesce(func.sum(PayrollRunItem.total_amount), 0)).filter(
        PayrollRunItem.shift_date >= filters["date_from"],
        PayrollRunItem.shift_date <= filters["date_to"],
    )
    payroll_total = _scope_payroll_query(payroll_query, allowed_cities).scalar() or 0

    pending_adjustments_query = session.query(func.count(PayrollAdjustment.id)).filter(
        PayrollAdjustment.status == "pending",
        PayrollAdjustment.shift_date >= filters["date_from"],
        PayrollAdjustment.shift_date <= filters["date_to"],
    )
    pending_adjustments = _scope_adjustment_query(pending_adjustments_query, allowed_cities).scalar() or 0

    document_rows = build_document_registry_rows(session, employees, status="all")
    missing_documents = len([
        row for row in document_rows
        if row["status"] in {"missing", "rejected", "archived"}
    ])
    expired_documents = len([row for row in document_rows if row["status"] == "expired"])

    lmk_query = session.query(func.coalesce(func.sum(MedicalBookCharge.remaining_amount), 0)).filter(
        MedicalBookCharge.status == "active",
        MedicalBookCharge.remaining_amount > 0,
    )
    if employees is not None:
        lmk_query = lmk_query.filter(MedicalBookCharge.employee_name.in_(employees or ["__none__"]))
    lmk_debt = lmk_query.scalar() or 0

    sent_count = _payroll_run_count(session, "sent", allowed_cities, filters)
    closed_count = _payroll_run_count(session, "closed", allowed_cities, filters)

    return [
        {"label": "Активные сотрудники", "value": active_employees, "tone": "blue"},
        {"label": "Часы за неделю", "value": round(hours_week, 2), "tone": "blue"},
        {"label": "Выплаты за период", "value": round(payroll_total, 2), "tone": "green"},
        {"label": "Корректировки pending", "value": pending_adjustments, "tone": "warn"},
        {"label": "Не хватает документов", "value": missing_documents, "tone": "bad"},
        {"label": "Документы истекли", "value": expired_documents, "tone": "bad"},
        {"label": "Остаток ЛМК", "value": round(lmk_debt, 2), "tone": "warn"},
        {"label": "Табели в оплате", "value": sent_count, "tone": "green"},
        {"label": "Закрытые табели", "value": closed_count, "tone": "muted"},
    ]


def _payroll_run_count(session, status, allowed_cities, filters):
    query = session.query(func.count(distinct(PayrollRun.id))).join(
        PayrollRunItem,
        PayrollRunItem.run_id == PayrollRun.id,
    ).filter(
        PayrollRun.status == status,
        PayrollRunItem.shift_date >= filters["date_from"],
        PayrollRunItem.shift_date <= filters["date_to"],
    )
    query = _scope_payroll_query(query, allowed_cities)
    return query.scalar() or 0


def _alerts(session, filters, allowed_cities, employees):
    pending_adjustments = _scope_adjustment_query(
        session.query(func.count(PayrollAdjustment.id)).filter(PayrollAdjustment.status == "pending"),
        allowed_cities,
    ).scalar() or 0

    document_rows = build_document_registry_rows(session, employees, status="all")
    missing_documents = len([
        row for row in document_rows
        if row["status"] in {"missing", "rejected", "archived"}
    ])
    expired_documents = len([row for row in document_rows if row["status"] == "expired"])

    requisites_query = session.query(func.count(Requisite.id)).filter(
        Requisite.is_active == True,
        Requisite.is_verified == False,
    )
    if employees is not None:
        requisites_query = requisites_query.filter(Requisite.employee_name.in_(employees or ["__none__"]))
    unverified_requisites = requisites_query.scalar() or 0

    no_plan_query = session.query(func.count(Shift.id)).filter(
        Shift.request_type == "Смена без плана",
        Shift.shift_date >= filters["date_from"],
        Shift.shift_date <= filters["date_to"],
    )
    shifts_without_plan = _scope_shift_query(no_plan_query, allowed_cities).scalar() or 0

    fixed_payroll = _payroll_run_count(session, "fixed", allowed_cities, filters)

    lmk_query = session.query(func.count(MedicalBookCharge.id)).filter(
        MedicalBookCharge.status == "active",
        MedicalBookCharge.remaining_amount > 0,
        MedicalBookCharge.start_month < _today().replace(day=1),
    )
    if employees is not None:
        lmk_query = lmk_query.filter(MedicalBookCharge.employee_name.in_(employees or ["__none__"]))
    lmk_overdue = lmk_query.scalar() or 0

    return [
        {"label": "Ожидают корректировки", "value": pending_adjustments, "href": "adjustments"},
        {"label": "Отсутствуют документы", "value": missing_documents, "href": "missing-documents"},
        {"label": "Истекли документы", "value": expired_documents, "href": "expired-documents"},
        {"label": "Непроверенные реквизиты", "value": unverified_requisites, "href": "requisites"},
        {"label": "Смены без плана", "value": shifts_without_plan, "href": "hours-by-store"},
        {"label": "Payroll не передан", "value": fixed_payroll, "href": "payroll"},
        {"label": "Просроченные ЛМК", "value": lmk_overdue, "href": "lmk"},
    ]


def _labels_values(rows, label_attr, value_attr):
    return {
        "labels": [str(getattr(row, label_attr)) for row in rows],
        "values": [float(getattr(row, value_attr) or 0) for row in rows],
    }


def _charts(session, filters, allowed_cities, employees):
    payroll_week_expr = func.date_trunc("week", PayrollRunItem.shift_date)
    payroll_week_query = session.query(
        payroll_week_expr.label("week"),
        func.coalesce(func.sum(PayrollRunItem.total_amount), 0).label("amount"),
    ).filter(
        PayrollRunItem.shift_date >= filters["date_from"],
        PayrollRunItem.shift_date <= filters["date_to"],
    )
    payroll_week_query = _scope_payroll_query(payroll_week_query, allowed_cities).group_by(payroll_week_expr).order_by(payroll_week_expr.asc())
    payroll_weeks = payroll_week_query.all()

    city_query = session.query(
        func.coalesce(Shift.city, "Не указано").label("city"),
        func.coalesce(func.sum(Shift.hours), 0).label("hours"),
    ).filter(
        Shift.shift_date >= filters["date_from"],
        Shift.shift_date <= filters["date_to"],
    )
    city_rows = _scope_shift_query(city_query, allowed_cities).group_by(Shift.city).order_by(func.sum(Shift.hours).desc()).limit(10).all()

    store_query = session.query(
        Shift.store.label("store"),
        func.coalesce(func.sum(Shift.hours), 0).label("hours"),
    ).filter(
        Shift.shift_date >= filters["date_from"],
        Shift.shift_date <= filters["date_to"],
    )
    store_rows = _scope_shift_query(store_query, allowed_cities).group_by(Shift.store).order_by(func.sum(Shift.hours).desc()).limit(10).all()

    employee_query = session.query(
        PayrollRunItem.employee_name.label("employee"),
        func.coalesce(func.sum(PayrollRunItem.total_amount), 0).label("amount"),
    ).filter(
        PayrollRunItem.shift_date >= filters["date_from"],
        PayrollRunItem.shift_date <= filters["date_to"],
    )
    employee_rows = _scope_payroll_query(employee_query, allowed_cities).group_by(PayrollRunItem.employee_name).order_by(func.sum(PayrollRunItem.total_amount).desc()).limit(10).all()

    adjustment_day_expr = func.date(PayrollAdjustment.created_at)
    adjustments_query = session.query(
        adjustment_day_expr.label("day"),
        func.count(PayrollAdjustment.id).label("count"),
    ).filter(PayrollAdjustment.created_at != None)
    adjustments_rows = _scope_adjustment_query(adjustments_query, allowed_cities).group_by(adjustment_day_expr).order_by(adjustment_day_expr.asc()).limit(30).all()

    lmk_day_expr = func.date(MedicalBookPayment.created_at)
    lmk_query = session.query(
        lmk_day_expr.label("day"),
        func.coalesce(func.sum(MedicalBookPayment.amount), 0).label("amount"),
    ).filter(MedicalBookPayment.created_at != None)
    if employees is not None:
        lmk_query = lmk_query.filter(MedicalBookPayment.employee_name.in_(employees or ["__none__"]))
    lmk_rows = lmk_query.group_by(lmk_day_expr).order_by(lmk_day_expr.asc()).limit(30).all()

    return {
        "payroll_by_week": {
            "labels": [row.week.strftime("%d.%m") if row.week else "" for row in payroll_weeks],
            "values": [float(row.amount or 0) for row in payroll_weeks],
        },
        "hours_by_city": _labels_values(city_rows, "city", "hours"),
        "top_stores": _labels_values(store_rows, "store", "hours"),
        "top_employees": _labels_values(employee_rows, "employee", "amount"),
        "adjustments_dynamics": {
            "labels": [row.day.strftime("%d.%m") if row.day else "" for row in adjustments_rows],
            "values": [int(row.count or 0) for row in adjustments_rows],
        },
        "lmk_dynamics": {
            "labels": [row.day.strftime("%d.%m") if row.day else "" for row in lmk_rows],
            "values": [float(row.amount or 0) for row in lmk_rows],
        },
    }


def _trends(session, filters, allowed_cities):
    current_from = filters["date_from"]
    current_to = filters["date_to"]
    period_days = max((current_to - current_from).days + 1, 1)
    previous_to = current_from - timedelta(days=1)
    previous_from = previous_to - timedelta(days=period_days - 1)

    current_hours = _scope_shift_query(
        session.query(func.coalesce(func.sum(Shift.hours), 0)).filter(
            Shift.shift_date >= current_from,
            Shift.shift_date <= current_to,
        ),
        allowed_cities,
    ).scalar() or 0
    previous_hours = _scope_shift_query(
        session.query(func.coalesce(func.sum(Shift.hours), 0)).filter(
            Shift.shift_date >= previous_from,
            Shift.shift_date <= previous_to,
        ),
        allowed_cities,
    ).scalar() or 0

    current_payroll = _scope_payroll_query(
        session.query(func.coalesce(func.sum(PayrollRunItem.total_amount), 0)).filter(
            PayrollRunItem.shift_date >= current_from,
            PayrollRunItem.shift_date <= current_to,
        ),
        allowed_cities,
    ).scalar() or 0
    previous_payroll = _scope_payroll_query(
        session.query(func.coalesce(func.sum(PayrollRunItem.total_amount), 0)).filter(
            PayrollRunItem.shift_date >= previous_from,
            PayrollRunItem.shift_date <= previous_to,
        ),
        allowed_cities,
    ).scalar() or 0

    def delta(current, previous):
        return round(((current - previous) / previous) * 100, 1) if previous else None

    return [
        {"label": "Динамика часов", "current": round(current_hours, 2), "previous": round(previous_hours, 2), "delta": delta(current_hours, previous_hours)},
        {"label": "Динамика payroll", "current": round(current_payroll, 2), "previous": round(previous_payroll, 2), "delta": delta(current_payroll, previous_payroll)},
    ]


def _document_analytics(session, document_rows, employees):
    total_required = len(document_rows)
    missing_statuses = {"missing", "rejected", "archived"}
    missing_count = len([row for row in document_rows if row["status"] in missing_statuses])
    expired_count = len([row for row in document_rows if row["status"] == "expired"])
    verified_count = len([row for row in document_rows if row["status"] == "verified"])

    employees_count = len(employees or [])
    problem_employees = {
        row["employee_name"]
        for row in document_rows
        if row["status"] in missing_statuses or row["status"] == "expired"
    }
    complete_employees = max(employees_count - len(problem_employees), 0)

    type_stats = {}
    for row in document_rows:
        document_type = row["type"]
        stats = type_stats.setdefault(
            document_type.id,
            {
                "name": document_type.name,
                "total": 0,
                "verified": 0,
                "missing": 0,
                "expired": 0,
            },
        )
        stats["total"] += 1
        if row["status"] == "verified":
            stats["verified"] += 1
        elif row["status"] == "expired":
            stats["expired"] += 1
        elif row["status"] in missing_statuses:
            stats["missing"] += 1

    return {
        "employees_count": employees_count,
        "complete_employees": complete_employees,
        "complete_percent": round((complete_employees / employees_count) * 100, 1) if employees_count else 0,
        "total_required": total_required,
        "verified_count": verified_count,
        "missing_count": missing_count,
        "expired_count": expired_count,
        "expired_percent": round((expired_count / total_required) * 100, 1) if total_required else 0,
        "type_stats": sorted(type_stats.values(), key=lambda item: item["name"])[:12],
        "active_types": session.query(DocumentType).filter(DocumentType.is_active == True).count(),
    }


def _payroll_analytics(session, filters, allowed_cities):
    payroll_query = session.query(
        func.coalesce(func.sum(PayrollRunItem.total_amount), 0).label("total_amount"),
        func.coalesce(func.sum(PayrollRunItem.hours), 0).label("hours"),
        func.count(distinct(PayrollRunItem.employee_name)).label("employees"),
    ).filter(
        PayrollRunItem.shift_date >= filters["date_from"],
        PayrollRunItem.shift_date <= filters["date_to"],
    )
    totals = _scope_payroll_query(payroll_query, allowed_cities).first()

    total_amount = float(totals.total_amount or 0) if totals else 0
    total_hours = float(totals.hours or 0) if totals else 0
    employees_count = int(totals.employees or 0) if totals else 0

    city_query = session.query(
        func.coalesce(Shift.city, "Не указано").label("label"),
        func.coalesce(func.sum(PayrollRunItem.total_amount), 0).label("amount"),
    ).join(PayrollRunItem, _shift_item_join_condition()).filter(
        PayrollRunItem.shift_date >= filters["date_from"],
        PayrollRunItem.shift_date <= filters["date_to"],
    )
    city_rows = _scope_shift_query(city_query, allowed_cities).group_by(Shift.city).order_by(func.sum(PayrollRunItem.total_amount).desc()).limit(8).all()

    legal_query = session.query(
        func.coalesce(PayrollRun.legal_entity, "Не выбрано").label("label"),
        func.coalesce(func.sum(PayrollRunItem.total_amount), 0).label("amount"),
    ).join(PayrollRunItem, PayrollRunItem.run_id == PayrollRun.id).filter(
        PayrollRunItem.shift_date >= filters["date_from"],
        PayrollRunItem.shift_date <= filters["date_to"],
    )
    legal_rows = _scope_payroll_query(legal_query, allowed_cities).group_by(PayrollRun.legal_entity).order_by(func.sum(PayrollRunItem.total_amount).desc()).limit(8).all()

    return {
        "total_amount": round(total_amount, 2),
        "avg_employee_payout": round(total_amount / employees_count, 2) if employees_count else 0,
        "avg_hourly_rate": round(total_amount / total_hours, 2) if total_hours else 0,
        "total_hours": round(total_hours, 2),
        "employees_count": employees_count,
        "by_city": [{"label": row.label, "amount": round(float(row.amount or 0), 2)} for row in city_rows],
        "by_legal_entity": [{"label": row.label, "amount": round(float(row.amount or 0), 2)} for row in legal_rows],
    }


def _change_rows(session, filters, allowed_cities, group_column, label_name):
    current_from = filters["date_from"]
    current_to = filters["date_to"]
    period_days = max((current_to - current_from).days + 1, 1)
    previous_to = current_from - timedelta(days=1)
    previous_from = previous_to - timedelta(days=period_days - 1)

    def grouped(date_from, date_to):
        query = session.query(
            group_column.label("label"),
            func.coalesce(func.sum(Shift.hours), 0).label("hours"),
        ).filter(
            Shift.shift_date >= date_from,
            Shift.shift_date <= date_to,
        )
        rows = _scope_shift_query(query, allowed_cities).group_by(group_column).all()
        return {row.label or "Не указано": float(row.hours or 0) for row in rows}

    current = grouped(current_from, current_to)
    previous = grouped(previous_from, previous_to)
    labels = set(current) | set(previous)
    rows = []
    for label in labels:
        current_hours = current.get(label, 0)
        previous_hours = previous.get(label, 0)
        rows.append({
            "label": label,
            "kind": label_name,
            "current": round(current_hours, 2),
            "previous": round(previous_hours, 2),
            "delta": round(current_hours - previous_hours, 2),
        })
    return sorted(rows, key=lambda row: abs(row["delta"]), reverse=True)[:8]


def _analytics_page(request, session, user, economist=False):
    filters = _filters(request)
    allowed_cities = _allowed_cities(user, economist)
    employees = _employee_scope(session, allowed_cities)
    base_path = "/economist/analytics" if economist else "/admin/analytics"
    reports_path = "/economist/reports" if economist else "/admin/reports"
    back_url = "/economist" if economist else "/admin"

    document_rows = build_document_registry_rows(session, employees, status="all")

    return templates.TemplateResponse(
        request,
        "analytics_dashboard.html",
        {
            "user": user,
            "title": "Аналитика",
            "base_path": base_path,
            "reports_path": reports_path,
            "back_url": back_url,
            "filters": filters,
            "kpis": _kpi(session, filters, allowed_cities, employees),
            "alerts": _alerts(session, filters, allowed_cities, employees),
            "charts": _charts(session, filters, allowed_cities, employees),
            "trends": _trends(session, filters, allowed_cities),
            "document_analytics": _document_analytics(session, document_rows, employees),
            "payroll_analytics": _payroll_analytics(session, filters, allowed_cities),
            "city_changes": _change_rows(session, filters, allowed_cities, Shift.city, "city"),
            "store_changes": _change_rows(session, filters, allowed_cities, Shift.store, "store"),
        },
    )


@router.get("/admin/analytics", response_class=HTMLResponse)
def admin_analytics(
    request: Request,
    session: Session = Depends(get_db),
    admin=Depends(require_admin_user),
):
    return _analytics_page(request, session, admin, economist=False)


@router.get("/economist/analytics", response_class=HTMLResponse)
def economist_analytics(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(require_economist_user),
):
    return _analytics_page(request, session, user, economist=True)

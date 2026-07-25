"""Мониторинг выходов сотрудников — переиспользуемая расчётная логика.

Вынесено из routers/employees.py, чтобы пересчёт рекомендаций звался И из ручной
кнопки (в скоупе пользователя), И из хука загрузки смен (глобально, без user).
Идемпотентно: create_recommendation не плодит дубли (проверка exists по new).
"""

from datetime import timedelta

from sqlalchemy import func

from access import apply_shift_scope
from audit_helpers import create_audit_log
from models import (
    EmployeeMonitoringRecommendation,
    EmployeeMonitoringSettings,
    EmployeeStoreAssignment,
    Shift,
)
from time_helpers import business_today, now_utc


def get_monitoring_settings(session):
    settings = session.query(EmployeeMonitoringSettings).first()
    if not settings:
        settings = EmployeeMonitoringSettings(inactive_days=14, minimum_shifts=3, analysis_days=14)
        session.add(settings)
        session.flush()
    return settings


def create_recommendation(session, request, user, employee, store, city, kind, text_value):
    """Создать рекомендацию, если такой ещё нет (status=new). Возвращает 0/1."""
    exists = session.query(EmployeeMonitoringRecommendation).filter(
        EmployeeMonitoringRecommendation.employee_name == employee,
        EmployeeMonitoringRecommendation.store == store,
        EmployeeMonitoringRecommendation.recommendation_type == kind,
        EmployeeMonitoringRecommendation.status == "new",
    ).first()
    if exists:
        return 0
    row = EmployeeMonitoringRecommendation(
        employee_name=employee, store=store, city=city, recommendation_type=kind,
        remove_from_planning=kind == "remove_from_planning",
        add_to_planning=kind == "add_to_planning",
        recommendation_text=text_value, status="new", created_at=now_utc(),
    )
    session.add(row)
    session.flush()
    create_audit_log(
        session, request, user, "monitoring_recommendation_created",
        "employee_monitoring_recommendation", row.id, f"{employee} / {store}",
    )
    return 1


def recompute_recommendations(session, request=None, user=None):
    """Пересчёт рекомендаций планирования. Возвращает число созданных.

    - `user` задан → в его скоупе городов/магазинов (ручная кнопка);
    - `user is None` → глобально (хук после загрузки смен).
    Правила: закреплён, но нет смен `inactive_days` дней → remove_from_planning;
    отработал ≥ `minimum_shifts` за `analysis_days`, но не закреплён → add_to_planning.
    """
    settings = get_monitoring_settings(session)
    today = business_today()
    created = 0

    assignment_q = session.query(EmployeeStoreAssignment).filter(
        EmployeeStoreAssignment.is_active == True  # noqa: E712
    )
    shift_q = (
        session.query(Shift.employee, Shift.store, Shift.city, func.count(Shift.id).label("count"))
        .filter(Shift.shift_date >= today - timedelta(days=settings.analysis_days - 1))
        .group_by(Shift.employee, Shift.store, Shift.city)
    )
    if user is not None:
        assignment_q = apply_shift_scope(assignment_q, session, user, EmployeeStoreAssignment)
        shift_q = apply_shift_scope(shift_q, session, user, Shift)

    assignments = assignment_q.all()
    active_keys = {(a.employee_name, a.store) for a in assignments}

    for item in assignments:
        last_date = session.query(func.max(Shift.shift_date)).filter(
            Shift.employee == item.employee_name, Shift.store == item.store,
        ).scalar()
        if not last_date or last_date <= today - timedelta(days=settings.inactive_days):
            created += create_recommendation(
                session, request, user, item.employee_name, item.store, item.city,
                "remove_from_planning",
                f"Сотрудник закреплён за магазином, но не имеет смен {settings.inactive_days} "
                f"дней. Возможно его следует убрать из бланка планирования.",
            )

    for item in shift_q.having(func.count(Shift.id) >= settings.minimum_shifts).all():
        if (item.employee, item.store) not in active_keys:
            created += create_recommendation(
                session, request, user, item.employee, item.store, item.city,
                "add_to_planning",
                f"Сотрудник отработал {item.count} смен за последние {settings.analysis_days} "
                f"дней, но отсутствует в планировании. Возможно его следует добавить.",
            )

    session.commit()
    return created

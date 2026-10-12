"""Действия «Еженедельного отчёта» (П4.6): ставка → индивидуальная, закрепление за ТМ
и запросы на смену ТМ, статусы недели («ЧТС проверено», «Закрыто для коррекций»,
«Зафиксировать авансы»), отметка «Подать на аванс» с частичной суммой.

Права: weekly.manage (экономист, руководитель ТМ, суперадмин) — всё и всегда;
weekly.edit_own (ТМ) — только свои сотрудники и пока неделя не закрыта.
Каждое действие пишет аудит; коммит — на вызывающем.
"""

import logging
from datetime import timedelta

from audit_helpers import create_audit_log
from email_engine import send_email
from manual_adjustments import parse_money
from models import Rate, TmChangeRequest, User, WeeklyReview, WeeklyTmCheck
from payouts_helpers import advance_run_for_week, is_frozen, set_selection, week_selection
from rbac import ROLE_ECONOMIST, ROLE_HR_LEAD, has_permission
from time_helpers import now_utc
from tm_assignment import ensure_employee_user, set_employee_tm, tm_users
from utils import find_user_by_name, normalize_person_name, normalize_text
from weekly_report import CLOSED_HINT, NO_REQUISITES_HINT, is_week_closed, week_review

logger = logging.getLogger(__name__)

RATE_ACTION = "rate.individual.set"


class WeeklyError(Exception):
    """Отказ действия: текст — пользователю, status — HTTP-код для fetch."""

    def __init__(self, message, status=400):
        super().__init__(message)
        self.message = message
        self.status = status


def can_manage(user):
    return has_permission(user, "weekly.manage")


def can_edit_own(user):
    return has_permission(user, "weekly.edit_own")


def _week_label(week_start):
    return f"{week_start:%d.%m}–{week_start + timedelta(days=6):%d.%m}"


def ensure_open_for(session, user, week_start):
    """ТМ правит только открытую неделю; weekly.manage — всегда."""
    if can_manage(user):
        return
    if not can_edit_own(user):
        raise WeeklyError("Нет прав на правку еженедельного отчёта", 403)
    if is_week_closed(session, week_start):
        raise WeeklyError(f"Неделя закрыта, обратитесь к экономисту ({CLOSED_HINT})", 403)


def ensure_own(session, user, week_start, employee):
    """ТМ — только своих сотрудников (User.tm_id = ТМ) открытой недели."""
    ensure_open_for(session, user, week_start)
    if not can_manage(user) and (employee is None or employee.tm_id != user.id):
        raise WeeklyError("Можно менять только своих сотрудников", 403)


# ── Блок C: ставка → индивидуальная ставка сотрудника ───────────────────────

def _service_link(session, service):
    from routers.rates import _resolve_service_link

    return _resolve_service_link(session, service)


def set_individual_rate(session, request, user, week_start, employee_name, service, value):
    """Ставка с экрана: Rate(сотрудник, услуга, уровень) с понедельника недели; прежняя
    индивидуальная той же услуги закрывается воскресеньем перед ним (не удаляется).
    Пустое значение — вернуть к сетке (закрыть индивидуальную). Возвращает новую Rate или None."""
    employee_name = normalize_text(employee_name)
    service = normalize_text(service)
    employee = find_user_by_name(session, employee_name)
    ensure_own(session, user, week_start, employee)
    raw = normalize_text(value)
    hourly = parse_money(raw) if raw else None
    if raw and (not hourly or hourly <= 0):
        raise WeeklyError("Ставка — положительное число")
    service_id, level = _service_link(session, service)
    key = normalize_person_name(employee_name)
    previous_sunday = week_start - timedelta(days=1)

    def same_service(rate):
        if service_id is not None and rate.service_id is not None:
            return rate.service_id == service_id and rate.level == level
        return normalize_text(rate.service) == service

    existing = [rate for rate in session.query(Rate).filter(Rate.employee_name.isnot(None)).all()
                if normalize_person_name(rate.employee_name) == key and same_service(rate)
                and (rate.active_to is None or rate.active_to >= week_start)]
    old_value = [{"id": r.id, "hourly_rate": r.hourly_rate,
                  "active_from": r.active_from.isoformat() if r.active_from else None,
                  "active_to": r.active_to.isoformat() if r.active_to else None} for r in existing]
    for rate in existing:
        rate.active_to = previous_sunday
    new_rate = None
    if hourly:
        new_rate = Rate(service=service, service_id=service_id, level=level, employee_name=employee_name,
                        hourly_rate=hourly, active_from=week_start,
                        comment=f"Недельный отчёт {_week_label(week_start)}, ТМ {user.employee_name}")
        session.add(new_rate)
        session.flush()
    create_audit_log(session, request, user, RATE_ACTION, "rate", new_rate.id if new_rate else None,
                     f"{employee_name} / {service}", old_value={"closed": old_value},
                     new_value={"hourly_rate": hourly, "active_from": week_start.isoformat()} if hourly
                     else {"reset_to_grid": True, "active_to": previous_sunday.isoformat()})
    return new_rate


# ── Блок D: закрепление за ТМ и запросы на смену ТМ ─────────────────────────

def take_employee(session, request, user, week_start, employee_name):
    """«ПУСТО» → ТМ закрепляет сотрудника за собой (сотрудника без users — заводит)."""
    ensure_open_for(session, user, week_start)
    employee, _created = ensure_employee_user(session, request, user, employee_name,
                                              comment="Еженедельный отчёт: закрепление за ТМ")
    if employee.tm_id and employee.tm_id != user.id:
        raise WeeklyError("Сотрудник уже закреплён за другим ТМ — отправьте запрос", 409)
    set_employee_tm(session, request, user, employee, user.id, comment="Еженедельный отчёт")
    return employee


def release_employee(session, request, user, week_start, employee_name):
    employee = find_user_by_name(session, employee_name)
    ensure_own(session, user, week_start, employee)
    set_employee_tm(session, request, user, employee, None, comment="Еженедельный отчёт: открепление")
    return employee


def set_tm_directly(session, request, user, employee_name, tm_id):
    """weekly.manage: выбрать ТМ в ячейке без запросов (0 — открепить)."""
    if not can_manage(user):
        raise WeeklyError("Менять ТМ напрямую может экономист или руководитель ТМ", 403)
    employee, _created = ensure_employee_user(session, request, user, employee_name,
                                              comment="Еженедельный отчёт: назначение ТМ")
    if tm_id and tm_id not in {tm.id for tm in tm_users(session)}:
        raise WeeklyError("Такого ТМ нет")
    set_employee_tm(session, request, user, employee, tm_id or None, comment="Еженедельный отчёт")
    return employee


def _notify_managers(session, subject, text):
    emails = [u.email for u in session.query(User).filter(User.role.in_([ROLE_ECONOMIST, ROLE_HR_LEAD]))
              if normalize_text(u.email)]
    if not emails:
        return
    try:
        send_email(emails, subject, f"<p>{text}</p>", body_text=text)
    except Exception:  # почта не должна ломать действие
        logger.exception("weekly: письмо о запросе смены ТМ не отправлено")


def request_tm_change(session, request, user, week_start, employee_name, comment=None):
    """ТМ: «Это мой сотрудник!» на сотрудника другого ТМ → TmChangeRequest (pending).
    Повторный запрос по той же паре, пока есть pending, не создаётся — вернётся тот же."""
    ensure_open_for(session, user, week_start)
    employee = find_user_by_name(session, employee_name)
    if employee is None or not employee.tm_id:
        raise WeeklyError("У сотрудника нет ТМ — закрепите его за собой")
    if employee.tm_id == user.id:
        raise WeeklyError("Сотрудник уже ваш")
    pending = session.query(TmChangeRequest).filter(
        TmChangeRequest.employee_user_id == employee.id, TmChangeRequest.to_tm_id == user.id,
        TmChangeRequest.status == "pending").first()
    if pending:
        return pending, False
    change = TmChangeRequest(employee_user_id=employee.id, from_tm_id=employee.tm_id, to_tm_id=user.id,
                             requested_by=user.id, week_start=week_start, status="pending",
                             comment=normalize_text(comment) or None)
    session.add(change)
    session.flush()
    create_audit_log(session, request, user, "tm.request.create", "tm_change_request", change.id,
                     employee.employee_name, new_value={"from_tm_id": change.from_tm_id, "to_tm_id": user.id})
    _notify_managers(session, "Запрос на смену ТМ",
                     f"ТМ {user.employee_name} просит закрепить за собой сотрудника {employee.employee_name}.")
    return change, True


def decide_tm_request(session, request, user, request_id, accept):
    if not can_manage(user):
        raise WeeklyError("Запросы на смену ТМ решает экономист или руководитель ТМ", 403)
    change = session.get(TmChangeRequest, request_id)
    if change is None or change.status != "pending":
        raise WeeklyError("Запрос уже решён или не найден", 404)
    change.status = "accepted" if accept else "rejected"
    change.decided_by = user.id
    change.decided_at = now_utc()
    employee = session.get(User, change.employee_user_id)
    if accept and employee is not None:
        set_employee_tm(session, request, user, employee, change.to_tm_id, comment=f"Запрос смены ТМ №{change.id}")
    create_audit_log(session, request, user, "tm.request." + change.status, "tm_change_request", change.id,
                     employee.employee_name if employee else None,
                     new_value={"status": change.status, "to_tm_id": change.to_tm_id})
    return change


# ── Блок E: статусы недели ───────────────────────────────────────────────────

def _tm_check(session, week_start, tm_id):
    check = session.query(WeeklyTmCheck).filter(WeeklyTmCheck.week_start == week_start,
                                                WeeklyTmCheck.tm_id == tm_id).first()
    if check is None:
        check = WeeklyTmCheck(week_start=week_start, tm_id=tm_id)
        session.add(check)
    return check


def toggle_rates_checked(session, request, user, week_start):
    """«ЧТС проверено» (ТМ): ставит/снимает отметку, пока неделя не закрыта. Возвращает отметку."""
    if not can_edit_own(user):
        raise WeeklyError("«ЧТС проверено» отмечает ТМ", 403)
    if is_week_closed(session, week_start):
        raise WeeklyError(f"Неделя закрыта, обратитесь к экономисту ({CLOSED_HINT})", 403)
    check = _tm_check(session, week_start, user.id)
    check.checked_at = None if check.checked_at else now_utc()
    create_audit_log(session, request, user, "weekly.rates_checked" if check.checked_at else "weekly.rates_unchecked",
                     "weekly_week", week_start.isoformat(), f"Неделя {_week_label(week_start)}")
    return check


def toggle_advances_submitted(session, request, user, week_start):
    """«Зафиксировать авансы» (ТМ подал своих) / «Вернуть на правку», пока неделя не закрыта."""
    if not can_edit_own(user):
        raise WeeklyError("Подаёт авансы ТМ", 403)
    if is_week_closed(session, week_start):
        raise WeeklyError(f"Неделя закрыта, обратитесь к экономисту ({CLOSED_HINT})", 403)
    check = _tm_check(session, week_start, user.id)
    check.advances_submitted_at = None if check.advances_submitted_at else now_utc()
    create_audit_log(session, request, user,
                     "weekly.advances_submitted" if check.advances_submitted_at else "weekly.advances_reopened",
                     "weekly_week", week_start.isoformat(), f"Неделя {_week_label(week_start)}")
    return check


def set_week_closed(session, request, user, week_start, closed):
    """«Закрыто для коррекций» / «Открыть для коррекций» — weekly.manage. Не фиксирует аванс."""
    if not can_manage(user):
        raise WeeklyError("Закрывать неделю может экономист или руководитель ТМ", 403)
    review = week_review(session, week_start)
    if review is None:
        review = WeeklyReview(week_start=week_start)
        session.add(review)
    review.closed_at = now_utc() if closed else None
    review.closed_by = user.id if closed else None
    create_audit_log(session, request, user, "weekly.close" if closed else "weekly.open", "weekly_week",
                     week_start.isoformat(), f"Неделя {_week_label(week_start)}")
    return review


def advances_locked_for(session, user, week_start):
    """Текст причины, по которой ТМ не может менять отметки аванса недели (None — может)."""
    if can_manage(user) or has_permission(user, "payouts.advances.select_any"):
        return None
    if is_week_closed(session, week_start):
        return f"Неделя закрыта, обратитесь к экономисту ({CLOSED_HINT})"
    check = session.query(WeeklyTmCheck).filter(WeeklyTmCheck.week_start == week_start,
                                                WeeklyTmCheck.tm_id == user.id).first()
    if check and check.advances_submitted_at:
        return "Авансы поданы — нажмите «Вернуть на правку»"
    return None


# ── Блок F: «Подать на аванс» и частичная сумма ─────────────────────────────

def _ensure_can_select(session, user, week_start, employee):
    if is_frozen(advance_run_for_week(session, week_start)):
        raise WeeklyError("Аванс за неделю уже зафиксирован экономистом", 409)
    locked = advances_locked_for(session, user, week_start)
    if locked:
        raise WeeklyError(locked, 403)
    if not (can_manage(user) or has_permission(user, "payouts.advances.select_any")):
        if employee is None or employee.tm_id != user.id:
            raise WeeklyError("Можно отмечать только своих сотрудников", 403)


def set_advance(session, request, user, week_start, person, checked, amount_raw=""):
    """Отметка аванса из отчёта: person — из weekly_report()["people"]. amount_raw пусто —
    весь ФОТ (amount = NULL), иначе 0 < сумма ≤ ФОТ недели. Пишет в ту же AdvanceSelection,
    что страница авансов. Возвращает отметку или None (снята)."""
    employee = person["user"]
    _ensure_can_select(session, user, week_start, employee)
    if not checked:
        set_selection(session, request, user, week_start, person["name"], False)
        return None
    if not person["has_requisites"]:
        raise WeeklyError(f"{person['name']}: {NO_REQUISITES_HINT}")
    amount = None
    if normalize_text(amount_raw):
        amount = round(parse_money(amount_raw), 2)
        if amount <= 0 or amount > round(person["fot"], 2):
            raise WeeklyError(f"Сумма аванса — больше 0 и не больше ФОТ недели ({person['fot']:.2f})")
    set_selection(session, request, user, week_start, person["name"], True)
    session.flush()
    selection = week_selection(session, week_start)[normalize_person_name(person["name"])]
    if selection.amount != amount:
        old = selection.amount
        selection.amount = amount
        create_audit_log(session, request, user, "advance.selection.amount", "advance_week", week_start.isoformat(),
                         person["name"], old_value={"amount": old}, new_value={"amount": amount})
    return selection


def set_advance_all(session, request, user, week_start, people, checked):
    """«Выбрать всех» / «Снять всех» — ТМ: только свои с валидными реквизитами, весь ФОТ.
    Возвращает число изменённых отметок."""
    changed = 0
    current = week_selection(session, week_start)
    for key, person in people.items():
        if person["tm_id"] != user.id or (checked and not person["has_requisites"]):
            continue
        selected = current.get(key)
        if checked and (selected is None or selected.amount is not None):
            set_advance(session, request, user, week_start, person, True)
            changed += 1
        elif not checked and selected is not None:
            set_advance(session, request, user, week_start, person, False)
            changed += 1
    return changed


def partial_selections(session, week_start):
    """{ключ ФИО: AdvanceSelection} с частичной суммой."""
    return {key: row for key, row in week_selection(session, week_start).items() if row.amount}


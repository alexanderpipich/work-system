"""«Еженедельный отчёт» (П4.6): рабочий экран ТМ по понедельникам — /admin/payouts/weekly.

Данные и xlsx — weekly_report, действия — weekly_actions. Страница авансов (П3)
остаётся экраном экономиста и пишет в те же AdvanceSelection.
"""

from datetime import timedelta, timezone
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from dependencies import get_db
from file_storage import storage_response
from models import User
from payouts_helpers import advance_run_for_week, is_frozen
from rbac import ROLE_TM, canonical_role, has_permission, require_permission
from time_helpers import app_timezone, business_today
from tm_assignment import tm_users
from utils import normalize_person_name
from weekly_actions import (WeeklyError, advances_locked_for, can_edit_own, can_manage, decide_tm_request,
                            release_employee, request_tm_change, set_advance, set_advance_all,
                            set_individual_rate, set_tm_directly, set_week_closed, take_employee,
                            toggle_advances_submitted, toggle_rates_checked)
from weekly_report import (CLOSED_HINT, NO_REQUISITES_HINT, NO_TM, filter_rows, last_complete_week,
                           pending_tm_requests, resolve_week, save_weekly, selection_state, tm_checks,
                           week_review, weekly_report)

router = APIRouter()
templates = Jinja2Templates(directory="templates")

WEEKLY_URL = "/admin/payouts/weekly"
_weekly_view = require_permission("weekly.view")


def local_time(value):
    """dd.mm HH:MM в часовом поясе приложения (в БД — UTC)."""
    if not value:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(app_timezone()).strftime("%d.%m %H:%M")



def _parse_int(value):
    """«Все ТМ» = 0; пусто и мусор — тоже 0 (старые закладки)."""
    try:
        return int((value or "").strip() or 0)
    except ValueError:
        return 0


def _week_url(week_start, **params):
    query = {"week": week_start.isoformat(), **{k: v for k, v in params.items() if v not in (None, "", False)}}
    return WEEKLY_URL + "?" + urlencode(query)


def _back(week_start, form=None, **params):
    """Назад на отчёт с фильтрами формы и сообщением."""
    keep = {k: form.get(k) for k in ("tm", "q", "no_tm", "no_requisites", "no_rate")} if form else {}
    return RedirectResponse(_week_url(week_start, **keep, **params), 302)


def _json_error(error):
    return JSONResponse({"ok": False, "error": error.message}, status_code=error.status)


@router.get(WEEKLY_URL, response_class=HTMLResponse)
def weekly_page(
    request: Request,
    week: str = "",
    tm: str = "",
    q: str = "",
    no_tm: str = "",
    no_requisites: str = "",
    no_rate: str = "",
    message: str = "",
    error: str = "",
    session: Session = Depends(get_db),
    user=Depends(_weekly_view),
):
    today = business_today()
    week_start = resolve_week(week, today)
    report = weekly_report(session, week_start)
    is_tm = canonical_role(user) == ROLE_TM
    # ТМ по умолчанию видит своих; явный tm=0 из формы — всех.
    tm_id = (user.id if is_tm else 0) if tm == "" else _parse_int(tm)
    rows = filter_rows(report["rows"], tm=tm_id, q=q, no_tm=bool(no_tm), no_requisites=bool(no_requisites),
                       no_rate=bool(no_rate))
    review = week_review(session, week_start)
    closed = bool(review and review.closed_at)
    checks = tm_checks(session, week_start)
    tms = tm_users(session)
    names = {u.id: u.employee_name for u in tms}
    manage = can_manage(user)
    requests = pending_tm_requests(session) if manage else []
    request_users = {u.id: u.employee_name for u in session.query(User).filter(
        User.id.in_({r.employee_user_id for r in requests} | {0}))}
    selection = selection_state(session, week_start)
    run = advance_run_for_week(session, week_start)
    seen = set()
    for row in rows:  # колонка «Аванс» — на первой строке сотрудника
        row["first"] = row["key"] not in seen
        seen.add(row["key"])
    next_week = week_start + timedelta(days=7)
    closed_by = session.get(User, review.closed_by) if review and review.closed_by else None
    return templates.TemplateResponse(request, "payouts_weekly.html", {
        "user": user,
        "week_start": week_start,
        "week_end": report["week_end"],
        "prev_week": week_start - timedelta(days=7),
        "next_week": next_week if next_week <= last_complete_week(today) else None,
        "days": report["days"],
        "rows": rows,
        "people": report["people"],
        "total_hours": sum(r["hours"] for r in rows),
        "total_fot": round(sum(r["fot"] for r in rows), 2),
        "no_rate": report["no_rate"],
        "filters": {"tm": tm_id, "q": q, "no_tm": bool(no_tm), "no_requisites": bool(no_requisites),
                    "no_rate": bool(no_rate)},
        "tm_options": [(u.id, u.employee_name) for u in tms],
        "tm_status": [{"id": u.id, "name": u.employee_name,
                       "checked_at": local_time(checks[u.id].checked_at) if u.id in checks else "",
                       "submitted_at": local_time(checks[u.id].advances_submitted_at) if u.id in checks else ""}
                      for u in tms],
        "my_check": checks.get(user.id),
        "review": review,
        "closed": closed,
        "closed_at": local_time(review.closed_at) if closed else "",
        "closed_by_name": closed_by.employee_name if closed_by else "",
        "selection": selection,
        "frozen": is_frozen(run),
        "advance_locked": advances_locked_for(session, user, week_start),
        "is_tm": is_tm,
        "can_manage": manage,
        "can_edit_own": can_edit_own(user),
        "can_export": has_permission(user, "payouts.export"),
        "can_select_any": manage or has_permission(user, "payouts.advances.select_any"),
        "tm_requests": [{"id": r.id, "employee": request_users.get(r.employee_user_id, "?"),
                         "from_tm": names.get(r.from_tm_id, "—"), "to_tm": names.get(r.to_tm_id, "?"),
                         "created_at": local_time(r.created_at)} for r in requests],
        "NO_TM": NO_TM,
        "CLOSED_HINT": CLOSED_HINT,
        "NO_REQUISITES_HINT": NO_REQUISITES_HINT,
        "message": message or None,
        "error": error or None,
    })


@router.get(WEEKLY_URL + ".xlsx")
def weekly_xlsx(week: str = "", session: Session = Depends(get_db), user=Depends(_weekly_view)):
    week_start = resolve_week(week, business_today())
    if not has_permission(user, "payouts.export"):
        return RedirectResponse(_week_url(week_start), 302)
    key, filename = save_weekly(session, week_start)
    return storage_response(key, filename=filename) or RedirectResponse(_week_url(week_start), 302)


# ── fetch-действия ячеек (JSON) ──────────────────────────────────────────────

@router.post(WEEKLY_URL + "/rate")
def weekly_rate(request: Request, week: str = Form(...), employee_name: str = Form(...), service: str = Form(...),
                value: str = Form(""), session: Session = Depends(get_db), user=Depends(_weekly_view)):
    week_start = resolve_week(week, business_today())
    try:
        rate = set_individual_rate(session, request, user, week_start, employee_name, service, value)
    except WeeklyError as error:
        session.rollback()
        return _json_error(error)
    session.commit()
    return JSONResponse({"ok": True, "rate": rate.hourly_rate if rate else None})


@router.post(WEEKLY_URL + "/tm")
def weekly_tm(request: Request, week: str = Form(...), employee_name: str = Form(...), action: str = Form(...),
              tm_id: str = Form(""), session: Session = Depends(get_db), user=Depends(_weekly_view)):
    week_start = resolve_week(week, business_today())
    try:
        if action == "take":
            take_employee(session, request, user, week_start, employee_name)
            message = "Сотрудник закреплён за вами"
        elif action == "release":
            release_employee(session, request, user, week_start, employee_name)
            message = "Сотрудник откреплён"
        elif action == "request":
            _change, created = request_tm_change(session, request, user, week_start, employee_name)
            message = "Запрос отправлен экономисту" if created else "Запрос уже отправлен и ждёт решения"
        elif action == "set":
            set_tm_directly(session, request, user, employee_name, _parse_int(tm_id))
            message = "ТМ изменён"
        else:
            raise WeeklyError("Неизвестное действие")
    except WeeklyError as error:
        session.rollback()
        return _json_error(error)
    session.commit()
    return JSONResponse({"ok": True, "message": message})


@router.post(WEEKLY_URL + "/advance")
def weekly_advance(request: Request, week: str = Form(...), employee_name: str = Form(...),
                   checked: str = Form(""), amount: str = Form(""), session: Session = Depends(get_db),
                   user=Depends(_weekly_view)):
    week_start = resolve_week(week, business_today())
    person = weekly_report(session, week_start)["people"].get(normalize_person_name(employee_name))
    if person is None:
        return JSONResponse({"ok": False, "error": "Сотрудника нет в отчёте недели"}, status_code=404)
    try:
        selection = set_advance(session, request, user, week_start, person, checked in {"1", "true", "on"}, amount)
    except WeeklyError as error:
        session.rollback()
        return _json_error(error)
    session.commit()
    return JSONResponse({"ok": True, "amount": selection.amount if selection else None,
                         "selected": selection is not None})


# ── кнопки (форма → редирект) ────────────────────────────────────────────────

async def _form_action(request, session, user, action):
    form = await request.form()
    week_start = resolve_week(form.get("week"), business_today())
    try:
        message = action(week_start, form)
    except WeeklyError as error:
        session.rollback()
        return _back(week_start, form, error=error.message)
    session.commit()
    return _back(week_start, form, message=message)


@router.post(WEEKLY_URL + "/advance-all")
async def weekly_advance_all(request: Request, session: Session = Depends(get_db), user=Depends(_weekly_view)):
    def action(week_start, form):
        checked = form.get("checked") == "1"
        people = weekly_report(session, week_start)["people"]
        changed = set_advance_all(session, request, user, week_start, people, checked)
        return (f"Отмечено на аванс: {changed}" if checked else f"Снято отметок: {changed}")
    return await _form_action(request, session, user, action)


@router.post(WEEKLY_URL + "/check")
async def weekly_check(request: Request, session: Session = Depends(get_db), user=Depends(_weekly_view)):
    def action(week_start, form):
        check = toggle_rates_checked(session, request, user, week_start)
        return (f"ТМ {user.employee_name} проверил ЧТС своих сотрудников" if check.checked_at
                else "Отметка «ЧТС проверено» снята")
    return await _form_action(request, session, user, action)


@router.post(WEEKLY_URL + "/submit")
async def weekly_submit(request: Request, session: Session = Depends(get_db), user=Depends(_weekly_view)):
    def action(week_start, form):
        check = toggle_advances_submitted(session, request, user, week_start)
        return ("Авансы поданы — отметки заморожены" if check.advances_submitted_at
                else "Авансы возвращены на правку")
    return await _form_action(request, session, user, action)


@router.post(WEEKLY_URL + "/close")
async def weekly_close(request: Request, session: Session = Depends(get_db), user=Depends(_weekly_view)):
    def action(week_start, form):
        closed = form.get("closed") == "1"
        set_week_closed(session, request, user, week_start, closed)
        return "Неделя закрыта для коррекций" if closed else "Неделя открыта для коррекций"
    return await _form_action(request, session, user, action)


@router.post(WEEKLY_URL + "/tm-requests/{request_id}/{decision}")
async def weekly_tm_request(request_id: int, decision: str, request: Request, session: Session = Depends(get_db),
                            user=Depends(_weekly_view)):
    def action(week_start, form):
        change = decide_tm_request(session, request, user, request_id, decision == "accept")
        return "Запрос принят — ТМ изменён" if change.status == "accepted" else "Запрос отклонён"
    return await _form_action(request, session, user, action)


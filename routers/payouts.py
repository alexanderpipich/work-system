"""Выплаты (П3): еженедельные авансы и табель за период, реестр выплат xlsx; надбавки к часу (П4.4);
еженедельный отчёт по сменам (П4.6)."""

from datetime import date, datetime, timedelta
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from dependencies import RedirectException, current_user, get_db
from file_storage import storage_response
from audit_helpers import create_audit_log
from manual_adjustments import parse_money
from models import HourlyBonus, PayrollRun, User
from payouts_helpers import (advance_run_for_week, advance_week_rows, can_select, carry_over_selection,
                             create_period_draft, default_week, fix_advance, fix_period_run, is_frozen,
                             no_rate_summary, period_summary, save_registry, save_week_deduction, set_selection, unfix_run,
                             unsend_run, week_monday)
from payroll_run_helpers import RUN_KIND_ADVANCE
from statement_export import save_statement
from rbac import ROLE_TM, canonical_role, has_permission, require_permission
from time_helpers import business_today
from utils import find_user_by_name, format_card_number, normalize_person_name, normalize_text
from weekly_report import last_complete_week, resolve_week, save_weekly, weekly_report

router = APIRouter()
templates = Jinja2Templates(directory="templates")
templates.env.filters["card_format"] = format_card_number

PAYOUT_PERMISSIONS = (
    "payouts.advances.select_own",
    "payouts.advances.select_any",
    "payouts.advances.fix",
    "payouts.export",
    "payroll.manage",
    "payroll.send",
)
RUN_STATUS_LABELS = {"draft": "не зафиксирован", "fixed": "зафиксирован", "sent": "отправлен", "closed": "закрыт"}


def user_permissions(user):
    return {perm for perm in PAYOUT_PERMISSIONS if has_permission(user, perm)}


def require_advances_access(user=Depends(current_user)):
    """Экран авансов: ТМ (свои), экономист, руководитель ТМ, суперадмин."""
    perms = user_permissions(user)
    if not perms & {"payouts.advances.select_own", "payouts.advances.select_any", "payouts.advances.fix"}:
        raise RedirectException("/")
    return user


def _parse_week(value):
    try:
        return week_monday(datetime.strptime(value, "%Y-%m-%d").date())
    except (TypeError, ValueError):
        return default_week(business_today())


def _week_url(week_start, **params):
    query = {"week": week_start.isoformat(), **{k: v for k, v in params.items() if v}}
    return "/admin/payouts/advances?" + urlencode(query)


def _user_name(session, user_id):
    user = session.query(User).filter(User.id == user_id).first() if user_id else None
    return user.employee_name if user else ""


@router.get("/admin/payouts/advances", response_class=HTMLResponse)
def advances_page(
    request: Request,
    week: str = "",
    mine: str = "",
    tm: int = 0,
    q: str = "",
    message: str = "",
    error: str = "",
    session: Session = Depends(get_db),
    user=Depends(require_advances_access),
):
    week_start = _parse_week(week)
    perms = user_permissions(user)
    carry_over_selection(session, request, user, week_start)
    run = advance_run_for_week(session, week_start)
    rows = advance_week_rows(session, week_start)
    no_rate = no_rate_summary((item["shift"].service, item["shift"].hours)
                              for row in rows for item in row["shifts"] if item["no_rate"])

    # «Только мои» по умолчанию у ТМ; явный mine=0/1 из формы главнее.
    only_mine = (mine == "1") if mine in {"0", "1"} else canonical_role(user) == ROLE_TM
    if only_mine:
        rows = [r for r in rows if r["tm_id"] == user.id]
    if tm:
        rows = [r for r in rows if r["tm_id"] == tm]
    if normalize_text(q):
        needle = normalize_person_name(q)
        rows = [r for r in rows if needle in normalize_person_name(r["employee_name"])]
    for row in rows:
        row["can_select"] = can_select(user, row["user"], perms)

    tm_options = sorted({(r["tm_id"], r["tm_name"]) for r in advance_week_rows(session, week_start) if r["tm_id"]},
                        key=lambda item: item[1])
    selected = [r for r in rows if r["selected"]]
    return templates.TemplateResponse(request, "payouts_advances.html", {
        "user": user,
        "week_start": week_start,
        "week_end": week_start + timedelta(days=6),
        "prev_week": week_start - timedelta(days=7),
        "next_week": week_start + timedelta(days=7),
        "run": run,
        "run_status": RUN_STATUS_LABELS.get(run.status, run.status) if run else RUN_STATUS_LABELS["draft"],
        "fixed_by_name": _user_name(session, run.fixed_by) if run else "",
        "frozen": is_frozen(run),
        "rows": rows,
        "selected_count": len(selected),
        "selected_total": sum(r["to_pay"] for r in selected),
        "perms": perms,
        "filters": {"mine": only_mine, "tm": tm, "q": q},
        "tm_options": tm_options,
        "no_rate": no_rate,
        "message": message or None,
        "error": error or None,
    })


WEEKLY_URL = "/admin/payouts/weekly"


def _parse_tm(value):
    """tm из формы: «Все ТМ» = 0; пусто и мусор — тоже 0 (старые закладки)."""
    try:
        return int((value or "").strip() or 0)
    except ValueError:
        return 0


@router.get(WEEKLY_URL, response_class=HTMLResponse)
def weekly_page(
    request: Request,
    week: str = "",
    tm: str = "0",
    q: str = "",
    session: Session = Depends(get_db),
    user=Depends(require_advances_access),
):
    """Еженедельный отчёт (П4.6): видят все с доступом к авансам, все сотрудники; скачивание — payouts.export."""
    week_start = resolve_week(week, business_today())
    report = weekly_report(session, week_start)
    rows = report["rows"]
    tm_options = sorted({(r["tm_id"], r["ТМ"]) for r in rows if r["tm_id"]}, key=lambda item: item[1])
    tm_id = _parse_tm(tm)
    if tm_id:
        rows = [r for r in rows if r["tm_id"] == tm_id]
    if normalize_text(q):
        needle = normalize_person_name(q)
        rows = [r for r in rows if needle in normalize_person_name(r["ФИО сотрудника Исполнителя"])]
    next_week = week_start + timedelta(days=7)
    return templates.TemplateResponse(request, "payouts_weekly.html", {
        "user": user,
        "week_start": week_start,
        "week_end": week_start + timedelta(days=6),
        "prev_week": week_start - timedelta(days=7),
        "next_week": next_week if next_week <= last_complete_week(business_today()) else None,
        "days": report["days"],
        "rows": rows,
        "total": round(sum(r["ФОТ"] for r in rows), 2),
        "no_rate": report["no_rate"],
        "filters": {"tm": tm_id, "q": q},
        "tm_options": tm_options,
        "can_export": has_permission(user, "payouts.export"),
    })


@router.get(WEEKLY_URL + ".xlsx")
def weekly_xlsx(week: str = "", session: Session = Depends(get_db), user=Depends(current_user)):
    week_start = resolve_week(week, business_today())
    if not has_permission(user, "payouts.export"):
        return RedirectResponse(f"{WEEKLY_URL}?week={week_start.isoformat()}", 302)
    key, filename = save_weekly(session, week_start)
    return storage_response(key, filename=filename) or RedirectResponse(f"{WEEKLY_URL}?week={week_start.isoformat()}", 302)


@router.post("/admin/payouts/advances/select")
def advances_select(
    request: Request,
    week: str = Form(...),
    employee_name: str = Form(...),
    checked: str = Form(default=""),
    session: Session = Depends(get_db),
    user=Depends(require_advances_access),
):
    """Автосохранение одной галочки (fetch из ui)."""
    week_start = _parse_week(week)
    if is_frozen(advance_run_for_week(session, week_start)):
        return JSONResponse({"ok": False, "error": "Аванс зафиксирован — расфиксируйте для правки"}, status_code=409)
    employee_user = find_user_by_name(session, employee_name)
    if not can_select(user, employee_user, user_permissions(user)):
        return JSONResponse({"ok": False, "error": "Можно отмечать только своих сотрудников"}, status_code=403)
    set_selection(session, request, user, week_start, employee_name, checked in {"1", "true", "on"})
    session.commit()
    return JSONResponse({"ok": True})


@router.post("/admin/payouts/advances/save")
async def advances_save(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(require_advances_access),
):
    """Кнопка «Сохранить»: галочки видимых строк и вычеты (вычеты — у кого право фиксации)."""
    form = await request.form()
    week_start = _parse_week(form.get("week"))
    back = {"mine": form.get("mine", ""), "tm": form.get("tm", ""), "q": form.get("q", "")}
    if is_frozen(advance_run_for_week(session, week_start)):
        return RedirectResponse(_week_url(week_start, error="Аванс зафиксирован — расфиксируйте для правки", **back), 302)

    perms = user_permissions(user)
    checked = set(form.getlist("selected"))
    errors = []
    for index, name in enumerate(form.getlist("names")):
        employee_user = find_user_by_name(session, name)
        if can_select(user, employee_user, perms):
            set_selection(session, request, user, week_start, name, name in checked)
        if "payouts.advances.fix" in perms:
            amounts = form.getlist("deduction")
            comments = form.getlist("deduction_comment")
            error = save_week_deduction(
                session, request, user, week_start, name,
                amounts[index] if index < len(amounts) else "",
                comments[index] if index < len(comments) else "",
            )
            if error:
                errors.append(error)
    session.commit()
    if errors:
        return RedirectResponse(_week_url(week_start, error="; ".join(errors), **back), 302)
    return RedirectResponse(_week_url(week_start, message="Сохранено", **back), 302)


@router.post("/admin/payouts/advances/fix")
def advances_fix(
    request: Request,
    week: str = Form(...),
    session: Session = Depends(get_db),
    user=Depends(require_advances_access),
):
    week_start = _parse_week(week)
    if not has_permission(user, "payouts.advances.fix"):
        return RedirectResponse(_week_url(week_start, error="Фиксировать аванс может экономист"), 302)
    run, errors = fix_advance(session, request, user, week_start)
    if errors:
        return RedirectResponse(_week_url(week_start, error="; ".join(errors[:10])), 302)
    return RedirectResponse(_week_url(week_start, message="Аванс зафиксирован (табель №%s)" % run.id), 302)


def _run_or_404(session, run_id):
    return session.query(PayrollRun).filter(PayrollRun.id == run_id).with_for_update().first()


def _run_back_url(run, **params):
    if run and run.kind == RUN_KIND_ADVANCE:
        return _week_url(run.date_from, **params)
    query = urlencode({k: v for k, v in params.items() if v})
    return f"/admin/payouts/period/{run.id}" + (f"?{query}" if query else "") if run else "/admin/payouts"


def _can_manage_run(user, run):
    if run and run.kind == RUN_KIND_ADVANCE:
        return has_permission(user, "payouts.advances.fix")
    return has_permission(user, "payroll.manage")


@router.post("/admin/payouts/runs/{run_id}/unfix")
def run_unfix(request: Request, run_id: int, session: Session = Depends(get_db), user=Depends(current_user)):
    run = _run_or_404(session, run_id)
    if not _can_manage_run(user, run):
        raise RedirectException("/")
    error = unfix_run(session, request, user, run)
    return RedirectResponse(_run_back_url(run, error=error, message=None if error else "Расфиксировано"), 302)


@router.post("/admin/payouts/runs/{run_id}/unsend")
def run_unsend(request: Request, run_id: int, session: Session = Depends(get_db), user=Depends(current_user)):
    run = _run_or_404(session, run_id)
    if not _can_manage_run(user, run):
        raise RedirectException("/")
    error = unsend_run(session, request, user, run)
    return RedirectResponse(_run_back_url(run, error=error, message=None if error else "Возвращено в «зафиксирован»"), 302)


@router.get("/admin/payouts/runs/{run_id}/registry")
def run_registry(run_id: int, session: Session = Depends(get_db), user=Depends(current_user)):
    if not has_permission(user, "payouts.export"):
        raise RedirectException("/")
    run = session.query(PayrollRun).filter(PayrollRun.id == run_id).first()
    if not run or run.status not in {"fixed", "sent", "closed"}:
        return RedirectResponse(_run_back_url(run, error="Реестр — только у зафиксированного прогона"), 302)
    key, filename = save_registry(session, run)
    return storage_response(key, filename=filename) or RedirectResponse(_run_back_url(run), 302)


@router.get("/admin/payouts/runs/{run_id}/statement")
def run_statement(run_id: int, session: Session = Depends(get_db), user=Depends(current_user)):
    """П4.4: табель за период в формате ведомости («Табель» + «Ведомость»)."""
    if not has_permission(user, "payouts.export"):
        raise RedirectException("/")
    run = session.query(PayrollRun).filter(PayrollRun.id == run_id).first()
    if not run or run.kind == RUN_KIND_ADVANCE or run.status not in {"fixed", "sent", "closed"}:
        return RedirectResponse(_run_back_url(run, error="Ведомость — только у зафиксированного табеля за период"),
                                302)
    key, filename = save_statement(session, run)
    return storage_response(key, filename=filename) or RedirectResponse(_run_back_url(run), 302)


# ── Табель за период ─────────────────────────────────────────────────────────

def require_payroll_manage(user=Depends(current_user)):
    if not has_permission(user, "payroll.manage"):
        raise RedirectException("/")
    return user


@router.post("/admin/payouts/period/create")
def period_create(
    request: Request,
    date_from: str = Form(...),
    date_to: str = Form(...),
    comment: str = Form(default=""),
    session: Session = Depends(get_db),
    user=Depends(require_payroll_manage),
):
    from routers.payroll import payroll_redirect_url, period_comment_or_refusal

    try:
        start = datetime.strptime(date_from, "%Y-%m-%d").date()
        end = datetime.strptime(date_to, "%Y-%m-%d").date()
    except ValueError:
        return RedirectResponse("/admin/payroll?message=" + quote("Некорректные даты"), 302)
    comment, refusal = period_comment_or_refusal(user, start, end, comment)
    if refusal:
        return RedirectResponse(payroll_redirect_url("/admin/payroll", date_from, date_to, message=refusal), 302)
    run = create_period_draft(session, request, user, start, end, comment)
    return RedirectResponse(f"/admin/payouts/period/{run.id}", 302)


@router.get("/admin/payouts/period/{run_id}", response_class=HTMLResponse)
def period_page(
    request: Request,
    run_id: int,
    message: str = "",
    error: str = "",
    session: Session = Depends(get_db),
    user=Depends(require_payroll_manage),
):
    run = session.query(PayrollRun).filter(PayrollRun.id == run_id).first()
    if not run or run.kind != "period":
        return RedirectResponse("/admin/payouts", 302)
    rows, totals = period_summary(session, run)
    return templates.TemplateResponse(request, "payouts_period.html", {
        "run": run,
        "run_status": RUN_STATUS_LABELS.get(run.status, run.status),
        "fixed_by_name": _user_name(session, run.fixed_by),
        "rows": rows,
        "totals": totals,
        "no_rate": no_rate_summary((item.service, item.hours) for row in rows for item in row["items"]
                                   if item.comment == "Не найдена ЧТС"),
        "perms": user_permissions(user),
        "message": message or None,
        "error": error or None,
    })


@router.post("/admin/payouts/period/{run_id}/rebuild")
def period_rebuild(request: Request, run_id: int, session: Session = Depends(get_db),
                   user=Depends(require_payroll_manage)):
    run = _run_or_404(session, run_id)
    if not run or run.kind != "period" or run.status != "draft":
        return RedirectResponse(_run_back_url(run, error="Пересчитать можно только черновик"), 302)
    create_period_draft(session, request, user, run.date_from, run.date_to, run.comment)
    return RedirectResponse(_run_back_url(run, message="Черновик пересчитан"), 302)


@router.post("/admin/payouts/period/{run_id}/fix")
def period_fix(request: Request, run_id: int, session: Session = Depends(get_db),
               user=Depends(require_payroll_manage)):
    run = _run_or_404(session, run_id)
    errors = fix_period_run(session, request, user, run)
    if errors:
        return RedirectResponse(_run_back_url(run, error="; ".join(errors[:10])), 302)
    return RedirectResponse(_run_back_url(run, message="Табель зафиксирован"), 302)


# ── Надбавки к часу (П4.4) ───────────────────────────────────────────────────

_bonuses_manage = require_permission("payroll.manage")
BONUSES_URL = "/admin/payouts/bonuses"


def _parse_day(value):
    try:
        return date.fromisoformat(value) if value else None
    except ValueError:
        return None


def _bonuses_redirect(message=None, error=None):
    params = {k: v for k, v in (("message", message), ("error", error)) if v}
    return RedirectResponse(BONUSES_URL + ("?" + urlencode(params) if params else ""), status_code=303)


@router.get(BONUSES_URL, response_class=HTMLResponse)
def payouts_bonuses(request: Request, message: str = "", error: str = "",
                    session: Session = Depends(get_db), user=Depends(_bonuses_manage)):
    bonuses = session.query(HourlyBonus).order_by(HourlyBonus.active_from.desc(), HourlyBonus.id.desc()).all()
    return templates.TemplateResponse(request, "payouts_bonuses.html", {
        "user": user, "bonuses": bonuses, "today": business_today(), "message": message, "error": error,
    })


@router.post(BONUSES_URL + "/add")
def payouts_bonus_add(request: Request, name: str = Form(""), amount_per_hour: str = Form(""),
                      active_from: str = Form(""), active_to: str = Form(""), comment: str = Form(""),
                      session: Session = Depends(get_db), user=Depends(_bonuses_manage)):
    name = normalize_text(name)
    amount = parse_money(amount_per_hour)
    start, end = _parse_day(active_from), _parse_day(active_to)
    if not name or amount <= 0 or start is None:
        return _bonuses_redirect(error="Нужны название, сумма за час больше нуля и дата начала")
    if end and end < start:
        return _bonuses_redirect(error="Дата окончания раньше даты начала")
    bonus = HourlyBonus(name=name, amount_per_hour=amount, active_from=start, active_to=end, is_active=True,
                        comment=normalize_text(comment) or None, created_by=user.id)
    session.add(bonus)
    session.flush()
    create_audit_log(session, request, user, "hourly_bonus.create", "hourly_bonus", bonus.id, name,
                     new_value={"amount_per_hour": amount, "active_from": start.isoformat(),
                                "active_to": end.isoformat() if end else None})
    session.commit()
    return _bonuses_redirect(message=f"Надбавка «{name}» {amount:g} ₽/ч добавлена")


@router.post(BONUSES_URL + "/{bonus_id}/close")
def payouts_bonus_close(bonus_id: int, request: Request, active_to: str = Form(""),
                        session: Session = Depends(get_db), user=Depends(_bonuses_manage)):
    bonus = session.get(HourlyBonus, bonus_id)
    end = _parse_day(active_to)
    if bonus is None or end is None:
        return _bonuses_redirect(error="Укажите дату окончания")
    if end < bonus.active_from:
        return _bonuses_redirect(error="Дата окончания раньше даты начала")
    old = bonus.active_to
    bonus.active_to = end
    create_audit_log(session, request, user, "hourly_bonus.close", "hourly_bonus", bonus.id, bonus.name,
                     old_value={"active_to": old.isoformat() if old else None},
                     new_value={"active_to": end.isoformat()})
    session.commit()
    return _bonuses_redirect(message=f"«{bonus.name}» действует по {end:%d.%m.%Y}")


@router.post(BONUSES_URL + "/{bonus_id}/toggle")
def payouts_bonus_toggle(bonus_id: int, request: Request,
                         session: Session = Depends(get_db), user=Depends(_bonuses_manage)):
    bonus = session.get(HourlyBonus, bonus_id)
    if bonus is None:
        return _bonuses_redirect()
    bonus.is_active = not bonus.is_active
    create_audit_log(session, request, user, "hourly_bonus.toggle", "hourly_bonus", bonus.id, bonus.name,
                     old_value={"is_active": not bonus.is_active}, new_value={"is_active": bonus.is_active})
    session.commit()
    return _bonuses_redirect(message=f"«{bonus.name}» {'включена' if bonus.is_active else 'выключена'}")

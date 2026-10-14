"""Демо-туры (П5): шаги тура пользователя, отметка «тур просмотрен» и страница настроек
«Демо-тур» (/admin/tour-settings, только суперадмин — tour.manage). Логика — tours.py."""

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from audit_helpers import create_audit_log
from dependencies import current_user, get_db
from models import TourSettings, User
from rbac import ROLE_EMPLOYEE, ROLE_HR_LEAD, require_permission, role_label
from time_helpers import now_utc
from tours import (AUTOSTART_MODES, MODE_LABELS, autostart_mode, demo_employee, find_demo_user, global_mode,
                   load_settings, mode_for, tour_for_user, tour_id_for, tour_settings)
from utils import normalize_person_name, normalize_phone, normalize_text

router = APIRouter()
templates = Jinja2Templates(directory="templates")
SETTINGS_URL = "/admin/tour-settings"
_tour_manage = require_permission("tour.manage", audit_denied=True)


@router.get("/tour/data")
def tour_data(session: Session = Depends(get_db), user=Depends(current_user)):
    """Шаги тура, положенного пользователю по роли; чужой тур не отдаётся. Руководителю — ещё
    `settings`: какой режим и демо-сотрудник действуют и откуда взяты (проверка на проде)."""
    tour = tour_for_user(user, load_settings(session))
    if tour is None:
        return JSONResponse({"error": "Тура для вашей роли нет"}, status_code=404)
    if tour["id"] == "hr_lead":
        tour["settings"] = tour_settings(session)
    return tour


@router.post("/tour/seen")
def tour_seen(request: Request, session: Session = Depends(get_db), user=Depends(current_user)):
    """«Готово» / «Пропустить»: в режиме first тур больше не стартует сам."""
    if tour_for_user(user) is None:
        return JSONResponse({"ok": False}, status_code=404)
    user = session.get(User, user.id)
    old = user.tour_seen_at.isoformat() if user.tour_seen_at else None
    user.tour_seen_at = now_utc()
    create_audit_log(session, request, user, "tour.seen", "user", user.id, user.employee_name,
                     old_value={"tour_seen_at": old}, new_value={"tour_seen_at": user.tour_seen_at.isoformat()})
    session.commit()
    return {"ok": True}


# ── Страница «Демо-тур» ─────────────────────────────────────────────────────────

def _redirect(**params):
    query = {key: value for key, value in params.items() if value}
    return RedirectResponse(SETTINGS_URL + (f"?{urlencode(query)}" if query else ""), status_code=302)


def _settings_row(session):
    row = session.query(TourSettings).order_by(TourSettings.id).first()
    if row is None:
        row = TourSettings()
        session.add(row)
    return row


def _find_user(session, value):
    """Пользователь с туром по телефону или ФИО: (user, ошибка)."""
    value = normalize_text(value)
    if not value:
        return None, "Укажите ФИО или телефон"
    phone = normalize_phone(value)
    candidates = session.query(User).filter(User.role.in_([ROLE_EMPLOYEE, ROLE_HR_LEAD])).all()
    if phone and len(phone) >= 10:
        found = [u for u in candidates if normalize_phone(u.phone or "") == phone]
    else:
        needle = normalize_person_name(value)
        found = [u for u in candidates if normalize_person_name(u.employee_name or "") == needle]
    found = [u for u in found if tour_id_for(u)]
    if not found:
        return None, f"«{value}» не найден среди сотрудников и руководителей"
    if len(found) > 1:
        return None, f"«{value}» — несколько пользователей, укажите телефон"
    return found[0], None


@router.get(SETTINGS_URL, response_class=HTMLResponse)
def tour_settings_page(request: Request, message: str = "", error: str = "",
                       session: Session = Depends(get_db), user=Depends(_tour_manage)):
    settings = load_settings(session) or {}
    demo = demo_employee(settings)
    users = session.query(User).filter(User.role.in_([ROLE_EMPLOYEE, ROLE_HR_LEAD])).all()
    personal = sorted(
        [u for u in users if u.role == ROLE_HR_LEAD or u.tour_mode],
        key=lambda u: (u.role != ROLE_HR_LEAD, normalize_person_name(u.employee_name or "")))
    rows = [{
        "user": u,
        "role": role_label(u.role),
        "mode": u.tour_mode or "",
        "effective": mode_for(u, settings),
    } for u in personal]
    employees = sorted({u.employee_name for u in users if u.role == ROLE_EMPLOYEE and u.employee_name})
    return templates.TemplateResponse(request, "tour_settings.html", {
        "user": user,
        "modes": [(mode, MODE_LABELS[mode]) for mode in AUTOSTART_MODES],
        "mode_labels": MODE_LABELS,
        "saved_mode": settings.get("autostart_mode") or "",
        "env_mode": autostart_mode(),
        "global_mode": global_mode(settings),
        "saved_demo": settings.get("demo_employee") or "",
        "demo": demo,
        "demo_user": find_demo_user(session, demo) if demo else None,
        "report": tour_settings(session),
        "rows": rows,
        "employees": employees,
        "message": message or None,
        "error": error or None,
    })


@router.post(SETTINGS_URL)
def tour_settings_save(request: Request, autostart_mode: str = Form(default=""), demo_employee: str = Form(default=""),
                       session: Session = Depends(get_db), user=Depends(_tour_manage)):
    mode = normalize_text(autostart_mode).lower()
    if mode and mode not in AUTOSTART_MODES:
        return _redirect(error="Неизвестный режим")
    name = normalize_text(" ".join((demo_employee or "").split()))
    if name:
        found = find_demo_user(session, name)
        if found is None:
            return _redirect(error=f"Сотрудник «{name}» не найден — проверьте ФИО")
        name = found.employee_name
    row = _settings_row(session)
    old = {"autostart_mode": row.autostart_mode, "demo_employee": row.demo_employee}
    new = {"autostart_mode": mode or None, "demo_employee": name or None}
    if old == new:
        return _redirect(message="Изменений нет")
    row.autostart_mode, row.demo_employee = new["autostart_mode"], new["demo_employee"]
    row.updated_by, row.updated_at = user.id, now_utc()
    session.flush()
    create_audit_log(session, request, user, "tour.settings", "tour_settings", row.id, "Демо-тур",
                     old_value=old, new_value=new)
    session.commit()
    return _redirect(message="Настройки тура сохранены")


@router.post(SETTINGS_URL + "/user")
def tour_settings_user(request: Request, target: str = Form(default=""), user_id: int = Form(default=0),
                       tour_mode: str = Form(default=""), reset_seen: str = Form(default=""),
                       session: Session = Depends(get_db), user=Depends(_tour_manage)):
    """Режим тура лично для пользователя («как у всех» — пусто) и «показать снова» (сброс tour_seen_at)."""
    if user_id:
        target_user = session.get(User, user_id)
        error = None if target_user is not None and tour_id_for(target_user) else "Пользователь не найден"
    else:
        target_user, error = _find_user(session, target)
    if error:
        return _redirect(error=error)
    mode = normalize_text(tour_mode).lower()
    if mode and mode not in AUTOSTART_MODES:
        return _redirect(error="Неизвестный режим")
    old = {"tour_mode": target_user.tour_mode,
           "tour_seen_at": target_user.tour_seen_at.isoformat() if target_user.tour_seen_at else None}
    target_user.tour_mode = mode or None
    if reset_seen == "1":
        target_user.tour_seen_at = None
    new = {"tour_mode": target_user.tour_mode,
           "tour_seen_at": target_user.tour_seen_at.isoformat() if target_user.tour_seen_at else None}
    if old == new:
        return _redirect(message="Изменений нет")
    create_audit_log(session, request, user, "tour.user_mode", "user", target_user.id, target_user.employee_name,
                     old_value=old, new_value=new)
    session.commit()
    what = MODE_LABELS[mode].lower() if mode else "как у всех"
    if reset_seen == "1" and old["tour_mode"] == new["tour_mode"]:
        return _redirect(message=f"{target_user.employee_name}: тур покажется снова при следующем входе")
    return _redirect(message=f"{target_user.employee_name}: тур — {what}")

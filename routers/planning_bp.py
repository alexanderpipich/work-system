"""
Бланк планирования (БП) — генерация PDF по магазину и скачивание.

По образцу БП-007: один PDF на ТК со списком активных сотрудников этого ТК.
Рассылки здесь нет (отдельный пункт) — только формирование, сохранение и
скачивание. Доступ: planning.manage (ТМ, руководитель ТМ, суперадмин); пороги
мониторинга — глобальная настройка, только admin.settings. Только формат ГМ.
"""

import calendar
from datetime import date
from io import BytesIO
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from urllib.parse import urlencode

from audit_helpers import create_audit_log
from dependencies import get_db
from file_storage import storage_response, storage_save
from models import (
    EmployeeMonitoringRecommendation,
    EmployeeStoreAssignment,
    PlanningForm,
    Store,
    User,
)
from monitoring_helpers import get_monitoring_settings, recompute_recommendations
from planning_pdf import build_filename, build_planning_pdf
from rbac import has_permission, require_permission
from store_helpers import allows_bp, extract_tk_number, store_formats
from time_helpers import business_today, now_utc
from utils import normalize_format, normalize_text

router = APIRouter()
templates = Jinja2Templates(directory="templates")

_mgmt = require_permission("planning.manage")
_settings = require_permission("admin.settings")

# Префикс ключей в хранилище (в локальном режиме — под GENERATED_FILES_ROOT).
PLANNING_PREFIX = "generated_files/planning_forms"


def _period():
    """Дефолтный период бланка: сегодня … последний день текущего месяца."""
    start = business_today()
    last_day = calendar.monthrange(start.year, start.month)[1]
    return start, start.replace(day=last_day)


def _parse_date(value: str):
    value = (value or "").strip()
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def _employees_for_tk(session: Session, tk: int):
    """Активные сотрудники ТК: список пар (ФИО, должность) без дублей, по ФИО.

    Должность берётся из User.job_title (матч по нормализованному ФИО); если User
    не найден или должность не задана — пустая строка (в БП будет пустая ячейка).
    """
    rows = (
        session.query(EmployeeStoreAssignment)
        .filter(EmployeeStoreAssignment.is_active == True)
        .all()
    )
    names = {
        normalize_text(r.employee_name)
        for r in rows
        if r.employee_name and extract_tk_number(r.store) == tk
    }

    # ФИО → должность из User (матч по нормализованному имени; legacy-данные
    # могут отличаться регистром/пробелами, поэтому нормализуем обе стороны).
    job_by_name = {}
    for user in session.query(User).filter(User.job_title != None).all():
        key = normalize_text(user.employee_name)
        if key in names:
            job_by_name[key] = user.job_title

    return [(name, job_by_name.get(name, "")) for name in sorted(names)]


def _history(session: Session):
    """Ранее сформированные БП (PDF), новые сверху."""
    return (
        session.query(PlanningForm)
        .filter(PlanningForm.file_name.ilike("БП-%.pdf"))
        .order_by(PlanningForm.id.desc())
        .all()
    )


def _store_block(session, selected_store, new_recs):
    """Данные правого блока для выбранного магазина: закреплённые + рекомендации."""
    if not selected_store:
        return None
    assignments = (
        session.query(EmployeeStoreAssignment)
        .filter(
            EmployeeStoreAssignment.store == selected_store,
            EmployeeStoreAssignment.is_active == True,  # noqa: E712
        )
        .order_by(EmployeeStoreAssignment.employee_name)
        .all()
    )
    return {
        "store": selected_store,
        "assignments": assignments,
        "add_recs": [r for r in new_recs if r.store == selected_store and r.recommendation_type == "add_to_planning"],
        "remove_recs": [r for r in new_recs if r.store == selected_store and r.recommendation_type == "remove_from_planning"],
    }


def _page(request, user, session, selected_store="", **extra):
    stores = (
        session.query(Store)
        .filter(Store.is_active == True)
        .order_by(Store.tk_number)
        .all()
    )
    start, end = _period()
    new_recs = (
        session.query(EmployeeMonitoringRecommendation)
        .filter(EmployeeMonitoringRecommendation.status == "new")
        .all()
    )
    # Левый список — магазины с привязками ИЛИ рекомендациями (тот же store-строка,
    # что в рекомендациях/сменах; каталог Store — только для формы генерации PDF).
    assign_stores = {
        a.store for a in session.query(EmployeeStoreAssignment).filter(
            EmployeeStoreAssignment.is_active == True  # noqa: E712
        ).all()
    }
    attention_stores = {r.store for r in new_recs}
    formats = store_formats(session)
    # П4.2: БП только для ГМ — СМ в списке не показываем.
    monitoring_stores = sorted(s for s in assign_stores | attention_stores if allows_bp(formats.get(s)))
    selected_store = normalize_text(selected_store)
    selected_is_gm = allows_bp(formats.get(selected_store)) if selected_store else True
    context = {
        "request": request,
        "user": user,
        "stores": stores,
        "monitoring_stores": monitoring_stores,
        # Магазины с активными рекомендациями — подсветка «внимание».
        "attention_stores": attention_stores,
        "settings": get_monitoring_settings(session),
        "selected_store": selected_store,
        "store_block": _store_block(session, selected_store, new_recs) if selected_is_gm else None,
        "selected_not_gm": bool(selected_store) and not selected_is_gm,
        "can_settings": has_permission(user, "admin.settings"),
        "period": {"date_from": start, "date_to": end},
        # Значения полей формы (ISO для <input type=date>); по умолчанию — дефолт.
        "form": {"date_from": start.isoformat(), "date_to": end.isoformat()},
        "history": _history(session),
        "message": "",
        "error": "",
        "download_url": None,
    }
    context.update(extra)
    return templates.TemplateResponse("planning_bp.html", context)


def _bp_redirect(store="", message="", error=""):
    params = {}
    if store:
        params["store"] = store
    if message:
        params["message"] = message
    if error:
        params["error"] = error
    return RedirectResponse(f"/admin/planning-bp?{urlencode(params)}", status_code=302)


def _activate_assignment(session, user, employee_name, store, city, active, comment=""):
    """Создать/активировать/деактивировать привязку сотрудник↔магазин. Возвращает row."""
    row = (
        session.query(EmployeeStoreAssignment)
        .filter(
            EmployeeStoreAssignment.employee_name == normalize_text(employee_name),
            EmployeeStoreAssignment.store == normalize_text(store),
        )
        .first()
    )
    if row:
        row.is_active = active
        if comment:
            row.comment = normalize_text(comment) or None
    else:
        person = session.query(User).filter(User.employee_name == normalize_text(employee_name)).first()
        row = EmployeeStoreAssignment(
            user_id=person.id if person else None,
            employee_name=normalize_text(employee_name), store=normalize_text(store),
            city=city, is_active=active, created_by=user.id, created_at=now_utc(),
            comment=normalize_text(comment) or None,
        )
        session.add(row)
        session.flush()
    return row


@router.get("/admin/planning-bp", response_class=HTMLResponse)
def planning_bp_page(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_mgmt),
    store: str = "",
    message: str = "",
    error: str = "",
):
    return _page(request, user, session, selected_store=store, message=message, error=error)


@router.post("/admin/planning-bp/monitoring/recompute")
def planning_bp_recompute(request: Request, store: str = Form(default=""),
                          session: Session = Depends(get_db), user=Depends(_mgmt)):
    created = recompute_recommendations(session, request, user)
    return _bp_redirect(store, message=f"Рекомендации обновлены. Новых: {created}")


@router.post("/admin/planning-bp/monitoring/settings")
def planning_bp_settings(request: Request, inactive_days: int = Form(...),
                         minimum_shifts: int = Form(...), analysis_days: int = Form(...),
                         store: str = Form(default=""), session: Session = Depends(get_db), user=Depends(_settings)):
    settings = get_monitoring_settings(session)
    settings.inactive_days = max(inactive_days, 1)
    settings.minimum_shifts = max(minimum_shifts, 1)
    settings.analysis_days = max(analysis_days, 1)
    settings.updated_by = user.id
    settings.updated_at = now_utc()
    session.commit()
    return _bp_redirect(store, message="Пороги сохранены")


@router.post("/admin/planning-bp/assignment/add")
def planning_bp_assignment_add(request: Request, employee_name: str = Form(...), store: str = Form(...),
                               comment: str = Form(default=""), session: Session = Depends(get_db), user=Depends(_mgmt)):
    store = normalize_text(store)
    if not normalize_text(employee_name) or not store:
        return _bp_redirect(store, error="Укажите сотрудника и магазин")
    if not allows_bp(store_formats(session).get(store)):
        return _bp_redirect(store, error="БП ведётся только для формата ГМ")
    store_row = session.query(Store).filter(Store.display_name == store).first()
    row = _activate_assignment(session, user, employee_name, store,
                               store_row.city if store_row else None, active=True, comment=comment)
    create_audit_log(session, request, user, "planning_assignment_created",
                     "employee_store_assignment", row.id, f"{row.employee_name} / {row.store}")
    session.commit()
    return _bp_redirect(store, message=f"Добавлен в БП: {row.employee_name}")


@router.post("/admin/planning-bp/assignment/deactivate")
def planning_bp_assignment_deactivate(request: Request, assignment_id: int = Form(...), store: str = Form(default=""),
                                      session: Session = Depends(get_db), user=Depends(_mgmt)):
    """П4.2: убрать сотрудника из БП (закрепление неактивно; работать в ТК это не мешает)."""
    row = session.query(EmployeeStoreAssignment).filter(EmployeeStoreAssignment.id == assignment_id).first()
    if row is None or not row.is_active:
        return _bp_redirect(store, error="Закрепление не найдено")
    row.is_active = False
    create_audit_log(session, request, user, "planning_assignment_updated", "employee_store_assignment",
                     row.id, f"{row.employee_name} / {row.store}",
                     old_value={"is_active": True}, new_value={"is_active": False}, comment="убран из БП вручную")
    session.commit()
    return _bp_redirect(row.store, message=f"{row.employee_name} убран из БП")


@router.post("/admin/planning-bp/monitoring/accept")
def planning_bp_accept(request: Request, recommendation_id: int = Form(...),
                       store: str = Form(default=""), session: Session = Depends(get_db), user=Depends(_mgmt)):
    """Принять рекомендацию: add → добавить в БП; remove → убрать. Человеком, с аудитом."""
    rec = session.query(EmployeeMonitoringRecommendation).filter(
        EmployeeMonitoringRecommendation.id == recommendation_id,
        EmployeeMonitoringRecommendation.status == "new",
    ).first()
    if not rec:
        return _bp_redirect(store, error="Рекомендация не найдена")
    add = rec.recommendation_type == "add_to_planning"
    row = _activate_assignment(session, user, rec.employee_name, rec.store, rec.city, active=add)
    rec.status = "accepted"
    rec.processed_by = user.id
    rec.processed_at = now_utc()
    create_audit_log(
        session, request, user,
        "planning_assignment_created" if add else "planning_assignment_updated",
        "employee_store_assignment", row.id, f"{row.employee_name} / {row.store}",
        comment=f"по рекомендации #{rec.id} ({'добавить' if add else 'убрать'})",
    )
    session.commit()
    verb = "добавлен в БП" if add else "убран из БП"
    return _bp_redirect(rec.store, message=f"{rec.employee_name} {verb}")


@router.post("/admin/planning-bp/monitoring/dismiss")
def planning_bp_dismiss_rec(request: Request, recommendation_id: int = Form(...),
                            store: str = Form(default=""), session: Session = Depends(get_db), user=Depends(_mgmt)):
    """Отклонить рекомендацию (не менять привязку)."""
    rec = session.query(EmployeeMonitoringRecommendation).filter(
        EmployeeMonitoringRecommendation.id == recommendation_id,
        EmployeeMonitoringRecommendation.status == "new",
    ).first()
    if rec:
        rec.status = "dismissed"
        rec.processed_by = user.id
        rec.processed_at = now_utc()
        session.commit()
    return _bp_redirect(store, message="Рекомендация отклонена")


@router.post("/admin/planning-bp/generate", response_class=HTMLResponse)
def planning_bp_generate(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_mgmt),
    tk_number: int = Form(...),
    date_from: str = Form(""),
    date_to: str = Form(""),
):
    store = session.query(Store).filter(Store.tk_number == tk_number).first()
    if store is None:
        return _page(request, user, session, error=f"Магазин ТК-{tk_number:03d} не найден.")

    # БП формируется только для гипермаркетов (формат ГМ).
    if normalize_format(store.format) != "ГМ":
        return _page(
            request, user, session,
            error=f"БП формируется только для формата ГМ. ТК-{tk_number:03d} — формат «{store.format or '—'}».",
        )

    # Период из формы; пустые поля → дефолт (сегодня … конец месяца).
    default_start, default_end = _period()
    start = _parse_date(date_from) or default_start
    end = _parse_date(date_to) or default_end
    if end < start:
        return _page(
            request, user, session,
            error="Дата по не может быть раньше даты с.",
            form={"date_from": start.isoformat(), "date_to": end.isoformat()},
        )

    employees = _employees_for_tk(session, tk_number)

    row = PlanningForm(
        employee_name=store.display_name or f"ТК-{tk_number:03d}",
        store=store.display_name or f"ТК-{tk_number:03d}",
        city=store.city,
        date_from=start,
        date_to=end,
        status="created",
        created_by=user.id,
        created_at=now_utc(),
        comment=f"БП ТК-{tk_number:03d}; сотрудников: {len(employees)}",
    )
    session.add(row)
    session.flush()  # нужен row.id для имени файла в хранилище

    buffer = BytesIO()
    build_planning_pdf(
        buffer,
        tk_number=tk_number,
        object_address=store.object_address,
        city=store.city,
        date_from=start,
        date_to=end,
        employees=employees,
    )
    row.file_path = storage_save(
        f"{PLANNING_PREFIX}/planning_bp_{row.id}.pdf",
        buffer.getvalue(),
        content_type="application/pdf",
    )
    row.file_name = build_filename(tk_number, start)

    create_audit_log(
        session, request, user,
        "planning_bp_generated", "planning_form", row.id,
        f"ТК-{tk_number:03d}",
        new_value={
            "tk": tk_number,
            "period": f"{start:%d.%m.%Y}–{end:%d.%m.%Y}",
            "employees": len(employees),
        },
        comment="planning blank PDF",
    )
    session.commit()

    note = "" if employees else " Внимание: активных сотрудников по ТК не найдено — таблица пустая."
    return _page(
        request, user, session,
        message=f"БП по ТК-{tk_number:03d} сформирован ({len(employees)} сотр.).{note}",
        download_url=f"/admin/planning-bp/{row.id}/download",
    )


@router.get("/admin/planning-bp/{form_id}/download")
def planning_bp_download(
    form_id: int,
    session: Session = Depends(get_db),
    user=Depends(_mgmt),
):
    row = session.query(PlanningForm).filter(PlanningForm.id == form_id).first()
    if not row:
        return RedirectResponse("/admin/planning-bp", status_code=302)
    return storage_response(
        row.file_path,
        filename=row.file_name or Path(row.file_path or "").name,
        media_type="application/pdf",
    ) or RedirectResponse("/admin/planning-bp", status_code=302)

"""
Бланк планирования (БП) — генерация PDF по магазину и скачивание.

По образцу БП-007: один PDF на ТК со списком активных сотрудников этого ТК.
Рассылки здесь нет (отдельный пункт) — только формирование, сохранение и
скачивание. Доступ: superadmin (право admin.settings).
"""

import calendar
import os
from datetime import date
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from audit_helpers import create_audit_log
from dependencies import get_db
from models import EmployeeStoreAssignment, PlanningForm, Store
from planning_pdf import build_filename, build_planning_pdf
from rbac import require_permission
from store_helpers import extract_tk_number
from time_helpers import business_today, now_utc
from utils import normalize_text

router = APIRouter()
templates = Jinja2Templates(directory="templates")

_mgmt = require_permission("admin.settings")

GENERATED_FILES_ROOT = Path(os.getenv("GENERATED_FILES_ROOT", "generated_files"))
PLANNING_DIR = GENERATED_FILES_ROOT / "planning_forms"


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
    """Активные сотрудники, привязанные к этому ТК, по ФИО (без дублей)."""
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
    return sorted(names)


def _history(session: Session):
    """Ранее сформированные БП (PDF), новые сверху."""
    return (
        session.query(PlanningForm)
        .filter(PlanningForm.file_name.ilike("БП-%.pdf"))
        .order_by(PlanningForm.id.desc())
        .all()
    )


def _page(request, user, session, **extra):
    stores = (
        session.query(Store)
        .filter(Store.is_active == True)
        .order_by(Store.tk_number)
        .all()
    )
    start, end = _period()
    context = {
        "request": request,
        "user": user,
        "stores": stores,
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


@router.get("/admin/planning-bp", response_class=HTMLResponse)
def planning_bp_page(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_mgmt),
    message: str = "",
    error: str = "",
):
    return _page(request, user, session, message=message, error=error)


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
    session.flush()  # нужен row.id для имени файла на диске

    PLANNING_DIR.mkdir(parents=True, exist_ok=True)
    disk_path = PLANNING_DIR / f"planning_bp_{row.id}.pdf"
    build_planning_pdf(
        disk_path,
        tk_number=tk_number,
        object_address=store.object_address,
        city=store.city,
        date_from=start,
        date_to=end,
        employees=employees,
    )
    row.file_path = str(disk_path)
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
    if not row or not row.file_path or not Path(row.file_path).is_file():
        return RedirectResponse("/admin/planning-bp", status_code=302)
    return FileResponse(row.file_path, filename=row.file_name, media_type="application/pdf")

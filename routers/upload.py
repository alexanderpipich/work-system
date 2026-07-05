import logging
import re

import pandas as pd
from fastapi import APIRouter, Depends, File, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from audit_helpers import create_audit_log
from dependencies import get_db
from models import Shift, TimebookEmployee, UploadLog
from payroll_adjustments import reconcile_sent_payroll_runs
from rbac import require_permission
from time_helpers import business_today, now_utc
from utils import normalize_format, normalize_phone, normalize_text

_require_upload = require_permission("shifts.upload")


router = APIRouter()
templates = Jinja2Templates(directory="templates")
logger = logging.getLogger(__name__)

UPLOAD_BATCH_SIZE = 500
DEFAULT_REQUEST_TYPE = "Основные заказы"
NO_PLAN_REQUEST_TYPE = "Смена без плана"
SHIFT_KEY_COLUMNS = ["store", "format", "date", "service", "employee", "request_type"]


def recent_upload_logs(session):
    return session.query(UploadLog).order_by(
        UploadLog.id.desc()
    ).limit(20).all()


def _previous_month(today_date):
    if today_date.month == 1:
        return 12, today_date.year - 1
    return today_date.month - 1, today_date.year


def _is_editable_month(shift_date, today_date):
    if shift_date.year == today_date.year and shift_date.month == today_date.month:
        return True

    prev_month, prev_year = _previous_month(today_date)
    return (
        shift_date.year == prev_year
        and shift_date.month == prev_month
        and today_date.day <= 7
    )


def _choose_last_text(values, default=""):
    clean_values = [normalize_text(value) for value in values if normalize_text(value)]
    return clean_values[-1] if clean_values else default


def _resolve_col(df, candidates, fallback_index):
    """Найти колонку по заголовку (подстрока, регистр/пробелы игнор), иначе по индексу.

    candidates — упорядоченный список подстрок (специфичные раньше общих).
    В реальных данных телефон/табельный иногда смещены — заголовок надёжнее индекса.
    """
    normalized = {col: re.sub(r"\s+", " ", str(col)).strip().lower() for col in df.columns}
    for sub in candidates:
        for col, name in normalized.items():
            if sub in name:
                return df[col]
    if fallback_index < len(df.columns):
        return df.iloc[:, fallback_index]
    return None


def _cell_phone(value):
    if value is None or pd.isna(value):
        return ""
    return normalize_phone(value)


def _cell_str(value):
    if value is None or pd.isna(value):
        return ""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return normalize_text(value)


def _extract_timebook_contacts(df):
    """{нормализованное ФИО: {phone, inn, tab}} из timebook, последнее непустое значение."""
    emp = _resolve_col(df, ["фио сотрудника исполнителя", "фио сотрудника", "фио", "исполнител"], 13)
    if emp is None:
        return {}
    phone = _resolve_col(df, ["номер телефона", "телефон"], 15)
    inn = _resolve_col(df, ["инн сотрудника", "инн"], 16)
    tab = _resolve_col(df, ["табельный номер", "табельный"], 14)

    contacts = {}
    for i in range(len(df)):
        name = _cell_str(emp.iloc[i])
        if not name:
            continue
        rec = contacts.setdefault(name, {"phone": "", "inn": "", "tab": ""})
        if phone is not None:
            p = _cell_phone(phone.iloc[i])
            if p:
                rec["phone"] = p
        if inn is not None:
            v = _cell_str(inn.iloc[i])
            if v:
                rec["inn"] = v
        if tab is not None:
            v = _cell_str(tab.iloc[i])
            if v:
                rec["tab"] = v
    return contacts


def _upsert_timebook_contacts(session, contacts):
    """Сохранить связку ФИО→контакты в стейджинг (непустое обновляет). Смены не трогаем."""
    for name, rec in contacts.items():
        if not (rec["phone"] or rec["inn"] or rec["tab"]):
            continue
        row = session.query(TimebookEmployee).filter(TimebookEmployee.employee_name == name).first()
        if not row:
            row = TimebookEmployee(employee_name=name)
            session.add(row)
        if rec["phone"]:
            row.phone = rec["phone"]
        if rec["inn"]:
            row.inn = rec["inn"]
        if rec["tab"]:
            row.tab_number = rec["tab"]
        row.updated_at = now_utc()


def _normalize_upload_dataframe(df):
    if len(df.columns) < 27:
        raise ValueError("Недостаточно колонок в Excel-файле")

    # Контакты (телефон/ИНН/табельный) — из ПОЛНОГО df по заголовку, до слайса.
    contacts = _extract_timebook_contacts(df)

    # A=0 store, C=2 format, E=4 city, H=7 date,
    # J=9 request_type, M=12 service, N=13 employee, AA=26 hours.
    df = df.iloc[:, [0, 2, 4, 7, 9, 12, 13, 26]].copy()
    df.columns = [
        "store",
        "format",
        "city",
        "date",
        "request_type",
        "service",
        "employee",
        "hours",
    ]

    if df.empty:
        raise ValueError("Файл пуст")

    before_required = len(df)
    df = df.dropna(subset=["store", "format", "date", "service", "employee", "hours"])
    skipped_invalid = before_required - len(df)

    df["store"] = df["store"].apply(normalize_text)
    df["format"] = df["format"].apply(normalize_format)
    df["city"] = df["city"].apply(normalize_text)
    df["request_type"] = df["request_type"].apply(normalize_text)
    df.loc[df["request_type"] == "", "request_type"] = DEFAULT_REQUEST_TYPE
    df["service"] = df["service"].apply(normalize_text)
    df["employee"] = df["employee"].apply(normalize_text)
    df["date"] = pd.to_datetime(df["date"], dayfirst=True, errors="coerce")
    df["hours"] = pd.to_numeric(df["hours"], errors="coerce")

    valid_mask = df["date"].notna() & df["hours"].notna()
    skipped_invalid += int((~valid_mask).sum())
    df = df[valid_mask].copy()

    if df.empty:
        return df, skipped_invalid, contacts

    # request_type is part of the business identity: no-plan shifts must stay
    # separate from normal planned shifts for display and payroll.
    grouped = df.groupby(SHIFT_KEY_COLUMNS, as_index=False).agg(
        hours=("hours", "sum"),
        city=("city", _choose_last_text),
    )
    return grouped, skipped_invalid, contacts


def _shift_query(session, row):
    return session.query(Shift).filter(
        Shift.employee == row["employee"],
        Shift.store == row["store"],
        Shift.format == row["format"],
        Shift.service == row["service"],
        Shift.shift_date == row["date"].date(),
        Shift.request_type == row["request_type"],
    )


def _process_shift_dataframe(session, df):
    rows, skipped_invalid, contacts = _normalize_upload_dataframe(df)
    _upsert_timebook_contacts(session, contacts)
    added = 0
    updated = 0
    skipped_duplicates = skipped_invalid
    skipped_locked_months = 0
    today_date = business_today()

    for index, row in rows.iterrows():
        shift_date = row["date"].date()
        if not _is_editable_month(shift_date, today_date):
            skipped_locked_months += 1
            continue

        employee = row["employee"]
        store = row["store"]
        city = row["city"]
        service = row["service"]
        format_value = row["format"]
        request_type = row["request_type"] or DEFAULT_REQUEST_TYPE
        hours = float(row["hours"])

        existing = _shift_query(session, row).first()
        if existing:
            row_changed = False

            if float(existing.hours or 0) != hours:
                existing.hours = hours
                row_changed = True

            if normalize_text(existing.city) != city:
                existing.city = city
                row_changed = True

            if row_changed:
                updated += 1
            else:
                skipped_duplicates += 1
            continue

        session.add(
            Shift(
                employee=employee,
                store=store,
                city=city,
                service=service,
                format=format_value,
                shift_date=shift_date,
                hours=hours,
                request_type=request_type,
            )
        )
        added += 1

        if (added + updated) % UPLOAD_BATCH_SIZE == 0:
            session.flush()

    session.commit()
    adjustments_created = reconcile_sent_payroll_runs(session)

    return {
        "added": added,
        "updated": updated,
        "skipped_duplicates": skipped_duplicates,
        "skipped_locked_months": skipped_locked_months,
        "adjustments_created": adjustments_created,
    }


def _write_upload_log(session, request, admin, filename, result=None, error=None):
    result = result or {}
    log = UploadLog(
        filename=filename,
        uploaded_by=admin.id if admin else None,
        added=result.get("added", 0),
        updated=result.get("updated", 0),
        skipped_duplicates=result.get("skipped_duplicates", 0),
        skipped_locked_months=result.get("skipped_locked_months", 0),
        adjustments_created=result.get("adjustments_created", 0),
        status="error" if error else "success",
        error=error,
    )
    session.add(log)
    session.flush()

    if error:
        create_audit_log(
            session,
            request,
            admin,
            "excel_upload_failed",
            "upload_log",
            log.id,
            filename,
            new_value={"status": "error", "error": error},
        )
    else:
        create_audit_log(
            session,
            request,
            admin,
            "excel_uploaded",
            "upload_log",
            log.id,
            filename,
            new_value=result,
        )
        if result.get("adjustments_created"):
            create_audit_log(
                session,
                request,
                admin,
                "adjustments_generated",
                "upload_log",
                log.id,
                filename,
                new_value={"adjustments_created": result["adjustments_created"]},
            )

    session.commit()
    return log


@router.get("/admin/upload", response_class=HTMLResponse)
def admin_upload_page(
    request: Request,
    session: Session = Depends(get_db),
    admin=Depends(_require_upload),
):
    return templates.TemplateResponse(
        request,
        "admin_upload.html",
        {
            "logs": recent_upload_logs(session),
            "message": None,
            "error": None,
            "result": None,
        },
    )




@router.post("/admin/upload", response_class=HTMLResponse)
async def admin_upload_submit(
    request: Request,
    file: UploadFile = File(...),
    session: Session = Depends(get_db),
    admin=Depends(_require_upload),
):
    if not (file.filename or "").lower().endswith(".xlsx"):
        return templates.TemplateResponse(
            request,
            "admin_upload.html",
            {
                "logs": recent_upload_logs(session),
                "message": None,
                "result": None,
                "error": "Разрешены только .xlsx файлы",
            },
        )

    try:
        df = pd.read_excel(file.file)
        result = _process_shift_dataframe(session, df)
        _write_upload_log(session, request, admin, file.filename, result=result)

        return templates.TemplateResponse(
            request,
            "admin_upload.html",
            {
                "logs": recent_upload_logs(session),
                "message": "Файл успешно загружен",
                "error": None,
                "result": result,
            },
        )

    except Exception as exc:
        session.rollback()
        logger.exception("Admin upload failed")
        _write_upload_log(
            session,
            request,
            admin,
            file.filename if file else None,
            error=str(exc),
        )
        return templates.TemplateResponse(
            request,
            "admin_upload.html",
            {
                "logs": recent_upload_logs(session),
                "message": None,
                "result": None,
                "error": "Upload failed",
            },
        )

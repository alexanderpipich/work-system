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
from service_catalog import diagnose_uploaded_services
from time_helpers import business_today, is_editable_month, now_utc, previous_month
from utils import normalize_format, normalize_phone, normalize_text

_require_upload = require_permission("shifts.upload")


router = APIRouter()
templates = Jinja2Templates(directory="templates")
logger = logging.getLogger(__name__)

UPLOAD_BATCH_SIZE = 500
DEFAULT_REQUEST_TYPE = "Основные заказы"
NO_PLAN_REQUEST_TYPE = "Смена без плана"
SHIFT_KEY_COLUMNS = ["store", "format", "date", "service", "employee", "request_type"]

# Строка заголовков в отчёте смен — вторая (первая занята агрегатами «Итого:»).
TIMEBOOK_HEADER_ROW = 1

EMPLOYEE_CANDIDATES = ["фио сотрудника исполнителя", "фио сотрудника", "фио"]

# (поле, кандидаты-заголовки, fallback-индекс, обязательное).
# Индексы — страховка на случай отсутствия заголовка; порядок колонок в отчёте
# уже менялся, поэтому первичен ЗАГОЛОВОК.
SHIFT_COLUMN_SPECS = [
    ("store", "Магазин", ["магазин"], 0, True),
    ("format", "Формат", ["формат"], 2, True),
    ("city", "Город", ["город"], 4, False),
    ("date", "Дата", ["дата"], 7, True),
    ("request_type", "Тип заявки", ["тип заявки"], 9, False),
    ("service", "Услуга", ["услуга"], 13, True),
    ("employee", "ФИО сотрудника Исполнителя", EMPLOYEE_CANDIDATES, 14, True),
    # Часы — ТОЛЬКО числовая колонка. Соседняя «…, чч:мм» — timedelta, не парсится.
    ("hours", "ПланФакт … (в числовом формате), часы", ["в числовом формате"], 27, True),
]


def recent_upload_logs(session):
    return session.query(UploadLog).order_by(
        UploadLog.id.desc()
    ).limit(20).all()


# Правило редактируемого месяца переехало в time_helpers: его же использует
# рассылка «смена без плана», а два экземпляра одного правила разошлись бы.
# Имена оставлены прежними — на них ссылается остальной модуль.
_previous_month = previous_month
_is_editable_month = is_editable_month


def _choose_last_text(values, default=""):
    clean_values = [normalize_text(value) for value in values if normalize_text(value)]
    return clean_values[-1] if clean_values else default


def _resolve_col(df, candidates, fallback_index):
    """Найти колонку по заголовку, иначе по индексу. Вернуть (Series | None, by_header).

    Сначала точное совпадение заголовка, потом подстрочное — иначе «формат» матчит
    «ПланФакт … (в числовом формате), часы». candidates — упорядоченный список
    (специфичные раньше общих). Заголовок надёжнее индекса: формат отчёта уже менялся.
    """
    normalized = {col: re.sub(r"\s+", " ", str(col)).strip().lower() for col in df.columns}
    for match in (lambda sub, name: name == sub, lambda sub, name: sub in name):
        for sub in candidates:
            for col, name in normalized.items():
                if match(sub, name):
                    return df[col], True
    if fallback_index < len(df.columns):
        return df.iloc[:, fallback_index], False
    return None, False


def _cell_phone(value):
    if value is None or pd.isna(value):
        return ""
    return normalize_phone(value)


_PHONE_LIKE = re.compile(r"^[78]\d{10}$")


def _looks_like_phone(value):
    """11 цифр, начинается с 7/8 — российский номер. Табельные короче (42, 12345)."""
    return bool(_PHONE_LIKE.match(re.sub(r"\D", "", str(value))))


def _cell_str(value):
    if value is None or pd.isna(value):
        return ""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return normalize_text(value)


def _extract_timebook_contacts(df):
    """{нормализованное ФИО: {phone, inn, tab}} из timebook, последнее непустое значение."""
    emp, _ = _resolve_col(df, EMPLOYEE_CANDIDATES + ["исполнител"], 14)
    if emp is None:
        return {}
    phone, _ = _resolve_col(df, ["номер телефона", "телефон"], 16)
    inn, _ = _resolve_col(df, ["инн сотрудника", "инн"], 17)
    tab, _ = _resolve_col(df, ["табельный номер", "табельный"], 15)

    contacts = {}
    for i in range(len(df)):
        name = _cell_str(emp.iloc[i])
        if not name:
            continue
        rec = contacts.setdefault(name, {"phone": "", "inn": "", "tab": ""})

        phone_value = _cell_phone(phone.iloc[i]) if phone is not None else ""
        tab_value = _cell_str(tab.iloc[i]) if tab is not None else ""

        # В отчёте заказчика телефон иногда лежит в колонке табельного, а «Номер
        # телефона» пуст. Номер как табельный не сохраняем — это не табельный.
        if not phone_value and _looks_like_phone(tab_value):
            phone_value = normalize_phone(tab_value)
            tab_value = ""

        if phone_value:
            rec["phone"] = phone_value
        if tab_value:
            rec["tab"] = tab_value
        if inn is not None:
            v = _cell_str(inn.iloc[i])
            if v:
                rec["inn"] = v
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


def _build_shift_dataframe(df):
    """Собрать df смен по ЗАГОЛОВКАМ колонок (fallback — индекс).

    Устойчиво к добавлению/перестановке колонок в отчёте, пока заголовки называются
    по-прежнему. Отсутствие обязательного заголовка — внятная ошибка, не тихий мусор.
    """
    columns = {}
    matched_by_header = 0
    missing = []
    for field, title, candidates, fallback_index, required in SHIFT_COLUMN_SPECS:
        series, by_header = _resolve_col(df, candidates, fallback_index)
        matched_by_header += int(by_header)
        if series is None:
            if required:
                missing.append(title)
            continue
        columns[field] = series.reset_index(drop=True)

    if missing:
        raise ValueError("Не найдена колонка: " + ", ".join(f"«{title}»" for title in missing))

    if matched_by_header == 0:
        # Все колонки пришлось брать по индексу — заголовков нет ни одного.
        # Молча разложить данные по позициям опаснее, чем упасть.
        raise ValueError("Не распознаны заголовки колонок — ожидается строка 2 файла")

    for field in ("city", "request_type"):
        if field not in columns:
            columns[field] = pd.Series([""] * len(df))

    return pd.DataFrame({field: columns[field] for field, *_ in SHIFT_COLUMN_SPECS})


def _normalize_upload_dataframe(df):
    # Контакты (телефон/ИНН/табельный) — из ПОЛНОГО df по заголовку, до сборки.
    contacts = _extract_timebook_contacts(df)

    df = _build_shift_dataframe(df)

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

    # Автопересчёт рекомендаций мониторинга выходов (глобально, без user-скоупа) —
    # чтобы после загрузки смен планирование/увольнения были свежими без ручной кнопки.
    from monitoring_helpers import recompute_recommendations
    try:
        recompute_recommendations(session)
    except Exception:
        logger.exception("Monitoring recompute after upload failed")
        session.rollback()

    # АПД: проверить, не набрал ли приведённый порог часов → pending-премия.
    from referral_helpers import check_referral_thresholds
    try:
        check_referral_thresholds(session)
    except Exception:
        logger.exception("Referral threshold check after upload failed")
        session.rollback()

    # Диагностика услуг (этап 4): какие услуги из файла не нашлись в справочнике
    # Service → по ним не подтянется тариф. Информационно, загрузку не блокирует.
    service_counts = (
        rows["service"].value_counts().to_dict() if not rows.empty else {}
    )
    diagnostics = diagnose_uploaded_services(session, service_counts)

    return {
        "added": added,
        "updated": updated,
        "skipped_duplicates": skipped_duplicates,
        "skipped_locked_months": skipped_locked_months,
        "adjustments_created": adjustments_created,
        "unmatched_services": diagnostics["unmatched_services"],
        "services_without_level": diagnostics["services_without_level"],
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
        df = pd.read_excel(file.file, header=TIMEBOOK_HEADER_ROW)
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

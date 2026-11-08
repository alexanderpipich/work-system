import hashlib
import logging
import os
import re
import sys
import tempfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta
from types import SimpleNamespace
from xml.etree.ElementTree import ParseError
from zipfile import BadZipFile

import pandas as pd
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from openpyxl import load_workbook
from openpyxl.cell.cell import ERROR_CODES
from openpyxl.utils.exceptions import InvalidFileException
from sqlalchemy import tuple_
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from audit_helpers import create_audit_log
from database import SessionLocal
from dependencies import current_user, get_db
from models import Shift, TimebookEmployee, UploadLog, User
from payroll_adjustments import reconcile_sent_payroll_runs
from rbac import has_permission, record_denied_action, require_permission
from service_catalog import diagnose_uploaded_services
from store_helpers import extract_tk_number, store_city_by_tk, timebook_cities
from time_helpers import business_today, is_editable_month, now_utc, previous_month
from utils import normalize_city, normalize_format, normalize_phone, normalize_text

# П4.8: журнал загрузок открывает upload.view (HR-руководитель), сама загрузка timebook —
# shifts.upload, только суперадмин; отказ на POST — 403 с аудитом.
_require_upload_view = require_permission("upload.view")
UPLOAD_LOCKED_HINT = "Загрузка timebook — право суперадмина"


def _require_upload(request: Request, session: Session = Depends(get_db), user=Depends(current_user)):
    if not has_permission(user, "shifts.upload"):
        if has_permission(user, "upload.view"):
            record_denied_action(session, request, user, "shifts.upload")
            raise HTTPException(status_code=403, detail=UPLOAD_LOCKED_HINT)
        return require_permission("shifts.upload")(request, session, user)
    return user


router = APIRouter()
templates = Jinja2Templates(directory="templates")
logger = logging.getLogger(__name__)

UPLOAD_BATCH_SIZE = 500
UPLOAD_CHUNK_BYTES = 1024 * 1024
UPLOAD_HEARTBEAT_ROWS = 5000
# Обработка отмечается в журнале после каждой пачки; дольше этого без отметок —
# поток умер вместе с контейнером, а запись не должна вечно блокировать повтор файла.
UPLOAD_STALE_AFTER = timedelta(minutes=15)

UPLOAD_STATUS_PROCESSING = "processing"
UPLOAD_STATUS_SUCCESS = "success"
UPLOAD_STATUS_ERROR = "error"
UPLOAD_STATUS_LABELS = {
    UPLOAD_STATUS_PROCESSING: "в обработке",
    UPLOAD_STATUS_SUCCESS: "готово",
    UPLOAD_STATUS_ERROR: "ошибка",
}
UPLOAD_INTERRUPTED_ERROR = "Обработка прервана перезапуском сервера. Загрузите файл ещё раз."

DEFAULT_REQUEST_TYPE = "Основные заказы"
NO_PLAN_REQUEST_TYPE = "Смена без плана"
SHIFT_KEY_COLUMNS = ["store", "format", "date", "service", "employee", "request_type"]

# Строка заголовков в отчёте смен — вторая (первая занята агрегатами «Итого:»).
TIMEBOOK_HEADER_ROW = 1

# Что pandas.read_excel считал пустой ячейкой: разбор без pandas обязан вести себя так же,
# иначе услуга «NA» или ячейка «#REF!» из пропущенных строк превратятся в смены.
XLSX_NA_VALUES = frozenset({
    "", "#N/A", "#N/A N/A", "#NA", "-1.#IND", "-1.#QNAN", "-NaN", "-nan", "1.#IND", "1.#QNAN",
    "<NA>", "N/A", "NA", "NULL", "NaN", "None", "n/a", "nan", "null",
}) | frozenset(ERROR_CODES)

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


def _resolve_index(columns, candidates, fallback_index):
    """Найти номер колонки по заголовку, иначе по индексу. Вернуть (номер | None, by_header).

    Сначала точное совпадение заголовка, потом подстрочное — иначе «формат» матчит
    «ПланФакт … (в числовом формате), часы». candidates — упорядоченный список
    (специфичные раньше общих). Заголовок надёжнее индекса: формат отчёта уже менялся.
    """
    normalized = [re.sub(r"\s+", " ", str(col)).strip().lower() for col in columns]
    for match in (lambda sub, name: name == sub, lambda sub, name: sub in name):
        for sub in candidates:
            for index, name in enumerate(normalized):
                if match(sub, name):
                    return index, True
    if fallback_index < len(normalized):
        return fallback_index, False
    return None, False


def _resolve_col(df, candidates, fallback_index):
    """То же для DataFrame: (Series | None, by_header)."""
    index, by_header = _resolve_index(df.columns, candidates, fallback_index)
    return (None if index is None else df.iloc[:, index]), by_header


def _cell(row, index):
    return row[index] if index is not None and index < len(row) else None


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


class _ContactCollector:
    """{нормализованное ФИО: {phone, inn, tab}} из timebook, последнее непустое значение."""

    def __init__(self, columns):
        self.contacts = {}
        self.emp, _ = _resolve_index(columns, EMPLOYEE_CANDIDATES + ["исполнител"], 14)
        self.phone, _ = _resolve_index(columns, ["номер телефона", "телефон"], 16)
        self.inn, _ = _resolve_index(columns, ["инн сотрудника", "инн"], 17)
        self.tab, _ = _resolve_index(columns, ["табельный номер", "табельный"], 15)

    def feed(self, row):
        if self.emp is None:
            return
        name = _cell_str(_cell(row, self.emp))
        if not name:
            return
        rec = self.contacts.setdefault(name, {"phone": "", "inn": "", "tab": ""})

        phone_value = _cell_phone(_cell(row, self.phone))
        tab_value = _cell_str(_cell(row, self.tab))

        # В отчёте заказчика телефон иногда лежит в колонке табельного, а «Номер
        # телефона» пуст. Номер как табельный не сохраняем — это не табельный.
        if not phone_value and _looks_like_phone(tab_value):
            phone_value = normalize_phone(tab_value)
            tab_value = ""

        if phone_value:
            rec["phone"] = phone_value
        if tab_value:
            rec["tab"] = tab_value
        inn_value = _cell_str(_cell(row, self.inn))
        if inn_value:
            rec["inn"] = inn_value


def _extract_timebook_contacts(df):
    collector = _ContactCollector(df.columns)
    for row in df.itertuples(index=False, name=None):
        collector.feed(row)
    return collector.contacts


def _upsert_timebook_contacts(session, contacts):
    """Сохранить связку ФИО→контакты в стейджинг (непустое обновляет). Смены не трогаем."""
    filled = [(name, rec) for name, rec in contacts.items() if rec["phone"] or rec["inn"] or rec["tab"]]
    for start in range(0, len(filled), UPLOAD_BATCH_SIZE):
        chunk = filled[start:start + UPLOAD_BATCH_SIZE]
        existing = {
            row.employee_name: row
            for row in session.query(TimebookEmployee).filter(
                TimebookEmployee.employee_name.in_([name for name, _rec in chunk])
            )
        }
        for name, rec in chunk:
            row = existing.get(name)
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


def _parse_shift_date(value):
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return datetime.strptime(value.strip(), "%d.%m.%Y").date()
        except ValueError:
            pass
    try:
        parsed = pd.to_datetime(value, dayfirst=True, errors="coerce")
    except (TypeError, ValueError):
        return None
    return None if pd.isna(parsed) else parsed.date()


def _parse_hours(value):
    if not isinstance(value, (int, float)):
        try:
            value = pd.to_numeric(value, errors="coerce")
        except (TypeError, ValueError):
            return None
    return None if pd.isna(value) else float(value)


class _TimebookParser:
    """Построчный разбор выгрузки: в памяти только итог по ключу смены, не сам лист.

    Строки с одним ключом (SHIFT_KEY_COLUMNS) встречаются в разных концах файла и их
    часы складываются, поэтому писать в базу можно только после чтения всего файла.
    Ошибка разбора, таким образом, не оставляет в базе половины файла.
    """

    def __init__(self, columns):
        self.indexes = self._resolve_columns(columns)
        self.collector = _ContactCollector(columns)
        self.groups = {}
        self.rows_seen = 0
        self.skipped_invalid = 0

    @staticmethod
    def _resolve_columns(columns):
        """Колонки смен по ЗАГОЛОВКАМ (fallback — индекс).

        Устойчиво к добавлению/перестановке колонок в отчёте, пока заголовки называются
        по-прежнему. Отсутствие обязательного заголовка — внятная ошибка, не тихий мусор.
        """
        indexes = {}
        matched_by_header = 0
        missing = []
        for field, title, candidates, fallback_index, required in SHIFT_COLUMN_SPECS:
            index, by_header = _resolve_index(columns, candidates, fallback_index)
            matched_by_header += int(by_header)
            if index is None and required:
                missing.append(title)
            indexes[field] = index

        if missing:
            raise ValueError("Не найдена колонка: " + ", ".join(f"«{title}»" for title in missing))

        if matched_by_header == 0:
            # Все колонки пришлось брать по индексу — заголовков нет ни одного.
            # Молча разложить данные по позициям опаснее, чем упасть.
            raise ValueError("Не распознаны заголовки колонок — ожидается строка 2 файла")
        return indexes

    @property
    def contacts(self):
        return self.collector.contacts

    def add_blank_rows(self, count):
        self.rows_seen += count
        self.skipped_invalid += count

    def feed(self, row):
        self.rows_seen += 1
        # Контакты (телефон/ИНН/табельный) — и из строк, негодных как смена.
        self.collector.feed(row)

        indexes = self.indexes
        store = _cell(row, indexes["store"])
        format_value = _cell(row, indexes["format"])
        raw_date = _cell(row, indexes["date"])
        service = _cell(row, indexes["service"])
        employee = _cell(row, indexes["employee"])
        raw_hours = _cell(row, indexes["hours"])
        if any(pd.isna(value) for value in (store, format_value, raw_date, service, employee, raw_hours)):
            self.skipped_invalid += 1
            return

        shift_date = _parse_shift_date(raw_date)
        hours = _parse_hours(raw_hours)
        if shift_date is None or hours is None:
            self.skipped_invalid += 1
            return

        raw_request_type = _cell(row, indexes["request_type"])
        request_type = "" if pd.isna(raw_request_type) else normalize_text(raw_request_type)
        # request_type is part of the business identity: no-plan shifts must stay
        # separate from normal planned shifts for display and payroll.
        key = (
            sys.intern(normalize_text(store)),
            sys.intern(normalize_format(format_value)),
            shift_date,
            sys.intern(normalize_text(service)),
            sys.intern(normalize_text(employee)),
            sys.intern(request_type or DEFAULT_REQUEST_TYPE),
        )
        group = self.groups.get(key)
        if group is None:
            group = self.groups[key] = [0.0, 0.0, ""]
        # Сумма Кэхэна — как у pandas groupby().sum(): иначе повторная загрузка того же файла
        # разойдётся с уже записанными часами на 1e-15 и покажет смену как «обновлённую».
        compensated = hours - group[1]
        total = group[0] + compensated
        group[1] = total - group[0] - compensated
        group[0] = total
        city = normalize_city(_cell(row, indexes["city"]))  # П4.2: без «г.», NaN → пусто
        if city:
            group[2] = sys.intern(city)

    def finish(self):
        if not self.rows_seen:
            raise ValueError("Файл пуст")
        return self


def _xlsx_rows(path):
    workbook = load_workbook(path, read_only=True, data_only=True, keep_links=False)
    try:
        sheet = workbook.worksheets[0]
        # Размер листа в файле бывает неверным (A1) — тогда строки обрезаются.
        sheet.reset_dimensions()
        yield from sheet.iter_rows(values_only=True)
    finally:
        workbook.close()


def _parse_timebook_file(path, heartbeat=None):
    """Разобрать xlsx потоком: лист целиком в память не читается."""
    rows = _xlsx_rows(path)
    try:
        next(rows, None)  # первая строка — агрегаты «Итого:»
        header = next(rows, None)
        if header is None:
            raise ValueError("Файл пуст")
        parser = _TimebookParser(["" if title is None else title for title in header])

        # Пустые строки в хвосте листа — не данные, а в середине считаются пропущенными.
        pending_blank = 0
        for number, row in enumerate(rows, start=1):
            if all(value is None or value == "" for value in row):
                pending_blank += 1
                continue
            if pending_blank:
                parser.add_blank_rows(pending_blank)
                pending_blank = 0
            parser.feed([None if isinstance(value, str) and value in XLSX_NA_VALUES else value for value in row])
            if heartbeat and number % UPLOAD_HEARTBEAT_ROWS == 0:
                heartbeat()
    finally:
        rows.close()
    return parser.finish()


def _parse_timebook_dataframe(df):
    parser = _TimebookParser(list(df.columns))
    for row in df.itertuples(index=False, name=None):
        parser.feed(row)
    return parser.finish()


def _normalize_upload_dataframe(df):
    """Разобранный DataFrame в табличном виде: (смены, пропущено, контакты)."""
    parser = _parse_timebook_dataframe(df)
    rows = pd.DataFrame(
        [(*key, group[0], group[2]) for key, group in sorted(parser.groups.items())],
        columns=SHIFT_KEY_COLUMNS + ["hours", "city"],
    )
    return rows, parser.skipped_invalid, parser.contacts


def _store_shift_batch(session, batch, counters, on_batch):
    """Записать пачку смен одним запросом на чтение и одним коммитом."""
    existing = {
        (shift.store, shift.format, shift.shift_date, shift.service, shift.employee, shift.request_type): shift
        for shift in session.query(Shift).filter(
            tuple_(
                Shift.store, Shift.format, Shift.shift_date, Shift.service, Shift.employee, Shift.request_type
            ).in_([key for key, _hours, _city in batch])
        )
    }
    for key, hours, city in batch:
        shift = existing.get(key)
        if shift:
            row_changed = False

            if float(shift.hours or 0) != hours:
                shift.hours = hours
                row_changed = True

            if (normalize_city(shift.city) or None) != city:
                shift.city = city
                row_changed = True

            if row_changed:
                counters["updated"] += 1
            else:
                counters["skipped_duplicates"] += 1
            continue

        store, format_value, shift_date, service, employee, request_type = key
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
        counters["added"] += 1

    # Счётчики журнала — в той же транзакции: журнал не расходится с записанным.
    if on_batch:
        on_batch(counters)
    session.commit()


def _store_parsed_shifts(session, parser, on_batch=None):
    """Записать смены пачками по UPLOAD_BATCH_SIZE, коммит после каждой пачки."""
    _upsert_timebook_contacts(session, parser.contacts)
    session.commit()

    counters = {
        "added": 0,
        "updated": 0,
        "skipped_duplicates": parser.skipped_invalid,
        "skipped_locked_months": 0,
    }
    empty_city_shifts = 0
    city_from_reference = 0
    today_date = business_today()
    # П4.3: пустой «Город» — из справочника ТК, если город магазина встречается в выгрузках.
    known_cities = timebook_cities(session) | {group[2] for group in parser.groups.values() if group[2]}
    city_by_tk = store_city_by_tk(session, known_cities)

    batch = []
    for key in sorted(parser.groups):
        hours, _compensation, city = parser.groups[key]
        if not _is_editable_month(key[2], today_date):
            counters["skipped_locked_months"] += 1
            continue

        city = city or None  # П4.2: пустой город — NULL, не «nan»
        if city is None:
            city = city_by_tk.get(extract_tk_number(key[0]))
            if city:
                city_from_reference += 1
            else:
                empty_city_shifts += 1

        batch.append((key, hours, city))
        if len(batch) >= UPLOAD_BATCH_SIZE:
            _store_shift_batch(session, batch, counters, on_batch)
            batch = []
    # Последняя пачка, даже пустая: журнал получает итоговые счётчики.
    _store_shift_batch(session, batch, counters, on_batch)

    return {
        **counters,
        "empty_city_shifts": empty_city_shifts,
        "city_from_reference": city_from_reference,
    }


def _after_shifts_stored(session, parser):
    """Пересчёты после записи смен. Только из фоновой обработки: в запросе им не место."""
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
    service_counts = Counter(key[3] for key in parser.groups)
    diagnostics = diagnose_uploaded_services(session, service_counts)

    return {
        "adjustments_created": adjustments_created,
        "unmatched_services": diagnostics["unmatched_services"],
        "services_without_level": diagnostics["services_without_level"],
    }


def _process_shift_dataframe(session, df):
    parser = _parse_timebook_dataframe(df)
    result = _store_parsed_shifts(session, parser)
    result.update(_after_shifts_stored(session, parser))
    return result


def _finish_upload_log(session, request, admin, log, result=None, error=None):
    """Итог обработки в журнал и аудит. Счётчики при ошибке остаются от записанных пачек."""
    log.status = UPLOAD_STATUS_ERROR if error else UPLOAD_STATUS_SUCCESS
    log.error = error
    log.finished_at = now_utc()
    if result:
        log.added = result.get("added", 0)
        log.updated = result.get("updated", 0)
        log.skipped_duplicates = result.get("skipped_duplicates", 0)
        log.skipped_locked_months = result.get("skipped_locked_months", 0)
        log.adjustments_created = result.get("adjustments_created", 0)
        log.summary = result
    session.flush()

    if error:
        create_audit_log(
            session,
            request,
            admin,
            "excel_upload_failed",
            "upload_log",
            log.id,
            log.filename,
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
            log.filename,
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
                log.filename,
                new_value={"adjustments_created": result["adjustments_created"]},
            )

    session.commit()


def _upload_error_text(exc, log):
    if isinstance(exc, ValueError):
        text = str(exc)
    elif isinstance(exc, (BadZipFile, InvalidFileException, ParseError, KeyError)):
        text = "Файл повреждён или не является выгрузкой xlsx."
    elif isinstance(exc, SQLAlchemyError):
        text = "Ошибка записи в базу данных."
    else:
        text = f"Ошибка обработки файла: {exc}"
    written = (log.added or 0) + (log.updated or 0)
    if written:
        # Пачки уже закоммичены; загрузка идемпотентна, поэтому повтор безопасен.
        text += f" Записано смен до ошибки: {written}. Файл можно загрузить повторно."
    return text[:1000]


def _run_upload_job(log_id, path, request_info=None):
    """Фоновая обработка принятого файла: разбор, запись пачками, пересчёты, итог в журнал.

    У фонового потока нет запроса, поэтому сессия своя (а не Depends(get_db)).
    """
    session = SessionLocal()
    try:
        log = session.get(UploadLog, log_id)
        admin = session.get(User, log.uploaded_by) if log.uploaded_by else None

        def heartbeat():
            log.heartbeat_at = now_utc()
            session.commit()

        def on_batch(counters):
            log.added = counters["added"]
            log.updated = counters["updated"]
            log.skipped_duplicates = counters["skipped_duplicates"]
            log.skipped_locked_months = counters["skipped_locked_months"]
            log.heartbeat_at = now_utc()

        try:
            parser = _parse_timebook_file(path, heartbeat)
            result = _store_parsed_shifts(session, parser, on_batch)
            heartbeat()
            result.update(_after_shifts_stored(session, parser))
            _finish_upload_log(session, request_info, admin, log, result=result)
        except Exception as exc:
            logger.exception("Timebook upload %s failed", log_id)
            session.rollback()
            _finish_upload_log(session, request_info, admin, log, error=_upload_error_text(exc, log))
    except Exception:
        # Журнал не записать (база недоступна) — запись снимет _fail_stale_uploads.
        logger.exception("Timebook upload %s: cannot record the outcome", log_id)
        session.rollback()
    finally:
        session.close()
        try:
            os.unlink(path)
        except OSError:
            logger.warning("Timebook upload %s: temp file was not removed", log_id)


# Один поток на процесс: два больших файла разом не должны делить память контейнера.
# Не BackgroundTasks: они живут внутри запроса и его middleware (document_expiry_counter).
_upload_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="timebook-upload")


def _submit_upload_job(log_id, path, request_info):
    _upload_executor.submit(_run_upload_job, log_id, path, request_info)


def _fail_uploads(session, logs, error):
    for log in logs:
        log.status = UPLOAD_STATUS_ERROR
        log.error = error
        log.finished_at = now_utc()
        session.flush()
        create_audit_log(
            session,
            None,
            None,
            "excel_upload_failed",
            "upload_log",
            log.id,
            log.filename,
            new_value={"status": "error", "error": error},
        )
    session.commit()


def _fail_stale_uploads(session):
    """Снять зависшие: поток без отметок дольше UPLOAD_STALE_AFTER уже не работает."""
    _fail_uploads(
        session,
        session.query(UploadLog).filter(
            UploadLog.status == UPLOAD_STATUS_PROCESSING,
            UploadLog.heartbeat_at < now_utc() - UPLOAD_STALE_AFTER,
        ).all(),
        "Обработка зависла и снята по таймауту. Загрузите файл ещё раз.",
    )


def fail_interrupted_uploads(session):
    """На старте процесса: поток прошлого контейнера умер вместе с ним (деплой, OOM).

    Если тот контейнер ещё доживает при выкатке и успел закончить, его итог перезапишет
    эту отметку — итог всегда пишет тот, кто реально обрабатывал файл.
    """
    _fail_uploads(
        session,
        session.query(UploadLog).filter(UploadLog.status == UPLOAD_STATUS_PROCESSING).all(),
        UPLOAD_INTERRUPTED_ERROR,
    )


def _spool_upload(source):
    """Скопировать загрузку во временный файл, не читая её в память. Вернуть (путь, sha256)."""
    digest = hashlib.sha256()
    descriptor, path = tempfile.mkstemp(prefix="timebook-", suffix=".xlsx")
    try:
        with os.fdopen(descriptor, "wb") as target:
            while chunk := source.read(UPLOAD_CHUNK_BYTES):
                digest.update(chunk)
                target.write(chunk)
    except Exception:
        os.unlink(path)
        raise
    return path, digest.hexdigest()


def _upload_status_context(session):
    _fail_stale_uploads(session)
    logs = recent_upload_logs(session)
    return {
        "logs": logs,
        "processing": [log for log in logs if log.status == UPLOAD_STATUS_PROCESSING],
        "last_finished": next((log for log in logs if log.status != UPLOAD_STATUS_PROCESSING), None),
        "status_labels": UPLOAD_STATUS_LABELS,
    }


def _upload_page(request, session, admin, message=None, error=None, status_code=200):
    return templates.TemplateResponse(
        request,
        "admin_upload.html",
        {
            "can_upload": has_permission(admin, "shifts.upload"),
            "upload_locked_hint": UPLOAD_LOCKED_HINT,
            "message": message,
            "error": error,
            **_upload_status_context(session),
        },
        status_code=status_code,
    )


@router.get("/admin/upload", response_class=HTMLResponse)
def admin_upload_page(
    request: Request,
    accepted: bool = False,
    session: Session = Depends(get_db),
    admin=Depends(_require_upload_view),
):
    message = "Файл принят и обрабатывается. Статус обновляется на этой странице сам." if accepted else None
    return _upload_page(request, session, admin, message=message)


@router.get("/admin/upload/status", response_class=HTMLResponse)
def admin_upload_status(
    request: Request,
    session: Session = Depends(get_db),
    admin=Depends(_require_upload_view),
):
    """Фрагмент страницы для автообновления, пока идёт обработка."""
    return templates.TemplateResponse(request, "_upload_status.html", _upload_status_context(session))


@router.get("/admin/upload/auto", response_class=HTMLResponse)
def admin_upload_auto(request: Request, user=Depends(current_user)):
    """Вкладка «Настройка автозагрузки» (П2) — заглушка. Страница открыта всем,
    настройка — только по праву upload.auto (суперадмин)."""
    return templates.TemplateResponse(request, "upload_auto.html", {
        "title": "Настройка автозагрузки",
        "description": "Автоматическая выгрузка смен из timebook.ru по расписанию: "
                       "файл забирается сам и проходит ту же загрузку, что и ручная.",
        "stage": None,
        "back_url": "/admin",
        "can_configure": has_permission(user, "upload.auto"),
    })


@router.post("/admin/upload", response_class=HTMLResponse)
def admin_upload_submit(
    request: Request,
    file: UploadFile = File(...),
    session: Session = Depends(get_db),
    admin=Depends(_require_upload),
):
    """Только принять файл: разбор идёт в фоне, запрос не ждёт его и не упирается в таймаут прокси."""
    if not (file.filename or "").lower().endswith(".xlsx"):
        return _upload_page(request, session, admin, error="Разрешены только .xlsx файлы")

    _fail_stale_uploads(session)
    path, file_hash = _spool_upload(file.file)
    log = UploadLog(
        filename=file.filename,
        uploaded_by=admin.id,
        status=UPLOAD_STATUS_PROCESSING,
        file_hash=file_hash,
        heartbeat_at=now_utc(),
    )
    session.add(log)
    try:
        session.commit()
    except IntegrityError:
        # Частичный уникальный индекс: тот же файл уже в обработке (в том числе в другом воркере).
        session.rollback()
        os.unlink(path)
        running = session.query(UploadLog).filter(
            UploadLog.file_hash == file_hash,
            UploadLog.status == UPLOAD_STATUS_PROCESSING,
        ).first()
        number = f" (загрузка #{running.id})" if running else ""
        return _upload_page(
            request,
            session,
            admin,
            error=f"Этот файл уже обрабатывается{number}. Дождитесь результата — повторно загружать не нужно.",
            status_code=409,
        )

    request_info = SimpleNamespace(
        client=request.client,
        headers={"user-agent": request.headers.get("user-agent")},
    )
    _submit_upload_job(log.id, path, request_info)
    return RedirectResponse("/admin/upload?accepted=1", status_code=303)

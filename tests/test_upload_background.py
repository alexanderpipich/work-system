# -*- coding: utf-8 -*-
"""Загрузка timebook: потоковый разбор, запись пачками, фоновая обработка и журнал."""
import datetime
import io
import os
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

import openpyxl
import pandas as pd
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base
from dependencies import current_user, get_db
from models import AuditLog, Service, Shift, TimebookEmployee, UploadLog, User
from routers import upload as upload_module
from routers.upload import (
    _normalize_upload_dataframe,
    _parse_timebook_file,
    _process_shift_dataframe,
    _run_upload_job,
    fail_interrupted_uploads,
)
from routers.upload import router as upload_router

TODAY = datetime.date(2026, 7, 25)
HEADERS = [
    "Магазин", "Номер ТК", "Формат", "Дивизион", "Город", "Секции", "Типовые секции",
    "Дата", "Поставщик (Исполнитель)", "Тип заявки", "Статус заявки у заказчика",
    "Статус заявки у подрядчика", "Инициатор назначения", "Услуга",
    "ФИО сотрудника Исполнителя", "Табельный номер сотрудника", "Номер телефона",
    "ИНН сотрудника", "Отработано, сотрудники", "Время начала смены (заказ)",
    "Время окончания смены (заказ)", "Время прихода (факт)", "Время ухода (факт)",
    "Время нахождения на объекте, часы", "Обед (перерыв по плану), часы",
    "Обед (перерыв по факту), часы", "ПланФакт минус неоплач. обед, чч:мм",
    "ПланФакт минус неоплач. обед (в числовом формате), часы",
]
COL = {title: index for index, title in enumerate(HEADERS)}
HOURS = HEADERS[-1]


def _row(employee="Иванов", day=1, hours=8, store="Лента-1", service="2ур_Уборка", city="г. Москва", **cells):
    row = [None] * len(HEADERS)
    row[COL["Магазин"]] = store
    row[COL["Формат"]] = "ГМ"
    row[COL["Город"]] = city
    row[COL["Дата"]] = datetime.datetime(2026, 7, day)
    row[COL["Тип заявки"]] = "Основные заказы"
    row[COL["Услуга"]] = service
    row[COL["ФИО сотрудника Исполнителя"]] = employee
    row[COL[HOURS]] = hours
    for title, value in cells.items():
        row[COL[title]] = value
    return row


def _many_rows(count):
    return [_row(employee=f"Сотрудник {i}", day=i % 28 + 1) for i in range(count)]


def _xlsx_bytes(rows, headers=HEADERS):
    workbook = openpyxl.Workbook(write_only=True)
    sheet = workbook.create_sheet()
    sheet.append(["Итого:"])
    sheet.append(headers)
    for row in rows:
        sheet.append(row)
    buffer = io.BytesIO()
    workbook.save(buffer)
    return buffer.getvalue()


def _xlsx_path(test, content):
    descriptor, path = tempfile.mkstemp(suffix=".xlsx")
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)
    test.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
    return path


class _Base(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, autoflush=False)
        session = self.Session()
        session.add(User(id=1, employee_name="Админ", phone="79990000001", password_hash="x", role="superadmin"))
        session.add(Service(name="Уборка", is_active=True))
        session.commit()
        session.close()

        for patcher in (
            patch("routers.upload.SessionLocal", self.Session),
            patch("routers.upload.business_today", return_value=TODAY),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def _log(self, **fields):
        session = self.Session()
        log = UploadLog(filename="t.xlsx", uploaded_by=1, status="processing", file_hash="h", **fields)
        session.add(log)
        session.commit()
        log_id = log.id
        session.close()
        return log_id

    def _get_log(self, log_id):
        session = self.Session()
        self.addCleanup(session.close)
        return session.get(UploadLog, log_id)


class StreamParsingTests(_Base):
    def test_file_gives_same_groups_as_old_dataframe_shape(self):
        """Строки одного ключа в разных концах файла складываются, город — последний непустой."""
        rows = [_row(hours=3), _row(employee="Петров"), _row(hours=2.5, city=None)]
        path = _xlsx_path(self, _xlsx_bytes(rows))
        parser = _parse_timebook_file(path)
        self.assertEqual(parser.skipped_invalid, 0)
        key = ("Лента-1", "ГМ", datetime.date(2026, 7, 1), "2ур_Уборка", "Иванов", "Основные заказы")
        self.assertEqual(parser.groups[key][0], 5.5)
        self.assertEqual(parser.groups[key][2], "Москва")
        self.assertEqual(len(parser.groups), 2)

    def test_na_strings_and_excel_errors_are_empty_cells_as_in_pandas(self):
        rows = [
            _row(employee="NA"),  # read_excel читал это как пропуск
            _row(employee="Иванов", service="#REF!"),
            _row(employee="Петров", hours="не число"),
            _row(employee="Сидоров", **{"Дата": "02.07.2026"}),
        ]
        parser = _parse_timebook_file(_xlsx_path(self, _xlsx_bytes(rows)))
        self.assertEqual(parser.skipped_invalid, 3)
        self.assertEqual([key[4] for key in parser.groups], ["Сидоров"])
        self.assertEqual(list(parser.groups)[0][2], datetime.date(2026, 7, 2))

    def test_blank_rows_counted_inside_but_not_in_the_tail(self):
        rows = [_row(), [None] * len(HEADERS), _row(employee="Петров"), [None] * len(HEADERS), [None] * len(HEADERS)]
        parser = _parse_timebook_file(_xlsx_path(self, _xlsx_bytes(rows)))
        self.assertEqual(parser.skipped_invalid, 1)

    def test_empty_request_type_is_main_orders(self):
        parser = _parse_timebook_file(_xlsx_path(self, _xlsx_bytes([_row(**{"Тип заявки": None})])))
        self.assertEqual(list(parser.groups)[0][5], "Основные заказы")

    def test_file_matches_pandas_read_excel_pipeline(self):
        """Один файл двумя путями чтения — один и тот же итог."""
        rows = [_row(employee="Иванов", hours=8, **{"Табельный номер сотрудника": "12345", "ИНН сотрудника": 780115292688}),
                _row(employee="Петров", hours=None), _row(employee="Иванов", hours=0.1), _row(employee="Иванов", hours=0.2),
                _row(employee="Сидоров", city=None, **{"Номер телефона": 79990050445})]
        content = _xlsx_bytes(rows)
        from_pandas, skipped, contacts = _normalize_upload_dataframe(pd.read_excel(io.BytesIO(content), header=1))
        parser = _parse_timebook_file(_xlsx_path(self, content))
        self.assertEqual(parser.skipped_invalid, skipped)
        self.assertEqual(parser.contacts, contacts)
        self.assertEqual(
            sorted((key, group[0]) for key, group in parser.groups.items()),
            sorted(
                ((r.store, r.format, r.date, r.service, r.employee, r.request_type), r.hours)
                for r in from_pandas.itertuples()
            ),
        )

    def test_sheet_is_not_read_through_pandas(self):
        with patch("pandas.read_excel", side_effect=AssertionError("лист целиком в память")):
            _parse_timebook_file(_xlsx_path(self, _xlsx_bytes([_row()])))

    def test_missing_column_and_empty_file(self):
        with self.assertRaisesRegex(ValueError, "Не найдена колонка"):
            _parse_timebook_file(_xlsx_path(self, _xlsx_bytes([["a"]], headers=["Магазин", "Формат"])))
        with self.assertRaisesRegex(ValueError, "Файл пуст"):
            _parse_timebook_file(_xlsx_path(self, _xlsx_bytes([])))


class BatchWriteTests(_Base):
    ROWS = 3500

    def _run(self, rows):
        log_id = self._log()
        _run_upload_job(log_id, _xlsx_path(self, _xlsx_bytes(rows)))
        return self._get_log(log_id)

    def test_several_thousand_rows_go_in_batches_with_a_commit_each(self):
        commits = []
        selects = []
        event.listen(self.engine, "commit", lambda conn: commits.append(1))
        event.listen(
            self.engine, "before_cursor_execute",
            lambda conn, cursor, statement, *rest: selects.append(statement) if "FROM shifts" in statement else None,
        )

        log = self._run(_many_rows(self.ROWS))

        self.assertEqual(log.status, "success", log.error)
        self.assertEqual(log.added, self.ROWS)
        session = self.Session()
        self.addCleanup(session.close)
        self.assertEqual(session.query(Shift).count(), self.ROWS)

        batches = self.ROWS // upload_module.UPLOAD_BATCH_SIZE
        self.assertGreaterEqual(len(commits), batches)
        # Поиск существующих смен — запрос на пачку, а не на строку.
        lookups = [s for s in selects if " IN " in s]
        self.assertLessEqual(len(lookups), batches + 1)

    def test_commit_after_each_batch_keeps_journal_in_step(self):
        seen = []
        original = upload_module._store_shift_batch

        def spy(session, batch, counters, on_batch):
            original(session, batch, counters, on_batch)
            check = self.Session()
            seen.append((len(batch), check.query(Shift).count(), check.query(UploadLog).first().added))
            check.close()

        with patch("routers.upload._store_shift_batch", spy):
            self._run(_many_rows(1200))

        self.assertEqual([size for size, *_ in seen], [500, 500, 200])
        self.assertEqual([(count, added) for _size, count, added in seen], [(500, 500), (1000, 1000), (1200, 1200)])

    def test_reupload_is_idempotent_and_hours_are_updated(self):
        rows = _many_rows(700)
        self.assertEqual(self._run(rows).added, 700)
        again = self._run(rows)
        self.assertEqual((again.added, again.updated, again.skipped_duplicates), (0, 0, 700))
        rows[0][COL[HOURS]] = 11
        changed = self._run(rows)
        self.assertEqual((changed.added, changed.updated, changed.skipped_duplicates), (0, 1, 699))

    def test_same_key_across_batches_is_summed_not_overwritten(self):
        rows = [_row(hours=3)] + _many_rows(1100) + [_row(hours=4)]
        self._run(rows)
        session = self.Session()
        self.addCleanup(session.close)
        shift = session.query(Shift).filter(Shift.employee == "Иванов").one()
        self.assertEqual(shift.hours, 7)

    def test_dataframe_entry_point_still_commits_everything(self):
        session = self.Session()
        self.addCleanup(session.close)
        df = pd.DataFrame([_row(), _row(employee="Петров")], columns=HEADERS)
        result = _process_shift_dataframe(session, df)
        self.assertEqual(result["added"], 2)
        self.assertEqual(self.Session().query(Shift).count(), 2)


class JobStatusTests(_Base):
    def test_processing_to_success_with_correct_counters_and_summary(self):
        session = self.Session()
        session.add(Shift(store="Лента-1", format="ГМ", city="Москва", shift_date=datetime.date(2026, 7, 2),
                          service="2ур_Уборка", employee="Иванов", hours=5, request_type="Основные заказы"))
        session.add(Shift(store="Лента-1", format="ГМ", city="Москва", shift_date=datetime.date(2026, 7, 3),
                          service="2ур_Уборка", employee="Иванов", hours=8, request_type="Основные заказы"))
        session.commit()
        session.close()

        rows = [
            _row(day=1),  # новая
            _row(day=2),  # часы 5 → 8
            _row(day=3),  # без изменений
            _row(day=4, service="3ур_НетТакой", employee="Петров"),  # новая, без ЧТС
            _row(employee=None),  # негодная
            [*_row()[:COL["Дата"]], datetime.datetime(2020, 1, 1), *_row()[COL["Дата"] + 1:]],  # закрытый месяц
        ]
        log_id = self._log()
        self.assertEqual(self._get_log(log_id).status, "processing")
        path = _xlsx_path(self, _xlsx_bytes(rows))

        _run_upload_job(log_id, path)

        log = self._get_log(log_id)
        self.assertEqual(log.status, "success", log.error)
        self.assertEqual((log.added, log.updated, log.skipped_duplicates, log.skipped_locked_months), (2, 1, 2, 1))
        self.assertEqual(
            log.summary["unmatched_services"], [{"name": "3ур_НетТакой", "shifts_count": 1}]
        )
        self.assertIsNotNone(log.finished_at)
        self.assertFalse(os.path.exists(path), "временный файл должен быть удалён")
        check = self.Session()
        self.addCleanup(check.close)
        self.assertEqual(check.query(AuditLog).filter(AuditLog.action == "excel_uploaded").count(), 1)

    def test_parse_error_gives_error_status_with_text(self):
        for content, expected in (
            (_xlsx_bytes([["a"]], headers=["Магазин"]), "Не найдена колонка"),
            (b"this is not a zip", "Файл повреждён"),
        ):
            with self.subTest(expected):
                session = self.Session()
                session.query(UploadLog).delete()
                session.commit()
                session.close()
                log_id = self._log()
                path = _xlsx_path(self, content)
                _run_upload_job(log_id, path)
                log = self._get_log(log_id)
                self.assertEqual(log.status, "error")
                self.assertIn(expected, log.error)
                self.assertEqual(log.added, 0)
                self.assertFalse(os.path.exists(path))

    def test_failure_mid_way_reports_written_batches_and_can_be_retried(self):
        original = upload_module._store_shift_batch
        calls = []

        def fail_second(session, batch, counters, on_batch):
            calls.append(1)
            if len(calls) == 2:
                raise RuntimeError("обрыв соединения")
            original(session, batch, counters, on_batch)

        rows = _many_rows(1200)
        path = _xlsx_path(self, _xlsx_bytes(rows))
        log_id = self._log()
        with patch("routers.upload._store_shift_batch", fail_second):
            _run_upload_job(log_id, path)
        log = self._get_log(log_id)
        self.assertEqual(log.status, "error")
        self.assertEqual(log.added, 500)
        self.assertIn("обрыв соединения", log.error)
        self.assertIn("Записано смен до ошибки: 500", log.error)

        retry_id = self._log_retry()
        _run_upload_job(retry_id, _xlsx_path(self, _xlsx_bytes(rows)))
        retry = self._get_log(retry_id)
        self.assertEqual((retry.status, retry.added, retry.skipped_duplicates), ("success", 700, 500))

    def _log_retry(self):
        session = self.Session()
        log = UploadLog(filename="t.xlsx", uploaded_by=1, status="processing", file_hash="retry")
        session.add(log)
        session.commit()
        log_id = log.id
        session.close()
        return log_id

    def test_heavy_recalculations_run_in_the_job_not_before_status(self):
        with patch("routers.upload.reconcile_sent_payroll_runs", return_value=3) as reconcile:
            log_id = self._log()
            _run_upload_job(log_id, _xlsx_path(self, _xlsx_bytes([_row()])))
        reconcile.assert_called_once()
        self.assertEqual(self._get_log(log_id).adjustments_created, 3)

    def test_restart_marks_interrupted_and_frees_the_file(self):
        log_id = self._log()
        session = self.Session()
        self.addCleanup(session.close)
        fail_interrupted_uploads(session)
        log = self._get_log(log_id)
        self.assertEqual(log.status, "error")
        self.assertIn("перезапуск", log.error)

    def test_stale_job_times_out(self):
        fresh = self._log(heartbeat_at=upload_module.now_utc())
        session = self.Session()
        session.get(UploadLog, fresh).file_hash = "fresh"
        session.commit()
        stale = self._log(heartbeat_at=upload_module.now_utc() - upload_module.UPLOAD_STALE_AFTER * 2)
        upload_module._fail_stale_uploads(session)
        session.close()
        self.assertEqual(self._get_log(fresh).status, "processing")
        self.assertEqual(self._get_log(stale).status, "error")


class UploadRouteTests(_Base):
    def setUp(self):
        super().setUp()
        app = FastAPI()
        app.include_router(upload_router)

        def override_db():
            db = self.Session()
            try:
                yield db
            finally:
                db.close()

        def override_user():
            db = self.Session()
            user = db.get(User, 1)
            db.close()
            return user

        app.dependency_overrides[get_db] = override_db
        app.dependency_overrides[current_user] = override_user
        self.client = TestClient(app)

        # Очередь вместо потока: тест сам решает, когда обработка «идёт», а когда закончилась.
        self.jobs = []
        self.submit_patcher = patch("routers.upload._submit_upload_job", lambda *args: self.jobs.append(args))
        self.submit_patcher.start()
        self.addCleanup(self._drop_spooled)
        self.addCleanup(patch.stopall)

    def _drop_spooled(self):
        for _log_id, path, _info in self.jobs:
            if os.path.exists(path):
                os.unlink(path)

    def _post(self, content, name="t.xlsx"):
        return self.client.post("/admin/upload", files={"file": (name, content)}, follow_redirects=False)

    def test_post_answers_at_once_and_only_records_processing(self):
        response = self._post(_xlsx_bytes(_many_rows(50)))
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/admin/upload?accepted=1")

        session = self.Session()
        self.addCleanup(session.close)
        self.assertEqual(session.query(Shift).count(), 0, "в запросе смены не пишутся")
        log = session.query(UploadLog).one()
        self.assertEqual(log.status, "processing")
        self.assertEqual(len(log.file_hash), 64)
        self.assertEqual(len(self.jobs), 1)
        self.assertTrue(os.path.exists(self.jobs[0][1]))

        page = self.client.get("/admin/upload?accepted=1")
        self.assertIn("Файл принят", page.text)
        self.assertIn("в обработке", page.text)
        self.assertIn('data-processing="1"', page.text)

    def test_status_fragment_follows_the_job_to_done(self):
        self._post(_xlsx_bytes([_row(), _row(employee="Петров", service="3ур_НетТакой")]))
        fragment = self.client.get("/admin/upload/status")
        self.assertEqual(fragment.status_code, 200)
        self.assertNotIn("<html", fragment.text)
        self.assertIn('data-processing="1"', fragment.text)

        _run_upload_job(*self.jobs[0])

        fragment = self.client.get("/admin/upload/status").text
        self.assertIn('data-processing="0"', fragment)
        self.assertIn("готово", fragment)
        self.assertIn("Результат загрузки", fragment)
        self.assertIn("3ур_НетТакой", fragment)

    def test_status_fragment_shows_parse_error_text_not_502(self):
        response = self._post(_xlsx_bytes([["x"]], headers=["Магазин"]))
        self.assertEqual(response.status_code, 303)
        _run_upload_job(*self.jobs[0])
        fragment = self.client.get("/admin/upload/status")
        self.assertEqual(fragment.status_code, 200)
        self.assertIn("ошибка", fragment.text)
        self.assertIn("Не найдена колонка", fragment.text)

    def test_same_file_rejected_while_processing_then_allowed(self):
        content = _xlsx_bytes([_row()])
        self.assertEqual(self._post(content).status_code, 303)

        # То же содержимое под другим именем — тот же файл.
        repeat = self._post(content, name="копия.xlsx")
        self.assertEqual(repeat.status_code, 409)
        self.assertIn("Этот файл уже обрабатывается", repeat.text)
        self.assertEqual(len(self.jobs), 1)
        session = self.Session()
        self.assertEqual(session.query(UploadLog).count(), 1)
        session.close()

        _run_upload_job(*self.jobs[0])
        self.assertEqual(self._post(content).status_code, 303)
        self.assertEqual(len(self.jobs), 2)

    def test_other_file_is_accepted_while_first_is_processing(self):
        self.assertEqual(self._post(_xlsx_bytes([_row()])).status_code, 303)
        self.assertEqual(self._post(_xlsx_bytes([_row(employee="Петров")])).status_code, 303)
        self.assertEqual(len(self.jobs), 2)

    def test_not_xlsx_rejected_without_job(self):
        response = self._post(b"x", name="t.csv")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Разрешены только .xlsx", response.text)
        self.assertEqual(self.jobs, [])

    def test_real_thread_runs_the_job(self):
        """Настоящий исполнитель: POST возвращается, поток доводит журнал до «готово»."""
        self.submit_patcher.stop()
        self._post(_xlsx_bytes(_many_rows(20)))
        upload_module._upload_executor.submit(lambda: None).result(timeout=30)
        session = self.Session()
        self.addCleanup(session.close)
        log = session.query(UploadLog).one()
        self.assertEqual((log.status, log.added), ("success", 20), log.error)


if __name__ == "__main__":
    unittest.main()

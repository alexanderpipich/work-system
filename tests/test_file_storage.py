"""Тесты хранилища файлов: локальный бэкенд, выбор бэкенда, S3 через заглушку."""

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

import file_storage
from file_storage import (
    is_legacy_path,
    normalize_key,
    reset_client_cache,
    storage_backend,
    storage_delete,
    storage_exists,
    storage_save,
    storage_stream,
)


S3_ENV = ("S3_BUCKET", "S3_ACCESS_KEY", "S3_SECRET_KEY", "S3_ENDPOINT", "S3_REGION")


class _EnvMixin:
    """Изолирует тест от окружения разработчика (у него S3 может быть настроен)."""

    def setUp(self):
        self._saved = {name: os.environ.get(name) for name in
                       S3_ENV + ("DOCUMENT_UPLOAD_ROOT", "GENERATED_FILES_ROOT")}
        for name in S3_ENV:
            os.environ.pop(name, None)
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        os.environ["DOCUMENT_UPLOAD_ROOT"] = str(self.root / "uploaded_documents")
        os.environ["GENERATED_FILES_ROOT"] = str(self.root / "generated_files")
        reset_client_cache()

    def tearDown(self):
        self._tmp.cleanup()
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        reset_client_cache()

    def _enable_s3(self):
        os.environ["S3_BUCKET"] = "test-bucket"
        os.environ["S3_ACCESS_KEY"] = "key"
        os.environ["S3_SECRET_KEY"] = "secret"
        os.environ["S3_ENDPOINT"] = "https://s3.example.test"
        os.environ["S3_REGION"] = "ru-1"
        reset_client_cache()


class KeyNormalizationTests(unittest.TestCase):
    def test_strips_slashes_and_backslashes(self):
        self.assertEqual(normalize_key("/uploaded_documents\\qr\\a.png"), "uploaded_documents/qr/a.png")

    def test_rejects_traversal_and_empty(self):
        for bad in ("", "   ", "uploaded_documents/../../etc/passwd"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    normalize_key(bad)

    def test_legacy_paths_detected(self):
        for value in ("/data/uploaded_documents/a.png", "/app/uploaded_documents/a.png", r"C:\tmp\a.png"):
            with self.subTest(value=value):
                self.assertTrue(is_legacy_path(value))
        self.assertFalse(is_legacy_path("uploaded_documents/qr/a.png"))


class BackendSelectionTests(_EnvMixin, unittest.TestCase):
    def test_local_without_s3_env(self):
        self.assertEqual(storage_backend(), "local")

    def test_s3_when_bucket_and_keys_set(self):
        self._enable_s3()
        self.assertEqual(storage_backend(), "s3")

    def test_partial_s3_env_stays_local(self):
        os.environ["S3_BUCKET"] = "test-bucket"  # без ключей — не S3
        self.assertEqual(storage_backend(), "local")


class LocalBackendTests(_EnvMixin, unittest.TestCase):
    def test_save_returns_key_and_writes_under_root(self):
        key = storage_save("uploaded_documents/qr/qr_1.png", b"binary", content_type="image/png")
        self.assertEqual(key, "uploaded_documents/qr/qr_1.png")
        self.assertTrue((self.root / "uploaded_documents" / "qr" / "qr_1.png").is_file())

    def test_generated_files_go_under_own_root(self):
        key = storage_save("generated_files/planning_forms/f.xlsx", b"xlsx")
        self.assertTrue((self.root / "generated_files" / "planning_forms" / "f.xlsx").is_file())
        self.assertEqual(key, "generated_files/planning_forms/f.xlsx")

    def test_exists_and_delete(self):
        storage_save("uploaded_documents/qr/qr_2.png", b"x")
        self.assertTrue(storage_exists("uploaded_documents/qr/qr_2.png"))
        storage_delete("uploaded_documents/qr/qr_2.png")
        self.assertFalse(storage_exists("uploaded_documents/qr/qr_2.png"))
        storage_delete("uploaded_documents/qr/qr_2.png")  # повторное удаление — не ошибка

    def test_exists_false_for_empty_and_missing(self):
        self.assertFalse(storage_exists(None))
        self.assertFalse(storage_exists(""))
        self.assertFalse(storage_exists("uploaded_documents/qr/нет.png"))

    def test_stream_returns_content_and_size(self):
        storage_save("uploaded_documents/employee_documents/7/паспорт.pdf", b"%PDF-1.4 data")
        stored = storage_stream("uploaded_documents/employee_documents/7/паспорт.pdf")
        self.assertIsNotNone(stored)
        self.assertEqual(stored.read(), b"%PDF-1.4 data")
        self.assertEqual(stored.size, len(b"%PDF-1.4 data"))
        self.assertEqual(stored.content_type, "application/pdf")

    def test_stream_none_for_missing(self):
        self.assertIsNone(storage_stream("uploaded_documents/qr/нет.png"))

    def test_legacy_absolute_path_read_from_disk_in_local_mode(self):
        legacy = self.root / "legacy.png"
        legacy.write_bytes(b"old")
        self.assertTrue(storage_exists(str(legacy)))


class S3LegacyPathTests(_EnvMixin, unittest.TestCase):
    """В S3-режиме исторические абсолютные пути — заведомо отсутствующие файлы."""

    def setUp(self):
        super().setUp()
        self._enable_s3()

    def test_exists_false_without_network_call(self):
        for value in ("/data/uploaded_documents/a.png", "/app/uploaded_documents/a.png"):
            with self.subTest(value=value):
                self.assertFalse(storage_exists(value))
                self.assertIsNone(storage_stream(value))
        storage_delete("/data/uploaded_documents/a.png")  # не падает и не ходит в сеть


class _StubBody:
    def __init__(self, data):
        self._data = data

    def iter_chunks(self, chunk_size=None):
        yield self._data


class _StubS3Client:
    """Минимальный in-memory двойник boto3-клиента S3."""

    def __init__(self):
        self.objects = {}
        self.calls = []

    def put_object(self, Bucket, Key, Body, ContentType=None):
        self.calls.append(("put", Bucket, Key, ContentType))
        self.objects[Key] = Body

    def head_object(self, Bucket, Key):
        if Key not in self.objects:
            raise RuntimeError("404")
        return {"ContentLength": len(self.objects[Key])}

    def get_object(self, Bucket, Key):
        if Key not in self.objects:
            raise RuntimeError("404")
        data = self.objects[Key]
        return {"Body": _StubBody(data), "ContentLength": len(data), "ContentType": "image/png"}

    def delete_object(self, Bucket, Key):
        self.objects.pop(Key, None)


class S3BackendTests(_EnvMixin, unittest.TestCase):
    """S3-бэкенд на подменённом клиенте — без сетевых вызовов."""

    def setUp(self):
        super().setUp()
        self._enable_s3()
        self.stub = _StubS3Client()
        self._real_client = file_storage._client
        file_storage._client = lambda: (self.stub, "test-bucket")

    def tearDown(self):
        file_storage._client = self._real_client
        super().tearDown()

    def test_save_puts_object_with_content_type(self):
        key = storage_save("uploaded_documents/qr/qr_1.png", b"png-bytes", content_type="image/png")
        self.assertEqual(key, "uploaded_documents/qr/qr_1.png")
        self.assertEqual(self.stub.objects["uploaded_documents/qr/qr_1.png"], b"png-bytes")
        self.assertEqual(self.stub.calls[0][3], "image/png")

    def test_content_type_guessed_when_not_given(self):
        storage_save("generated_files/planning_forms/bp.pdf", b"%PDF")
        self.assertEqual(self.stub.calls[0][3], "application/pdf")

    def test_exists_delete_and_stream(self):
        storage_save("uploaded_documents/qr/qr_1.png", b"png-bytes", content_type="image/png")
        self.assertTrue(storage_exists("uploaded_documents/qr/qr_1.png"))

        stored = storage_stream("uploaded_documents/qr/qr_1.png")
        self.assertEqual(stored.read(), b"png-bytes")
        self.assertEqual(stored.size, len(b"png-bytes"))
        self.assertEqual(stored.content_type, "image/png")

        storage_delete("uploaded_documents/qr/qr_1.png")
        self.assertFalse(storage_exists("uploaded_documents/qr/qr_1.png"))
        self.assertIsNone(storage_stream("uploaded_documents/qr/qr_1.png"))

    def test_nothing_written_to_local_disk(self):
        storage_save("uploaded_documents/qr/qr_1.png", b"png-bytes")
        self.assertFalse((self.root / "uploaded_documents").exists())


class StorageResponseTests(_EnvMixin, unittest.TestCase):
    def test_cyrillic_filename_encoded(self):
        from file_storage import storage_response

        storage_save("uploaded_documents/employee_documents/7/doc.pdf", b"%PDF")
        response = storage_response(
            "uploaded_documents/employee_documents/7/doc.pdf",
            filename="Паспорт РФ.pdf",
            disposition="attachment",
        )
        disposition = response.headers["content-disposition"]
        self.assertTrue(disposition.startswith("attachment; filename*=UTF-8''"))
        self.assertNotIn("Паспорт", disposition)  # только percent-encoding, без сырой кириллицы
        self.assertIn("%D0%9F", disposition)
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertEqual(response.media_type, "application/pdf")

    def test_none_for_missing_object(self):
        from file_storage import storage_response

        self.assertIsNone(storage_response("uploaded_documents/нет.pdf", filename="нет.pdf"))


if __name__ == "__main__":
    unittest.main()

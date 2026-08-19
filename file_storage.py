"""Единая точка работы с файлами приложения.

Бэкенд выбирается по окружению:
  * задан ``S3_BUCKET`` вместе с ключами доступа — S3-совместимое объектное
    хранилище Timeweb (boto3, endpoint из ``S3_ENDPOINT``);
  * иначе — локальный диск (dev и тесты): запись под ``DOCUMENT_UPLOAD_ROOT``
    и ``GENERATED_FILES_ROOT``, ровно как до переезда.

В БД (колонки ``file_path`` / ``image_path`` / ``sample_image_path``) лежит ключ
объекта вида ``uploaded_documents/<папка>/<файл>`` или
``generated_files/planning_forms/<файл>``. Ключ одинаков для обоих бэкендов, поэтому
схема БД не меняется: локально первый сегмент ключа подменяется на
соответствующий корень с диска.

Исторические записи с абсолютными путями (``/data/...`` с Render, ``/app/...``
с первого деплоя на Timeweb) в S3-режиме считаются отсутствующими: файлы
физически утрачены при переезде. Локальный бэкенд такие пути по-прежнему читает
с диска, чтобы не ломать разработку на старой базе.
"""

import mimetypes
import os
from pathlib import Path, PurePosixPath


# Корни локального бэкенда. Читаются из окружения при каждом обращении, чтобы
# тесты могли подменить их через monkeypatch без перезагрузки модуля.
_LOCAL_ROOTS = {
    "uploaded_documents": ("DOCUMENT_UPLOAD_ROOT", "uploaded_documents"),
    "generated_files": ("GENERATED_FILES_ROOT", "generated_files"),
}

# Сохранено для обратной совместимости импортов (document_helpers).
DOCUMENT_UPLOAD_ROOT = Path(os.getenv("DOCUMENT_UPLOAD_ROOT", "uploaded_documents"))
GENERATED_FILES_ROOT = Path(os.getenv("GENERATED_FILES_ROOT", "generated_files"))

# Типы, которые не угадывает mimetypes, либо которые сознательно отдаём как поток.
_EXTRA_CONTENT_TYPES = {
    ".heic": "application/octet-stream",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}

DEFAULT_CONTENT_TYPE = "application/octet-stream"
_CHUNK_SIZE = 64 * 1024

_s3_client = None
_s3_client_config = None


class StoredFile:
    """Готовый к отдаче объект хранилища: поток байтов, размер и content-type."""

    def __init__(self, chunks, size=None, content_type=None):
        self.chunks = chunks
        self.size = size
        self.content_type = content_type or DEFAULT_CONTENT_TYPE

    def __iter__(self):
        return iter(self.chunks)

    def read(self):
        return b"".join(self.chunks)


def guess_content_type(key):
    suffix = PurePosixPath(str(key or "")).suffix.lower()
    if suffix in _EXTRA_CONTENT_TYPES:
        return _EXTRA_CONTENT_TYPES[suffix]
    return mimetypes.guess_type(f"x{suffix}")[0] or DEFAULT_CONTENT_TYPE


def s3_settings():
    """Настройки S3 из окружения; None, если бэкенд не сконфигурирован."""
    bucket = (os.getenv("S3_BUCKET") or "").strip()
    access_key = (os.getenv("S3_ACCESS_KEY") or "").strip()
    secret_key = (os.getenv("S3_SECRET_KEY") or "").strip()
    if not (bucket and access_key and secret_key):
        return None
    return {
        "bucket": bucket,
        "endpoint_url": (os.getenv("S3_ENDPOINT") or "").strip() or None,
        "region_name": (os.getenv("S3_REGION") or "").strip() or None,
        "aws_access_key_id": access_key,
        "aws_secret_access_key": secret_key,
    }


def storage_backend():
    """``"s3"`` или ``"local"`` — что используется прямо сейчас."""
    return "s3" if s3_settings() else "local"


def _client():
    """Клиент boto3 — один на процесс, пересоздаётся при смене настроек."""
    global _s3_client, _s3_client_config

    settings = s3_settings()
    if not settings:
        raise RuntimeError("S3 backend is not configured")

    if _s3_client is not None and _s3_client_config == settings:
        return _s3_client, settings["bucket"]

    import boto3
    from botocore.config import Config

    _s3_client = boto3.client(
        "s3",
        endpoint_url=settings["endpoint_url"],
        region_name=settings["region_name"],
        aws_access_key_id=settings["aws_access_key_id"],
        aws_secret_access_key=settings["aws_secret_access_key"],
        # Недоступность хранилища не должна вешать воркер.
        config=Config(connect_timeout=5, read_timeout=30, retries={"max_attempts": 2}),
    )
    _s3_client_config = settings
    return _s3_client, settings["bucket"]


def reset_client_cache():
    """Сбросить кэш клиента (нужно тестам при подмене окружения)."""
    global _s3_client, _s3_client_config
    _s3_client = None
    _s3_client_config = None


def is_legacy_path(key):
    """Абсолютный путь из старой инфраструктуры (Render `/data`, Timeweb `/app`)."""
    value = str(key or "")
    if not value:
        return False
    if value.startswith(("/", "\\")):
        return True
    return len(value) > 1 and value[1] == ":"  # C:\... — записи с dev-машины


def normalize_key(key):
    """Ключ объекта в POSIX-виде без ведущих слэшей и без `..`."""
    value = str(key or "").replace("\\", "/").strip().strip("/")
    if not value:
        raise ValueError("Пустой ключ хранилища")
    parts = [part for part in value.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise ValueError("Недопустимый ключ хранилища")
    return "/".join(parts)


def _local_path(key):
    """Путь на диске для ключа. Абсолютные (исторические) пути отдаются как есть."""
    value = str(key or "")
    if is_legacy_path(value):
        return Path(value)

    normalized = normalize_key(value)
    head, _, tail = normalized.partition("/")
    if head in _LOCAL_ROOTS and tail:
        env_name, default = _LOCAL_ROOTS[head]
        return Path(os.getenv(env_name, default)) / tail
    return Path(normalized)


def _local_chunks(path):
    def generate():
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(_CHUNK_SIZE)
                if not chunk:
                    break
                yield chunk

    return generate()


def storage_save(key, content, content_type=None):
    """Сохранить байты по ключу. Возвращает ключ — его и пишем в БД."""
    normalized = normalize_key(key)
    content_type = content_type or guess_content_type(normalized)

    if storage_backend() == "s3":
        client, bucket = _client()
        client.put_object(
            Bucket=bucket,
            Key=normalized,
            Body=content,
            ContentType=content_type,
        )
        return normalized

    path = _local_path(normalized)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return normalized


def storage_exists(key):
    if not key:
        return False

    if storage_backend() == "s3":
        # Файлы со старых абсолютных путей утрачены при переезде.
        if is_legacy_path(key):
            return False
        try:
            normalized = normalize_key(key)
        except ValueError:
            return False
        client, bucket = _client()
        try:
            client.head_object(Bucket=bucket, Key=normalized)
        except Exception:
            return False
        return True

    try:
        return _local_path(key).is_file()
    except (ValueError, OSError):
        return False


def storage_delete(key):
    """Удалить объект. Отсутствующий объект — не ошибка."""
    if not key:
        return

    if storage_backend() == "s3":
        if is_legacy_path(key):
            return
        try:
            normalized = normalize_key(key)
        except ValueError:
            return
        client, bucket = _client()
        try:
            client.delete_object(Bucket=bucket, Key=normalized)
        except Exception:
            pass
        return

    try:
        _local_path(key).unlink(missing_ok=True)
    except (ValueError, OSError):
        pass


def storage_stream(key):
    """``StoredFile`` для отдачи клиенту либо None, если объекта нет."""
    if not key:
        return None

    if storage_backend() == "s3":
        if is_legacy_path(key):
            return None
        try:
            normalized = normalize_key(key)
        except ValueError:
            return None
        client, bucket = _client()
        try:
            response = client.get_object(Bucket=bucket, Key=normalized)
        except Exception:
            return None
        body = response["Body"]
        chunks = body.iter_chunks(_CHUNK_SIZE) if hasattr(body, "iter_chunks") else iter([body.read()])
        return StoredFile(
            chunks,
            size=response.get("ContentLength"),
            content_type=response.get("ContentType") or guess_content_type(normalized),
        )

    try:
        path = _local_path(key)
        if not path.is_file():
            return None
        size = path.stat().st_size
    except (ValueError, OSError):
        return None
    return StoredFile(_local_chunks(path), size=size, content_type=guess_content_type(key))


def storage_response(
    key,
    *,
    filename=None,
    media_type=None,
    disposition="attachment",
    extra_headers=None,
):
    """StreamingResponse с корректным Content-Disposition; None — объекта нет.

    Имена файлов кириллические, поэтому только ``filename*=UTF-8''`` (RFC 5987).
    """
    from urllib.parse import quote

    from fastapi.responses import StreamingResponse

    stored = storage_stream(key)
    if stored is None:
        return None

    safe_name = Path(str(filename or key)).name.replace('"', "") or "file"
    headers = {
        "Content-Disposition": f"{disposition}; filename*=UTF-8''{quote(safe_name)}",
        "X-Content-Type-Options": "nosniff",
    }
    if stored.size is not None:
        headers["Content-Length"] = str(stored.size)
    if extra_headers:
        headers.update(extra_headers)

    return StreamingResponse(
        stored,
        media_type=media_type or stored.content_type,
        headers=headers,
    )

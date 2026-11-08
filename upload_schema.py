from sqlalchemy import text

from database import engine


def ensure_upload_log_columns():
    """Идемпотентно добавить колонки фоновой обработки загрузок на старую `upload_logs`.

    Индекс тоже здесь: create_all не добавляет индексы к существующей таблице.
    """
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE upload_logs ADD COLUMN IF NOT EXISTS file_hash VARCHAR"))
        connection.execute(text("ALTER TABLE upload_logs ADD COLUMN IF NOT EXISTS heartbeat_at TIMESTAMP"))
        connection.execute(text("ALTER TABLE upload_logs ADD COLUMN IF NOT EXISTS finished_at TIMESTAMP"))
        connection.execute(text("ALTER TABLE upload_logs ADD COLUMN IF NOT EXISTS summary JSON"))
        connection.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_upload_logs_processing_hash "
            "ON upload_logs (file_hash) WHERE status = 'processing'"
        ))

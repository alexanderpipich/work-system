from sqlalchemy import text

from database import engine


def ensure_shift_request_type_unique_key():
    with engine.begin() as connection:
        connection.execute(text(
            "ALTER TABLE shifts ADD COLUMN IF NOT EXISTS city VARCHAR"
        ))
        connection.execute(text(
            "ALTER TABLE shifts ADD COLUMN IF NOT EXISTS request_type VARCHAR"
        ))
        connection.execute(text("ALTER TABLE shifts DROP CONSTRAINT IF EXISTS uq_shift_row"))
        connection.execute(text("DROP INDEX IF EXISTS uq_shift_row"))
        connection.execute(text("DROP INDEX IF EXISTS uq_shift_row_request_type"))
        connection.execute(text("""
            CREATE UNIQUE INDEX IF NOT EXISTS uq_shift_row_request_type
            ON shifts (store, format, shift_date, service, employee, COALESCE(request_type, ''))
        """))

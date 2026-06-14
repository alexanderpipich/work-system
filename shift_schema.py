from sqlalchemy import text

from database import engine


DEFAULT_REQUEST_TYPE = "Основные заказы"


def ensure_shift_request_type_unique_key():
    with engine.begin() as connection:
        connection.execute(text(
            "ALTER TABLE shifts ADD COLUMN IF NOT EXISTS city VARCHAR"
        ))
        connection.execute(text(
            f"""
            ALTER TABLE shifts
            ADD COLUMN IF NOT EXISTS request_type VARCHAR
            DEFAULT '{DEFAULT_REQUEST_TYPE}'
            """
        ))
        connection.execute(text(
            f"""
            UPDATE shifts
            SET request_type = '{DEFAULT_REQUEST_TYPE}'
            WHERE request_type IS NULL OR BTRIM(request_type) = ''
            """
        ))
        connection.execute(text(
            """
            UPDATE shifts
            SET request_type = BTRIM(request_type)
            WHERE request_type <> BTRIM(request_type)
            """
        ))
        connection.execute(text(
            f"""
            ALTER TABLE shifts
            ALTER COLUMN request_type SET DEFAULT '{DEFAULT_REQUEST_TYPE}'
            """
        ))
        connection.execute(text(
            "ALTER TABLE shifts ALTER COLUMN request_type SET NOT NULL"
        ))
        connection.execute(text(
            "ALTER TABLE shifts DROP CONSTRAINT IF EXISTS ck_shift_request_type_not_blank"
        ))
        connection.execute(text(
            """
            ALTER TABLE shifts
            ADD CONSTRAINT ck_shift_request_type_not_blank
            CHECK (BTRIM(request_type) <> '')
            """
        ))
        connection.execute(text("ALTER TABLE shifts DROP CONSTRAINT IF EXISTS uq_shift_row"))
        connection.execute(text("DROP INDEX IF EXISTS uq_shift_row"))
        connection.execute(text("DROP INDEX IF EXISTS uq_shift_row_request_type"))
        connection.execute(text("""
            CREATE UNIQUE INDEX IF NOT EXISTS uq_shift_row_request_type
            ON shifts (store, format, shift_date, service, employee, BTRIM(request_type))
        """))

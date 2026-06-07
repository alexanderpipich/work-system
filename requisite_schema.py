from sqlalchemy import text

from database import engine


def ensure_requisite_profile_columns():
    with engine.begin() as connection:
        connection.execute(text(
            "ALTER TABLE requisites ADD COLUMN IF NOT EXISTS is_third_party BOOLEAN DEFAULT FALSE"
        ))
        connection.execute(text(
            "ALTER TABLE requisites ADD COLUMN IF NOT EXISTS recipient_name VARCHAR"
        ))
        connection.execute(text(
            "ALTER TABLE requisites ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE"
        ))
        connection.execute(text(
            "ALTER TABLE requisites ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE"
        ))
        connection.execute(text(
            "ALTER TABLE requisites ADD COLUMN IF NOT EXISTS created_at TIMESTAMP"
        ))
        connection.execute(text(
            "ALTER TABLE requisites ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP"
        ))
        connection.execute(text(
            "ALTER TABLE requisites ADD COLUMN IF NOT EXISTS verified_at TIMESTAMP"
        ))
        connection.execute(text(
            "ALTER TABLE requisites ADD COLUMN IF NOT EXISTS comment TEXT"
        ))

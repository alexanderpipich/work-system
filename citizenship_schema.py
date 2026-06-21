from sqlalchemy import text

from database import engine


def ensure_citizenship_columns():
    with engine.begin() as connection:
        connection.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS citizenship_country_id INTEGER REFERENCES countries(id)"
        ))
        connection.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_student BOOLEAN DEFAULT FALSE"
        ))
        connection.execute(text(
            "ALTER TABLE document_types ADD COLUMN IF NOT EXISTS sort_order INTEGER DEFAULT 0"
        ))
        connection.execute(text(
            "ALTER TABLE document_types ADD COLUMN IF NOT EXISTS is_student_doc BOOLEAN DEFAULT FALSE"
        ))

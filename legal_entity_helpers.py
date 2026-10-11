from sqlalchemy import text

from database import engine
from models import LegalEntity


def ensure_legal_entities_table():
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS legal_entities (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR NOT NULL,
                    short_name VARCHAR,
                    inn VARCHAR,
                    comment TEXT,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP
                )
                """
            )
        )
        # П4: реквизиты юрлица для договора и ходатайства.
        connection.execute(text("ALTER TABLE legal_entities ADD COLUMN IF NOT EXISTS full_name VARCHAR"))
        connection.execute(text("ALTER TABLE legal_entities ADD COLUMN IF NOT EXISTS ogrn VARCHAR"))
        connection.execute(text("ALTER TABLE legal_entities ADD COLUMN IF NOT EXISTS kpp VARCHAR"))
        connection.execute(text("ALTER TABLE legal_entities ADD COLUMN IF NOT EXISTS legal_address TEXT"))
        connection.execute(text("ALTER TABLE legal_entities ADD COLUMN IF NOT EXISTS bank_name VARCHAR"))
        connection.execute(text("ALTER TABLE legal_entities ADD COLUMN IF NOT EXISTS bank_account VARCHAR"))
        connection.execute(text("ALTER TABLE legal_entities ADD COLUMN IF NOT EXISTS bik VARCHAR"))
        connection.execute(text("ALTER TABLE legal_entities ADD COLUMN IF NOT EXISTS corr_account VARCHAR"))
        connection.execute(text("ALTER TABLE legal_entities ADD COLUMN IF NOT EXISTS director_name VARCHAR"))
        connection.execute(text("ALTER TABLE legal_entities ADD COLUMN IF NOT EXISTS director_name_genitive VARCHAR"))
        connection.execute(text("ALTER TABLE legal_entities ADD COLUMN IF NOT EXISTS director_short VARCHAR"))
        connection.execute(text("ALTER TABLE legal_entities ADD COLUMN IF NOT EXISTS director_title VARCHAR"))
        connection.execute(text("ALTER TABLE legal_entities ADD COLUMN IF NOT EXISTS work_address TEXT"))
        connection.execute(text("ALTER TABLE legal_entities ADD COLUMN IF NOT EXISTS actual_address TEXT"))


def active_legal_entities(session):
    return (
        session.query(LegalEntity)
        .filter(LegalEntity.is_active == True)
        .order_by(LegalEntity.name.asc())
        .all()
    )


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


def active_legal_entities(session):
    return (
        session.query(LegalEntity)
        .filter(LegalEntity.is_active == True)
        .order_by(LegalEntity.name.asc())
        .all()
    )


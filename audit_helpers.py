import json
import logging

from sqlalchemy import text

from database import engine
from models import AuditLog
from time_helpers import now_utc


logger = logging.getLogger(__name__)


def ensure_audit_log_table():
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER,
                    user_role VARCHAR,
                    action VARCHAR NOT NULL,
                    entity_type VARCHAR NOT NULL,
                    entity_id VARCHAR,
                    entity_name VARCHAR,
                    old_value TEXT,
                    new_value TEXT,
                    comment TEXT,
                    ip_address VARCHAR,
                    user_agent TEXT,
                    created_at TIMESTAMP DEFAULT NOW()
                )
                """
            )
        )


def audit_value(value):
    if value is None or isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except Exception:
        return str(value)


def create_audit_log(
    session,
    request,
    user,
    action,
    entity_type,
    entity_id=None,
    entity_name=None,
    old_value=None,
    new_value=None,
    comment=None,
):
    savepoint = None
    try:
        client = getattr(request, "client", None) if request else None
        headers = getattr(request, "headers", {}) if request else {}
        connection = session.connection()
        savepoint = connection.begin_nested()
        connection.execute(
            AuditLog.__table__.insert().values(
                user_id=getattr(user, "id", None),
                user_role=getattr(user, "role", None),
                action=action,
                entity_type=entity_type,
                entity_id=str(entity_id) if entity_id is not None else None,
                entity_name=entity_name,
                old_value=audit_value(old_value),
                new_value=audit_value(new_value),
                comment=comment,
                ip_address=getattr(client, "host", None),
                user_agent=headers.get("user-agent") if headers else None,
                created_at=now_utc(),
            )
        )
        savepoint.commit()
        return True
    except Exception:
        if savepoint is not None and savepoint.is_active:
            savepoint.rollback()
        logger.exception("Audit log write failed")
        return False

from sqlalchemy import text

from database import engine


def ensure_user_profile_columns():
    with engine.begin() as connection:
        connection.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(50) DEFAULT 'employee'"
        ))
        connection.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS brigadier_store VARCHAR"
        ))
        connection.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS economist_stores TEXT"
        ))
        connection.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS citizenship_country VARCHAR"
        ))
        connection.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS legal_entity VARCHAR"
        ))
        connection.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS inn VARCHAR"
        ))
        connection.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS qr_image_path VARCHAR"
        ))
        connection.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS job_title VARCHAR"
        ))
        connection.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_is_temporary BOOLEAN DEFAULT FALSE"
        ))
        # П1-Б: сотрудник без кабинета (phone/password_hash NULL), ДР, закреплённый ТМ.
        connection.execute(text("ALTER TABLE users ALTER COLUMN phone DROP NOT NULL"))
        connection.execute(text("ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL"))
        connection.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS birth_date DATE"))
        connection.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS tm_id INTEGER REFERENCES users(id)"
        ))
        connection.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS employee_name_norm VARCHAR(255)"
        ))
        connection.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS gender VARCHAR(1)"))
        connection.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR"))
        connection.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS tour_seen_at TIMESTAMP"))
        connection.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS tour_mode VARCHAR(10)"))
    _backfill_employee_name_norm()


def _backfill_employee_name_norm():
    """Заполнить employee_name_norm и поставить уникальный индекс, если дублей нет.

    На базе с дублями ФИО индекс не ставится (иначе упал бы старт приложения) —
    печатается предупреждение; разбор: tools/check_duplicate_users.py.
    """
    from utils import normalize_person_name

    with engine.begin() as connection:
        rows = connection.execute(text("SELECT id, employee_name, employee_name_norm FROM users")).all()
        for user_id, name, norm in rows:
            key = normalize_person_name(name)
            if key != norm:
                connection.execute(
                    text("UPDATE users SET employee_name_norm = :key WHERE id = :id"),
                    {"key": key, "id": user_id},
                )
        duplicates = connection.execute(text(
            "SELECT employee_name_norm FROM users GROUP BY employee_name_norm HAVING COUNT(*) > 1"
        )).all()
        if duplicates:
            print(
                "ВНИМАНИЕ: дубли ФИО в users (%d) — уникальный индекс uq_users_employee_name_norm "
                "не создан. Разбор: python tools/check_duplicate_users.py" % len(duplicates)
            )
            return
        connection.execute(text("ALTER TABLE users ALTER COLUMN employee_name_norm SET NOT NULL"))
        connection.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_users_employee_name_norm ON users (employee_name_norm)"
        ))

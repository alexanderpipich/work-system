from sqlalchemy import text

from database import engine


def ensure_service_columns():
    """Идемпотентно добавить колонки переделки услуг (этап 1).

    Таблицу `services` создаёт Base.metadata.create_all; здесь — недостающие
    колонки на существующей `rates` (service_id → services, level).
    """
    with engine.begin() as connection:
        connection.execute(text(
            "ALTER TABLE rates ADD COLUMN IF NOT EXISTS service_id INTEGER REFERENCES services(id)"
        ))
        connection.execute(text(
            "ALTER TABLE rates ADD COLUMN IF NOT EXISTS level INTEGER"
        ))
        # Услуга, не оплачиваемая из timebook (комплектация — другой отчёт).
        connection.execute(text(
            "ALTER TABLE services ADD COLUMN IF NOT EXISTS excluded_from_payroll BOOLEAN NOT NULL DEFAULT FALSE"
        ))
        # П4.4: тарифный регион магазина (подбор ставки).
        connection.execute(text(
            "ALTER TABLE stores ADD COLUMN IF NOT EXISTS rate_region VARCHAR"
        ))

"""
Drop the deprecated `citizenship` column from the `requisites` table.

Гражданство развязано (нормализация атрибутов, Блок 1): единственный источник
истины — `User.citizenship_country_id`. Колонка `requisites.citizenship` больше
не читается и не пишется кодом; данные перенесены скриптом
migrate_citizenship_decouple.py. Эта миграция удаляет колонку.

Идемпотентна — safe to run multiple times (DROP COLUMN IF EXISTS + inspect-проверка).

⚠️ Запускать на Render Shell ПОСЛЕ деплоя кода, где модель Requisite уже без поля:
    python scripts/migrate_drop_requisite_citizenship.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import inspect, text

from database import engine


def _column_exists(conn, table, column):
    inspector = inspect(conn)
    return any(col["name"] == column for col in inspector.get_columns(table))


def main():
    with engine.begin() as conn:
        if _column_exists(conn, "requisites", "citizenship"):
            conn.execute(text("ALTER TABLE requisites DROP COLUMN IF EXISTS citizenship"))
            print("[ok] dropped requisites.citizenship")
        else:
            print("[skip] requisites.citizenship already absent")

    print("Done.")


if __name__ == "__main__":
    main()

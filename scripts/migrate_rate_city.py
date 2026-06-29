"""
Add `city` column to the `rates` table.

Rates are matched to shifts by the "Город" column (Shift.city), which is read
from column E of the timebook report. This migration adds the matching column
to Rate so the base tariff grid can be scoped per city.

Idempotent — safe to run multiple times.

Run on Render Shell from the app root:
    python scripts/migrate_rate_city.py
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
        if _column_exists(conn, "rates", "city"):
            print("[skip] rates.city already exists")
        else:
            conn.execute(text("ALTER TABLE rates ADD COLUMN city VARCHAR"))
            print("[ok] added rates.city")

        # index for matching performance (idempotent via IF NOT EXISTS)
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_rates_city ON rates (city)")
        )
        print("[ok] ensured ix_rates_city")

    print("Done.")


if __name__ == "__main__":
    main()

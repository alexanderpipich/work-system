"""
Create the `reconciliation_notifications` table (рассылка сверок — идемпотентность).

Records the fact that a reconciliation (сверка) XLS was mailed for a given
store + period + type (A/B), so the same ТК+period+type is not sent twice.
Mirrors `bp_notifications`.

Idempotent — safe to run multiple times (CREATE TABLE checkfirst).

Run on Render Shell from the app root:
    python scripts/migrate_reconciliation_notifications.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import engine
from models import ReconciliationNotification


def main():
    ReconciliationNotification.__table__.create(bind=engine, checkfirst=True)
    print("[ok] ensured table reconciliation_notifications")
    print("Done.")


if __name__ == "__main__":
    main()

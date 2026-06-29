"""
Create the `bp_notifications` table (БП mailing idempotency).

Records the fact that a planning blank (БП) was mailed for a given store+period,
so the same ТК+period is not sent twice. Mirrors `unplanned_notifications`.

Idempotent — safe to run multiple times (CREATE TABLE checkfirst).

Run on Render Shell from the app root:
    python scripts/migrate_bp_notifications.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import engine
from models import BPNotification


def main():
    BPNotification.__table__.create(bind=engine, checkfirst=True)
    print("[ok] ensured table bp_notifications")
    print("Done.")


if __name__ == "__main__":
    main()

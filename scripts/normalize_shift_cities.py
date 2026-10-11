"""
Нормализовать город в уже загруженных сменах (П4.2): «г. Москва» → «Москва»,
«nan» и пустое → NULL. Новые загрузки нормализуются сами (routers/upload.py).

Зачем: Rate.city сравнивается с Shift.city строка в строку — «г. Москва» не
подберёт ставку «Москва». Зафиксированные табели не меняются (суммы в строках).

    python scripts/normalize_shift_cities.py           # сухой прогон
    python scripts/normalize_shift_cities.py --apply
"""

import argparse
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_helpers import create_audit_log  # noqa: E402
from database import SessionLocal           # noqa: E402
from models import Shift                    # noqa: E402
from utils import normalize_city            # noqa: E402


def normalize_shift_cities(session, apply=False):
    """Counter {(было, стало): смен}. Коммит — на вызывающем."""
    changes = Counter()
    for shift in session.query(Shift).filter(Shift.city != None).all():  # noqa: E711
        new_city = normalize_city(shift.city) or None
        if new_city != shift.city:
            changes[(shift.city, new_city)] += 1
            if apply:
                shift.city = new_city
    if apply and changes:
        create_audit_log(session, None, None, "shifts.city_normalized", "shift", None, "Нормализация города",
                         new_value={f"{old!r} → {new!r}": n for (old, new), n in changes.items()})
    return changes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    session = SessionLocal()
    try:
        changes = normalize_shift_cities(session, apply=args.apply)
        for (old, new), count in changes.most_common():
            print(f"  {old!r} → {new!r}: {count}")
        if args.apply:
            session.commit()
            print(f"Исправлено смен: {sum(changes.values())}")
        else:
            print(f"Будет исправлено смен: {sum(changes.values())} (сухой прогон, --apply для записи)")
    finally:
        session.close()


if __name__ == "__main__":
    main()

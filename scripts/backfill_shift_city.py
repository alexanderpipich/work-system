"""
Заполнить город в сменах без города по справочнику ТК (П4.3).

У смены с пустым «Городом» в выгрузке номер ТК берётся из Shift.store, город —
из Store.city, если он известен и встречается в выгрузках (иначе ставки по нему
не подберутся). Новые загрузки делают то же сами (routers/upload.py).
Зафиксированные табели не меняются (суммы в строках).

    python scripts/backfill_shift_city.py           # сухой прогон
    python scripts/backfill_shift_city.py --apply
"""

import argparse
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_helpers import create_audit_log                                    # noqa: E402
from database import SessionLocal                                             # noqa: E402
from models import Shift, Store                                               # noqa: E402
from store_helpers import extract_tk_number, store_city_by_tk, timebook_cities  # noqa: E402


def backfill_shift_city(session, apply=False):
    """{filled: Counter{(ТК, город): смен}, left: Counter{(магазин, причина): смен}}. Коммит — на вызывающем."""
    city_by_tk = store_city_by_tk(session, timebook_cities(session))
    stores = {tk: city for tk, city in session.query(Store.tk_number, Store.city)}
    filled, left = Counter(), Counter()
    for shift in session.query(Shift).filter(Shift.city == None).all():  # noqa: E711
        tk = extract_tk_number(shift.store)
        city = city_by_tk.get(tk)
        if city:
            filled[(tk, city)] += 1
            if apply:
                shift.city = city
        elif tk is None:
            left[(shift.store, "нет номера ТК")] += 1
        elif tk not in stores:
            left[(shift.store, "ТК нет в справочнике")] += 1
        elif not stores[tk]:
            left[(shift.store, "у ТК нет города")] += 1
        else:
            left[(shift.store, f"город ТК «{stores[tk]}» не встречается в выгрузках")] += 1
    if apply and filled:
        create_audit_log(session, None, None, "shifts.city_backfilled", "shift", None,
                         "Город смен из справочника ТК",
                         new_value={f"ТК {tk} → {city}": n for (tk, city), n in sorted(filled.items())})
    return {"filled": filled, "left": left}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    session = SessionLocal()
    try:
        result = backfill_shift_city(session, apply=args.apply)
        for (tk, city), count in sorted(result["filled"].items()):
            print(f"  ТК {tk} → {city}: {count}")
        filled = sum(result["filled"].values())
        if args.apply:
            session.commit()
            print(f"Заполнено смен: {filled}")
        else:
            print(f"Будет заполнено смен: {filled} (сухой прогон, --apply для записи)")
        if result["left"]:
            print(f"Остались без города: {sum(result['left'].values())}")
            for (store, reason), count in result["left"].most_common():
                print(f"  {store} — {reason}: {count}")
    finally:
        session.close()


if __name__ == "__main__":
    main()

import re

from sqlalchemy.orm import Session

from models import Shift, Store
from time_helpers import now_utc


def extract_tk_number(store_str: str):
    match = re.search(r"(\d+)", store_str or "")
    return int(match.group(1)) if match else None


def populate_stores_from_shifts(session: Session) -> dict:
    rows = session.query(Shift.store, Shift.city, Shift.format).distinct().all()

    seen_tk: dict[int, tuple] = {}
    unrecognized: list[str] = []

    for store_str, city, fmt in rows:
        tk = extract_tk_number(store_str)
        if tk is None:
            unrecognized.append(store_str)
            continue
        # prefer longest display name as most descriptive
        if tk not in seen_tk or len(store_str) > len(seen_tk[tk][0]):
            seen_tk[tk] = (store_str, city, fmt)

    created = 0
    updated = 0

    for tk, (store_str, city, fmt) in seen_tk.items():
        existing = session.query(Store).filter(Store.tk_number == tk).first()
        if existing is None:
            session.add(Store(
                tk_number=tk,
                display_name=store_str,
                city=city,
                format=fmt,
                created_at=now_utc(),
            ))
            created += 1
        else:
            changed = False
            if not existing.display_name:
                existing.display_name = store_str
                changed = True
            if not existing.city:
                existing.city = city
                changed = True
            if not existing.format:
                existing.format = fmt
                changed = True
            if changed:
                existing.updated_at = now_utc()
                updated += 1

    session.commit()
    return {"created": created, "updated": updated, "unrecognized": unrecognized}

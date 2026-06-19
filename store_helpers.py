import re

from sqlalchemy.orm import Session

from models import STORE_CONTACT_ROLES, Shift, Store, StoreContact, StoreNotificationSettings, StoreReconciliationSettings
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


def _find_store_by_string(session: Session, store_str: str):
    tk = extract_tk_number(store_str)
    if tk is None:
        return None
    return session.query(Store).filter(Store.tk_number == tk).first()


def _contact_exists(session: Session, store_id: int, email: str, scenario_field: str) -> bool:
    contact = session.query(StoreContact).filter(
        StoreContact.store_id == store_id,
        StoreContact.email == email,
        StoreContact.is_active == True,
    ).first()
    if contact is None:
        return False
    return bool(getattr(contact, scenario_field, False))


def migrate_legacy_store_settings(session: Session) -> dict:
    """
    Idempotently migrate StoreReconciliationSettings and StoreNotificationSettings
    into StoreContact rows. Old tables are left intact (deprecated).
    """
    reconciliation_created = 0
    unplanned_created = 0
    skipped = 0

    for row in session.query(StoreReconciliationSettings).all():
        if not row.email or not row.store:
            skipped += 1
            continue
        store = _find_store_by_string(session, row.store)
        if store is None:
            skipped += 1
            continue
        if _contact_exists(session, store.id, row.email, "for_reconciliation"):
            skipped += 1
            continue
        existing = session.query(StoreContact).filter(
            StoreContact.store_id == store.id,
            StoreContact.email == row.email,
            StoreContact.is_active == True,
        ).first()
        if existing:
            existing.for_reconciliation = True
        else:
            session.add(StoreContact(
                store_id=store.id,
                email=row.email,
                role="other",
                for_reconciliation=True,
            ))
        reconciliation_created += 1

    for row in session.query(StoreNotificationSettings).all():
        if not row.email or not row.store:
            skipped += 1
            continue
        store = _find_store_by_string(session, row.store)
        if store is None:
            skipped += 1
            continue
        if _contact_exists(session, store.id, row.email, "for_unplanned"):
            skipped += 1
            continue
        existing = session.query(StoreContact).filter(
            StoreContact.store_id == store.id,
            StoreContact.email == row.email,
            StoreContact.is_active == True,
        ).first()
        if existing:
            existing.for_unplanned = True
        else:
            session.add(StoreContact(
                store_id=store.id,
                email=row.email,
                role="other",
                for_unplanned=True,
            ))
        unplanned_created += 1

    session.commit()
    return {
        "reconciliation_migrated": reconciliation_created,
        "unplanned_migrated": unplanned_created,
        "skipped": skipped,
        "note": "StoreReconciliationSettings and StoreNotificationSettings left intact (deprecated, remove after prod verification)",
    }

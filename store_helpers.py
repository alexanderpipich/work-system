import re

from sqlalchemy.orm import Session

from models import STORE_CONTACT_ROLES, Shift, Store, StoreContact, StoreNotificationSettings, StoreReconciliationSettings
from time_helpers import now_utc


def extract_tk_number(store_str: str):
    match = re.search(r"(\d+)", store_str or "")
    return int(match.group(1)) if match else None


def populate_stores_from_shifts(session: Session) -> dict:
    """Создать недостающие ТК из выгрузки смен (П4.2): номер ТК, название, город,
    формат. Адреса и контакты — пустые, их заполняет ТМ по мере надобности.
    У существующих ТК заполняются только пустые название/город/формат."""
    from utils import normalize_city, normalize_format

    rows = session.query(Shift.store, Shift.city, Shift.format).distinct().all()

    seen_tk: dict[int, tuple] = {}
    unrecognized: list[str] = []

    for store_str, city, fmt in rows:
        tk = extract_tk_number(store_str)
        if tk is None:
            unrecognized.append(store_str)
            continue
        city = normalize_city(city) or None
        fmt = normalize_format(fmt) or None
        # prefer longest display name as most descriptive; any known city/format wins
        # over an empty one regardless of row order (one ТК can come with «nan» city)
        previous = seen_tk.get(tk)
        if previous is None:
            seen_tk[tk] = (store_str, city, fmt)
        else:
            name = store_str if len(store_str) > len(previous[0]) else previous[0]
            seen_tk[tk] = (name, previous[1] or city, previous[2] or fmt)

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


def store_formats(session: Session) -> dict:
    """{строка магазина из смен: формат} — по справочнику ТК, иначе по последней смене.

    П4.2: БП и сверки делаются только для ГМ; для СМ разделы действий не предлагают.
    """
    from utils import normalize_format

    by_tk = {s.tk_number: normalize_format(s.format) for s in session.query(Store).all() if s.format}
    result = {}
    for store_str, fmt in session.query(Shift.store, Shift.format).distinct().all():
        tk = extract_tk_number(store_str)
        known = by_tk.get(tk) if tk is not None else None
        result[store_str] = known or result.get(store_str) or normalize_format(fmt)
    return result


def is_gm(fmt) -> bool:
    from utils import normalize_format

    return normalize_format(fmt) == "ГМ"


def allows_bp(fmt) -> bool:
    """БП и сверки: ГМ — да; явно другой формат (СМ…) — нет; формат неизвестен — не
    отсекаем (магазина нет в справочнике и смен ещё не было)."""
    return not fmt or is_gm(fmt)


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

"""
RBAC-5 Step 4 (Part 1): Migrate legacy scope fields → UserAccessScope.

Idempotent — safe to run multiple times.

Reads:
  User.economist_stores  (comma-separated city names)  → scope_type="city"
      for roles: economist, hr_manager
  User.brigadier_store   (single store name)            → scope_type="store"
      for role: brigadier

Does NOT touch:
  - legacy fields (economist_stores, brigadier_store) — left intact
  - can_access_store / fallback logic in rbac.py
  - any other business logic

Run on Render Shell from the app root:
    python scripts/migrate_scopes.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import SessionLocal
from models import User, UserAccessScope
from rbac import canonical_role
from time_helpers import now_utc
from utils import normalize_text

CITY_ROLES = {"economist", "hr_manager"}
STORE_ROLES = {"brigadier"}


def _parse_cities(raw):
    if not raw:
        return []
    return sorted({normalize_text(v) for v in str(raw).split(",") if normalize_text(v)})


def _scope_exists(session, user_id, scope_type, scope_value):
    return (
        session.query(UserAccessScope)
        .filter(
            UserAccessScope.user_id == user_id,
            UserAccessScope.scope_type == scope_type,
            UserAccessScope.scope_value == scope_value,
        )
        .first()
    ) is not None


def _ensure_scope(session, user_id, scope_type, scope_value):
    """Insert scope row if it doesn't already exist. Returns True if created."""
    if _scope_exists(session, user_id, scope_type, scope_value):
        return False
    session.add(UserAccessScope(
        user_id=user_id,
        scope_type=scope_type,
        scope_value=scope_value,
        created_by=None,
        created_at=now_utc(),
        is_active=True,
    ))
    return True


def main():
    session = SessionLocal()
    try:
        users = session.query(User).all()

        users_processed = 0
        scopes_created = 0
        scopes_skipped = 0
        users_no_legacy = 0
        details = []

        for user in users:
            role = canonical_role(user)

            if role in CITY_ROLES:
                cities = _parse_cities(getattr(user, "economist_stores", "") or "")
                if not cities:
                    users_no_legacy += 1
                    continue
                users_processed += 1
                created_for_user = 0
                for city in cities:
                    if _ensure_scope(session, user.id, "city", city):
                        scopes_created += 1
                        created_for_user += 1
                    else:
                        scopes_skipped += 1
                details.append(
                    f"  [{role:12s}] {(user.employee_name or '?')[:35]:35s}"
                    f" city={cities}  +{created_for_user} new"
                )

            elif role in STORE_ROLES:
                store = normalize_text(getattr(user, "brigadier_store", "") or "")
                if not store:
                    users_no_legacy += 1
                    continue
                users_processed += 1
                created_for_user = 0
                if _ensure_scope(session, user.id, "store", store):
                    scopes_created += 1
                    created_for_user += 1
                else:
                    scopes_skipped += 1
                details.append(
                    f"  [{role:12s}] {(user.employee_name or '?')[:35]:35s}"
                    f" store={store}  +{created_for_user} new"
                )

        session.commit()

        print()
        print("=" * 60)
        print("  RBAC-5 SCOPE MIGRATION — DONE")
        print("=" * 60)
        for line in details:
            print(line)
        if details:
            print()
        print(f"  Users processed (had legacy data) : {users_processed}")
        print(f"  Scopes created                    : {scopes_created}")
        print(f"  Scopes already existed (skipped)  : {scopes_skipped}")
        print(f"  Users skipped (no legacy data)    : {users_no_legacy}")
        print("=" * 60)
        print("  Legacy fields left intact. Fallback NOT removed.")
        print("  Run scripts/check_scope_coverage.py to verify coverage.")
        print("=" * 60)
        print()

    except Exception as exc:
        session.rollback()
        print(f"\nERROR — rolled back: {exc}", file=sys.stderr)
        raise
    finally:
        session.close()


if __name__ == "__main__":
    main()

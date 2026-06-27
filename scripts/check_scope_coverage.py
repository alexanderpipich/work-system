"""
RBAC-5 Step 4 (Part 1): Coverage check after scope migration.

For each active economist / hr_manager / brigadier shows:
  - scopes present in UserAccessScope
  - users with EMPTY scope (will fall back to legacy data or see nothing)

Run on Render Shell from the app root:
    python scripts/check_scope_coverage.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import SessionLocal
from models import User, UserAccessScope
from rbac import canonical_role

SCOPED_ROLES = {"economist", "hr_manager", "brigadier"}
SCOPE_TYPE = {"economist": "city", "hr_manager": "city", "brigadier": "store"}


def main():
    session = SessionLocal()
    try:
        users = session.query(User).all()
        scoped = [u for u in users if canonical_role(u) in SCOPED_ROLES]

        covered = []
        empty = []

        for user in scoped:
            role = canonical_role(user)
            stype = SCOPE_TYPE[role]

            rows = (
                session.query(UserAccessScope)
                .filter(
                    UserAccessScope.user_id == user.id,
                    UserAccessScope.scope_type == stype,
                    UserAccessScope.is_active == True,
                )
                .order_by(UserAccessScope.scope_value)
                .all()
            )
            values = [r.scope_value for r in rows]

            if values:
                covered.append((user, role, stype, values))
            else:
                # Show what legacy field holds so we know if fallback will save them
                if stype == "city":
                    legacy = (getattr(user, "economist_stores", "") or "").strip()
                else:
                    legacy = (getattr(user, "brigadier_store", "") or "").strip()
                empty.append((user, role, stype, legacy))

        print()
        print("=" * 65)
        print("  RBAC-5 SCOPE COVERAGE REPORT")
        print("=" * 65)
        print(f"  Scoped users total : {len(scoped)}")
        print(f"  Have UserAccessScope : {len(covered)}")
        print(f"  Empty (no scope)     : {len(empty)}")
        print()

        if covered:
            print("--- COVERED ---")
            for user, role, stype, values in covered:
                name = (user.employee_name or "?")[:32]
                print(f"  [{role:12s}] {name:32s} ({stype}): {', '.join(values)}")
            print()

        if empty:
            print("--- EMPTY SCOPE ---")
            for user, role, stype, legacy in empty:
                name = (user.employee_name or "?")[:32]
                if legacy:
                    note = f"[legacy field has: '{legacy}' — migration may have been skipped]"
                else:
                    note = "[NO legacy data — user has no scope anywhere]"
                print(f"  [{role:12s}] {name:32s} {note}")
            print()
        else:
            print("  All scoped users have at least one scope in UserAccessScope.")
            print()

        print("=" * 65)
        print()

    finally:
        session.close()


if __name__ == "__main__":
    main()

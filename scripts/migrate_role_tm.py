"""
Переименовать роль: users.role 'hr_manager' → 'tm' (П1-В).

Код и без миграции считает hr_manager ТМ (rbac.LEGACY_ROLE_ALIASES), но
выборки по колонке role (фильтр /admin/users, «Команда HR») ищут уже 'tm'.
Идемпотентно: повторный запуск ничего не меняет. На чистой базе — 0 строк.

    python scripts/migrate_role_tm.py            # сухой прогон
    python scripts/migrate_role_tm.py --apply
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_helpers import create_audit_log  # noqa: E402
from database import SessionLocal           # noqa: E402
from models import User                     # noqa: E402
from rbac import ROLE_TM                    # noqa: E402

OLD_ROLE = "hr_manager"


def migrate_role_tm(session, apply=False):
    """Список переведённых User (при apply=False — кандидатов). Коммит — на вызывающем."""
    users = session.query(User).filter(User.role == OLD_ROLE).order_by(User.id).all()
    if apply:
        for user in users:
            user.role = ROLE_TM
            create_audit_log(
                session, None, None, "user_role_changed", "user", user.id, user.employee_name,
                old_value={"role": OLD_ROLE}, new_value={"role": ROLE_TM},
                comment="scripts/migrate_role_tm.py",
            )
    return users


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    session = SessionLocal()
    try:
        users = migrate_role_tm(session, apply=args.apply)
        for user in users:
            print(f"  {user.id}: {user.employee_name}")
        if args.apply:
            session.commit()
            print(f"Переведено в '{ROLE_TM}': {len(users)}")
        else:
            print(f"Будет переведено в '{ROLE_TM}': {len(users)} (сухой прогон, --apply для записи)")
    finally:
        session.close()


if __name__ == "__main__":
    main()

import os

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from dependencies import get_db, require_admin_user
from models import Shift, User
from utils import normalize_phone


router = APIRouter()


def _require_maintenance_enabled():
    if os.getenv("ENABLE_MAINTENANCE_ROUTES") != "1":
        raise HTTPException(status_code=404)


@router.get("/admin/fix-phones")
def fix_phones(
    session: Session = Depends(get_db),
    admin=Depends(require_admin_user),
):
    _require_maintenance_enabled()

    try:
        users = session.query(User).all()
        fixed = 0
        skipped = 0

        for user in users:
            old_phone = user.phone
            new_phone = normalize_phone(user.phone)

            if old_phone == new_phone:
                continue

            existing = session.query(User).filter(User.phone == new_phone).first()
            if existing and existing.id != user.id:
                skipped += 1
                continue

            user.phone = new_phone
            fixed += 1

        session.commit()
        return {"fixed": fixed, "skipped": skipped}

    except Exception:
        session.rollback()
        return {"error": "Maintenance action failed"}


@router.get("/debug/shifts-count")
def debug(
    session: Session = Depends(get_db),
    admin=Depends(require_admin_user),
):
    _require_maintenance_enabled()

    return {"count": session.query(Shift).count()}

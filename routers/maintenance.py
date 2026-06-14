import os

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from audit_helpers import create_audit_log
from dependencies import get_db
from models import Shift, User
from rbac import require_permission
from utils import normalize_phone


router = APIRouter()
require_maintenance_access = require_permission("system.maintenance", audit_denied=True)


def _require_maintenance_enabled():
    if os.getenv("ENABLE_MAINTENANCE_ROUTES") != "1":
        raise HTTPException(status_code=404)


@router.post("/admin/fix-phones")
def fix_phones(
    request: Request,
    session: Session = Depends(get_db),
    admin=Depends(require_maintenance_access),
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

        create_audit_log(
            session, request, admin, "maintenance_fix_phones", "system",
            new_value={"fixed": fixed, "skipped": skipped},
        )
        session.commit()
        return {"fixed": fixed, "skipped": skipped}

    except Exception:
        session.rollback()
        return {"error": "Maintenance action failed"}


@router.get("/debug/shifts-count")
def debug(
    session: Session = Depends(get_db),
    admin=Depends(require_maintenance_access),
):
    _require_maintenance_enabled()
    return {"count": session.query(Shift).count()}

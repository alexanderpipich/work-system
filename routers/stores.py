from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from dependencies import get_db
from rbac import require_permission
from store_helpers import populate_stores_from_shifts


router = APIRouter()


@router.post("/admin/stores/populate")
def admin_stores_populate(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(require_permission("stores.manage")),
):
    report = populate_stores_from_shifts(session)
    return JSONResponse(report)

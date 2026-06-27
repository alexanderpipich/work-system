from datetime import date

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from fastapi.templating import Jinja2Templates

from dependencies import get_db
from rbac import require_permission
from unplanned_helpers import collect_unplanned

router = APIRouter()
templates = Jinja2Templates(directory="templates")

_manage = require_permission("email.manage")


def _parse_date(value: str):
    value = (value or "").strip()
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def _parse_tk(value: str):
    value = (value or "").strip()
    return int(value) if value.isdigit() else None


@router.get("/admin/email/unplanned", response_class=HTMLResponse)
def unplanned_preview(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_manage),
    date_from: str = "",
    date_to: str = "",
    tk: str = "",
    message: str = "",
    error: str = "",
):
    data = collect_unplanned(
        session,
        date_from=_parse_date(date_from),
        date_to=_parse_date(date_to),
        tk_filter=_parse_tk(tk),
    )
    return templates.TemplateResponse("admin_email_unplanned.html", {
        "request": request,
        "user": user,
        "data": data,
        "filters": {"date_from": date_from, "date_to": date_to, "tk": tk},
        "results": None,
        "message": message,
        "error": error,
    })

from datetime import date

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from fastapi.templating import Jinja2Templates

from audit_helpers import create_audit_log
from dependencies import get_db
from email_engine import send_email
from models import EmailLog, UnplannedNotification
from rbac import require_permission
from time_helpers import now_utc
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


@router.post("/admin/email/unplanned/send", response_class=HTMLResponse)
def unplanned_send(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_manage),
    date_from: str = Form(""),
    date_to: str = Form(""),
    tk: str = Form(""),
):
    # Пересобираем актуальный набор (идемпотентно: уже отправленные исключены).
    data = collect_unplanned(
        session,
        date_from=_parse_date(date_from),
        date_to=_parse_date(date_to),
        tk_filter=_parse_tk(tk),
    )

    sent = 0
    failed = 0
    errors = []

    for letter in data["to_send"]:
        result = send_email(
            to=letter["contacts"],
            subject=letter["subject"],
            body_html=letter["body_html"],
            body_text=letter["body_text"],
        )

        log = EmailLog(
            to_addresses=", ".join(result["to"]),
            subject=letter["subject"],
            status=result["status"],
            error=result.get("error"),
            scenario="unplanned_shifts",
            created_at=now_utc(),
            created_by=user.id,
        )
        session.add(log)
        session.flush()

        if result["status"] == "sent":
            # Идемпотентность: помечаем смены отправленными только при успехе.
            for shift_id in letter["shift_ids"]:
                session.add(UnplannedNotification(
                    shift_id=shift_id,
                    email_log_id=log.id,
                    status="sent",
                    sent_at=now_utc(),
                ))
            sent += 1
        else:
            failed += 1
            errors.append({
                "tk": letter["tk"],
                "status": result["status"],
                "error": result.get("error"),
            })

        create_audit_log(
            session,
            request,
            user,
            "unplanned_email_sent",
            "store",
            letter["tk"],
            f"ТК {letter['tk']}",
            new_value={
                "to": letter["contacts"],
                "subject": letter["subject"],
                "status": result["status"],
                "shifts": len(letter["shift_ids"]),
            },
            comment="unplanned shifts mailing",
        )

    session.commit()

    # Пересобираем после отправки — успешные смены теперь исключены.
    fresh = collect_unplanned(
        session,
        date_from=_parse_date(date_from),
        date_to=_parse_date(date_to),
        tk_filter=_parse_tk(tk),
    )

    return templates.TemplateResponse("admin_email_unplanned.html", {
        "request": request,
        "user": user,
        "data": fresh,
        "filters": {"date_from": date_from, "date_to": date_to, "tk": tk},
        "results": {"sent": sent, "failed": failed, "errors": errors},
        "message": f"Готово. Отправлено: {sent}, не отправлено: {failed}.",
        "error": "",
    })

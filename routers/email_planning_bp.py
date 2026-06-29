from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from audit_helpers import create_audit_log
from bp_mailing_helpers import build_bp_attachment, collect_planning_bp, resolve_period
from dependencies import get_db
from email_engine import send_email
from models import BPNotification, EmailLog
from rbac import require_permission
from time_helpers import now_utc

router = APIRouter()
templates = Jinja2Templates(directory="templates")

_manage = require_permission("email.manage")


def _parse_tk(value: str):
    value = (value or "").strip()
    return int(value) if value.isdigit() else None


def _history(session: Session):
    return (
        session.query(BPNotification)
        .order_by(BPNotification.id.desc())
        .limit(50)
        .all()
    )


def _render(request, user, session, *, data, filters, results=None, message="", error=""):
    return templates.TemplateResponse("admin_email_planning_bp.html", {
        "request": request,
        "user": user,
        "data": data,
        "filters": filters,
        "results": results,
        "message": message,
        "error": error,
        "history": _history(session),
    })


@router.get("/admin/email/planning-bp", response_class=HTMLResponse)
def planning_bp_preview(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_manage),
    date_from: str = "",
    date_to: str = "",
    tk: str = "",
    message: str = "",
    error: str = "",
):
    start, end = resolve_period(date_from, date_to)
    err = error
    if end < start:
        err = "Дата по не может быть раньше даты с."
        data = {"to_send": [], "no_contacts": [], "total_letters": 0,
                "total_pending": 0, "already_sent_count": 0,
                "stores_without_contacts": 0, "period_label": ""}
    else:
        data = collect_planning_bp(session, start, end, tk_filter=_parse_tk(tk))
    return _render(
        request, user, session, data=data,
        filters={"date_from": date_from, "date_to": date_to, "tk": tk},
        message=message, error=err,
    )


@router.post("/admin/email/planning-bp/send", response_class=HTMLResponse)
def planning_bp_send(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_manage),
    date_from: str = Form(""),
    date_to: str = Form(""),
    tk: str = Form(""),
):
    single_tk = _parse_tk(tk)
    start, end = resolve_period(date_from, date_to)
    filters = {"date_from": date_from, "date_to": date_to, "tk": tk}

    if end < start:
        return _render(request, user, session,
                       data=collect_planning_bp(session, start, start),
                       filters=filters, error="Дата по не может быть раньше даты с.")

    data = collect_planning_bp(session, start, end, tk_filter=single_tk)

    # Нечего отправлять одному магазину (нет контактов for_planning).
    if single_tk is not None and not data["to_send"]:
        return _render(request, user, session, data=data, filters=filters,
                       message=f"По ТК {single_tk} нет получателей for_planning — отправлять некому.")

    sent = 0
    failed = 0
    skipped = 0
    errors = []

    for letter in data["to_send"]:
        # Идемпотентность: уже отправленные за этот период не шлём повторно.
        if letter["already_sent"]:
            skipped += 1
            continue

        filename, pdf_bytes = build_bp_attachment(session, letter["tk"], start, end)
        result = send_email(
            to=letter["contacts"],
            subject=letter["subject"],
            body_html=letter["body_html"],
            body_text=letter["body_text"],
            attachments=[{
                "filename": filename,
                "data": pdf_bytes,
                "maintype": "application",
                "subtype": "pdf",
            }],
        )

        log = EmailLog(
            to_addresses=", ".join(result["to"]),
            subject=letter["subject"],
            status=result["status"],
            error=result.get("error"),
            scenario="planning_bp",
            created_at=now_utc(),
            created_by=user.id,
        )
        session.add(log)
        session.flush()

        if result["status"] == "sent":
            # Идемпотентность фиксируется только при успешной отправке.
            session.add(BPNotification(
                store_tk=letter["tk"],
                period_from=start,
                period_to=end,
                email_log_id=log.id,
                to_addresses=", ".join(result["to"]),
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
            session, request, user,
            "planning_bp_email_sent", "store", letter["tk"], f"ТК {letter['tk']}",
            new_value={
                "to": letter["contacts"],
                "subject": letter["subject"],
                "period": f"{start:%d.%m.%Y}–{end:%d.%m.%Y}",
                "status": result["status"],
            },
            comment="planning blank mailing",
        )

    session.commit()

    # Пересобираем (already_sent обновится). tk-фильтр сбрасываем при отправке одному.
    fresh = collect_planning_bp(session, start, end, tk_filter=None)

    if single_tk is not None:
        if skipped and not sent and not failed:
            message = f"ТК {single_tk}: уже отправлено за этот период — повтор пропущен."
        else:
            message = f"ТК {single_tk}: отправлено {sent}, не отправлено {failed}."
    else:
        message = f"Готово. Отправлено: {sent}, не отправлено: {failed}, пропущено (уже отправлено): {skipped}."

    return _render(
        request, user, session, data=fresh,
        filters={"date_from": date_from, "date_to": date_to, "tk": ""},
        results={"sent": sent, "failed": failed, "skipped": skipped, "errors": errors},
        message=message,
    )

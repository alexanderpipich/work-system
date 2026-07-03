"""
Рассылка сверок — предпросмотр и ручная отправка XLS-сверки на контакты
магазина с флагом for_reconciliation. Калька /admin/email/planning-bp.

Тип A (01-15, рассылка 17-го) / тип B (01-31, рассылка 03-го следующего).
Ничего не уходит без явного нажатия. Идемпотентность по (ТК, период, тип).
"""

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from audit_helpers import create_audit_log
from dependencies import get_db
from email_engine import send_email
from models import EmailLog, ReconciliationNotification
from rbac import require_permission
from reconciliation_helpers import (
    RECON_FORMATS,
    RECON_TYPES,
    build_reconciliation_attachment,
    collect_reconciliation,
    resolve_default_period,
)
from time_helpers import now_utc
from utils import normalize_format

router = APIRouter()
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="templates")

_manage = require_permission("email.manage")


def _parse_formats(values):
    """Список форматов из формы → нормализованный список из RECON_FORMATS.
    Пусто → [] (означает «все форматы»)."""
    result = []
    for v in values or []:
        fmt = normalize_format(v)
        if fmt in RECON_FORMATS and fmt not in result:
            result.append(fmt)
    return result


def _normalize_type(value: str) -> str:
    value = (value or "").strip().upper()
    return value if value in RECON_TYPES else "A"


def _parse_month(value: str, default_year: int, default_month: int):
    """`YYYY-MM` (из <input type=month>) → (year, month); пусто → дефолт."""
    value = (value or "").strip()
    if value:
        try:
            year_s, month_s = value.split("-")
            year, month = int(year_s), int(month_s)
            if 1 <= month <= 12:
                return year, month
        except (ValueError, AttributeError):
            pass
    return default_year, default_month


def _history(session: Session):
    return (
        session.query(ReconciliationNotification)
        .order_by(ReconciliationNotification.id.desc())
        .limit(50)
        .all()
    )


def _render(request, user, session, *, data, filters, results=None, message="", error=""):
    return templates.TemplateResponse("admin_email_reconciliation.html", {
        "request": request,
        "user": user,
        "data": data,
        "filters": filters,
        "results": results,
        "message": message,
        "error": error,
        "history": _history(session),
    })


@router.get("/admin/email/reconciliation", response_class=HTMLResponse)
def reconciliation_preview(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_manage),
    recon_type: str = "",
    month: str = "",
    formats: list[str] = Query(default=[]),
    message: str = "",
    error: str = "",
):
    def_type, def_year, def_month = resolve_default_period()
    rtype = _normalize_type(recon_type) if recon_type else def_type
    year, mon = _parse_month(month, def_year, def_month)
    fmt_list = _parse_formats(formats)

    data = collect_reconciliation(session, rtype, year, mon, formats=fmt_list or None)
    filters = {"recon_type": rtype, "month": f"{year:04d}-{mon:02d}",
               "formats": fmt_list, "all_formats": list(RECON_FORMATS)}
    return _render(request, user, session, data=data, filters=filters,
                   message=message, error=error)


@router.post("/admin/email/reconciliation/send", response_class=HTMLResponse)
def reconciliation_send(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_manage),
    recon_type: str = Form(""),
    month: str = Form(""),
    formats: list[str] = Form(default=[]),
    tks: list[int] = Form(default=[]),
):
    def_type, def_year, def_month = resolve_default_period()
    rtype = _normalize_type(recon_type) if recon_type else def_type
    year, mon = _parse_month(month, def_year, def_month)
    fmt_list = _parse_formats(formats)
    filters = {"recon_type": rtype, "month": f"{year:04d}-{mon:02d}",
               "formats": fmt_list, "all_formats": list(RECON_FORMATS)}

    data = collect_reconciliation(session, rtype, year, mon, formats=fmt_list or None)

    selected = {int(t) for t in tks}
    to_process = [l for l in data["to_send"] if l["tk"] in selected]
    if not to_process:
        return _render(request, user, session, data=data, filters=filters,
                       error="Выберите хотя бы один ТК (галочками) для отправки.")

    sent = failed = skipped = 0
    errors = []

    for letter in to_process:
        if letter["already_sent"]:
            skipped += 1
            continue

        filename, xls_bytes = build_reconciliation_attachment(
            session, letter["tk"], rtype, year, mon, formats=fmt_list or None)
        result = send_email(
            to=letter["contacts"],
            subject=letter["subject"],
            body_html=letter["body_html"],
            body_text=letter["body_text"],
            attachments=[{
                "filename": filename,
                "data": xls_bytes,
                "maintype": "application",
                "subtype": "vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            }],
        )

        log = EmailLog(
            to_addresses=", ".join(result["to"]),
            subject=letter["subject"],
            status=result["status"],
            error=result.get("error"),
            scenario="reconciliation",
            created_at=now_utc(),
            created_by=user.id,
        )
        session.add(log)
        session.flush()

        if result["status"] == "sent":
            session.add(ReconciliationNotification(
                store_tk=letter["tk"],
                period_from=data["period_from"],
                period_to=data["period_to"],
                recon_type=rtype,
                email_log_id=log.id,
                to_addresses=", ".join(result["to"]),
                status="sent",
                sent_at=now_utc(),
            ))
            sent += 1
        else:
            failed += 1
            errors.append({"tk": letter["tk"], "status": result["status"], "error": result.get("error")})

        create_audit_log(
            session, request, user,
            "reconciliation_email_sent", "store", letter["tk"], f"ТК {letter['tk']}",
            new_value={
                "to": letter["contacts"],
                "subject": letter["subject"],
                "period": data["period_label"],
                "type": rtype,
                "status": result["status"],
            },
            comment="reconciliation mailing",
        )

    session.commit()

    fresh = collect_reconciliation(session, rtype, year, mon, formats=fmt_list or None)

    message = (f"Готово по {len(to_process)} выбранным ТК. Отправлено: {sent}, "
               f"не отправлено: {failed}, пропущено (уже отправлено): {skipped}.")

    return _render(
        request, user, session, data=fresh, filters=filters,
        results={"sent": sent, "failed": failed, "skipped": skipped, "errors": errors},
        message=message,
    )

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from dependencies import get_db
from email_engine import send_email
from models import EmailLog
from rbac import require_permission
from time_helpers import now_utc

router = APIRouter()
templates = Jinja2Templates(directory="templates")

_manage = require_permission("email.manage")


@router.get("/admin/email/test", response_class=HTMLResponse)
def email_test_page(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_manage),
    message: str = "",
    error: str = "",
):
    logs = (
        session.query(EmailLog)
        .order_by(EmailLog.id.desc())
        .limit(10)
        .all()
    )
    return templates.TemplateResponse("admin_email_test.html", {
        "request": request,
        "user": user,
        "logs": logs,
        "message": message,
        "error": error,
    })


@router.post("/admin/email/test", response_class=HTMLResponse)
def email_test_send(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_manage),
    to_email: str = Form(...),
):
    to_email = to_email.strip()
    result = send_email(
        to=to_email,
        subject="Тест work-system",
        body_html="<p>Проверка отправки. Если вы видите это письмо — SMTP работает.</p>",
    )
    log = EmailLog(
        to_addresses=", ".join(result["to"]),
        subject="Тест work-system",
        status=result["status"],
        error=result.get("error"),
        scenario="test",
        created_at=now_utc(),
        created_by=user.id,
    )
    session.add(log)
    session.commit()

    if result["status"] == "sent":
        message = f"Письмо отправлено на {to_email}"
        error = ""
    elif result["status"] == "disabled":
        message = ""
        error = "Email отключён (EMAIL_ENABLED=false или SMTP не настроен)"
    else:
        message = ""
        error = f"Ошибка отправки: {result.get('error', '')}"

    logs = (
        session.query(EmailLog)
        .order_by(EmailLog.id.desc())
        .limit(10)
        .all()
    )
    return templates.TemplateResponse("admin_email_test.html", {
        "request": request,
        "user": user,
        "logs": logs,
        "message": message,
        "error": error,
        "last_to": to_email,
    })

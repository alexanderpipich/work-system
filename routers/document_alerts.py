"""Истекающие документы (П4): список, ручной запуск проверки сроков."""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from dependencies import RedirectException, current_user, get_db
from document_alerts import expiring_documents, run_document_expiry_alerts
from models import DocumentExpiryAlert, User
from rbac import has_permission, role_label
from time_helpers import now_utc
from utils import safe_return_to

router = APIRouter()
templates = Jinja2Templates(directory="templates")


def require_expiry_view(user=Depends(current_user)):
    if not (has_permission(user, "documents.manage") or has_permission(user, "documents.verify")):
        raise RedirectException("/")
    return user


@router.get("/admin/documents/expiring", response_class=HTMLResponse)
def expiring_page(request: Request, message: str = "", session: Session = Depends(get_db),
                  user=Depends(require_expiry_view)):
    rows = []
    users = {u.id: u for u in session.query(User).all()}
    for doc, doc_type, days_left, level in expiring_documents(session):
        alerts = session.query(DocumentExpiryAlert).filter(DocumentExpiryAlert.document_id == doc.id).all()
        notified = sorted({(users[a.recipient_user_id].employee_name, role_label(users[a.recipient_user_id].role),
                            a.email_status or "") for a in alerts if a.recipient_user_id in users})
        rows.append({"doc": doc, "type": doc_type, "days_left": days_left, "level": level, "notified": notified})
    # Просмотр списка = напоминания этому пользователю прочитаны (счётчик в шапке гаснет).
    session.query(DocumentExpiryAlert).filter(
        DocumentExpiryAlert.recipient_user_id == user.id,
        DocumentExpiryAlert.read_at == None,  # noqa: E711
    ).update({"read_at": now_utc()}, synchronize_session=False)
    session.commit()
    return templates.TemplateResponse(request, "documents_expiring.html", {
        "rows": rows, "can_run": has_permission(user, "documents.manage"), "message": message or None,
    })


@router.post("/admin/documents/expiring/run")
def expiring_run(request: Request, return_to: str = Form(default=""), session: Session = Depends(get_db),
                 user=Depends(require_expiry_view)):
    if not has_permission(user, "documents.manage"):
        raise RedirectException("/")
    result = run_document_expiry_alerts(session, request=request, actor=user)
    target = safe_return_to(return_to, "/admin/documents/expiring")
    separator = "&" if "?" in target else "?"
    return RedirectResponse(f"{target}{separator}message=Проверено: новых напоминаний {result['alerts_created']}, "
                            f"писем {result['emails']}", 302)

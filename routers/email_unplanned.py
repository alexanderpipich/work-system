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
from store_helpers import extract_tk_number
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


def _resolve_tk(tk: str, store: str):
    """Номер ТК из явного параметра, иначе из названия магазина.

    `store` приходит по клику на смену без плана в табеле: там под рукой строка
    магазина («ТК-7 Мурино»), а не её номер. Явный `tk` имеет приоритет —
    он остаётся тем же контрактом, что и был у формы на странице.
    """
    parsed = _parse_tk(tk)
    if parsed is not None:
        return parsed, tk
    from_store = extract_tk_number(store) if store else None
    return from_store, ("%s" % from_store if from_store is not None else "")


@router.get("/admin/email/unplanned", response_class=HTMLResponse)
def unplanned_preview(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_manage),
    date_from: str = "",
    date_to: str = "",
    tk: str = "",
    store: str = "",
    message: str = "",
    error: str = "",
):
    tk_filter, tk_display = _resolve_tk(tk, store)
    # Магазин не распознан по названию — честно говорим, а не показываем молча
    # рассылку по всем магазинам, будто так и было задумано.
    if store and tk_filter is None and not error:
        error = "Не удалось определить номер ТК из «%s» — показаны все магазины." % store

    data = collect_unplanned(
        session,
        date_from=_parse_date(date_from),
        date_to=_parse_date(date_to),
        tk_filter=tk_filter,
    )
    return templates.TemplateResponse("admin_email_unplanned.html", {
        "request": request,
        "user": user,
        "data": data,
        "filters": {"date_from": date_from, "date_to": date_to, "tk": tk_display},
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
    # tk задан -> отправка одному магазину; пуст -> отправка всех.
    single_tk = _parse_tk(tk)
    data = collect_unplanned(
        session,
        date_from=_parse_date(date_from),
        date_to=_parse_date(date_to),
        tk_filter=single_tk,
    )

    # Нечего отправлять одному магазину (всё уже отправлено ранее).
    if single_tk is not None and not data["to_send"]:
        return templates.TemplateResponse("admin_email_unplanned.html", {
            "request": request,
            "user": user,
            "data": data,
            "filters": {"date_from": date_from, "date_to": date_to, "tk": tk},
            "results": None,
            "message": f"По ТК {single_tk} нет смен к отправке (возможно, уже отправлено).",
            "error": "",
        })

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
    # Сбрасываем tk-фильтр предпросмотра при отправке одному магазину,
    # чтобы остальные письма снова были видны.
    fresh = collect_unplanned(
        session,
        date_from=_parse_date(date_from),
        date_to=_parse_date(date_to),
        tk_filter=None,
    )

    if single_tk is not None:
        message = f"ТК {single_tk}: отправлено {sent}, не отправлено {failed}."
    else:
        message = f"Готово. Отправлено: {sent}, не отправлено: {failed}."

    return templates.TemplateResponse("admin_email_unplanned.html", {
        "request": request,
        "user": user,
        "data": fresh,
        "filters": {"date_from": date_from, "date_to": date_to, "tk": ""},
        "results": {"sent": sent, "failed": failed, "errors": errors},
        "message": message,
        "error": "",
    })

"""Демо-туры (П5): шаги тура пользователя и отметка «тур просмотрен». Логика — tours.py."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from audit_helpers import create_audit_log
from dependencies import current_user, get_db
from models import User
from time_helpers import now_utc
from tours import tour_for_user

router = APIRouter()


@router.get("/tour/data")
def tour_data(user=Depends(current_user)):
    """Шаги тура, положенного пользователю по роли; чужой тур не отдаётся."""
    tour = tour_for_user(user)
    if tour is None:
        return JSONResponse({"error": "Тура для вашей роли нет"}, status_code=404)
    return tour


@router.post("/tour/seen")
def tour_seen(request: Request, session: Session = Depends(get_db), user=Depends(current_user)):
    """«Готово» / «Пропустить»: в режиме first тур больше не стартует сам."""
    if tour_for_user(user) is None:
        return JSONResponse({"ok": False}, status_code=404)
    user = session.get(User, user.id)
    old = user.tour_seen_at.isoformat() if user.tour_seen_at else None
    user.tour_seen_at = now_utc()
    create_audit_log(session, request, user, "tour.seen", "user", user.id, user.employee_name,
                     old_value={"tour_seen_at": old}, new_value={"tour_seen_at": user.tour_seen_at.isoformat()})
    session.commit()
    return {"ok": True}

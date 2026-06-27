from fastapi import Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from database import SessionLocal
from models import User


class RedirectException(Exception):
    def __init__(self, url: str, status_code: int = 302):
        self.url = url
        self.status_code = status_code


def redirect_exception_response(exc: RedirectException):
    return RedirectResponse(url=exc.url, status_code=exc.status_code)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def current_user(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        raise RedirectException("/login")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise RedirectException("/login")

    return user




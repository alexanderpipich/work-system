from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from dependencies import get_db
from models import User
from rbac import ROLE_HEADHUNTER, canonical_role, is_superadmin
from utils import normalize_phone, verify_password


router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/")
def root():
    return RedirectResponse(url="/login", status_code=302)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(
        request,
        "login.html",
        {"error": None}
    )


@router.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    phone: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_db),
):
    phone_clean = normalize_phone(phone)
    password_clean = str(password).strip()

    user = session.query(User).filter(User.phone == phone_clean).first()

    if not user or not verify_password(password_clean, user.password_hash):
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Неверный телефон или пароль"}
        )

    request.session["user_id"] = user.id

    if is_superadmin(user):
        return RedirectResponse(url="/admin", status_code=302)

    if canonical_role(user) in {"hr_lead", "hr_manager"}:
        return RedirectResponse(url="/hr", status_code=302)

    if user.role == "economist":
        return RedirectResponse(url="/economist", status_code=302)

    if user.role == "brigadier":
        return RedirectResponse(url="/brigadier", status_code=302)

    if canonical_role(user) == ROLE_HEADHUNTER:
        return RedirectResponse(url="/headhunter", status_code=302)

    return RedirectResponse(url="/cabinet", status_code=302)


@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)



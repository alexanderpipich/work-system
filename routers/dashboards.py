from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from access import get_economist_cities
from dependencies import require_admin_user, require_economist_user


router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request, admin=Depends(require_admin_user)):
    return templates.TemplateResponse(
        request,
        "admin_dashboard.html",
        {"admin": admin}
    )


@router.get("/economist", response_class=HTMLResponse)
def economist_dashboard(request: Request, user=Depends(require_economist_user)):
    return templates.TemplateResponse(
        request,
        "economist_dashboard.html",
        {
            "user": user,
            "allowed_cities": get_economist_cities(user)
        }
    )

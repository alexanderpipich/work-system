from fastapi import APIRouter, Depends, Request
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import FileResponse

from dependencies import require_admin_user


router = APIRouter()


@router.get("/docs", include_in_schema=False)
def admin_docs(admin=Depends(require_admin_user)):
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="Work System API",
    )


@router.get("/redoc", include_in_schema=False)
def admin_redoc(admin=Depends(require_admin_user)):
    return get_redoc_html(
        openapi_url="/openapi.json",
        title="Work System API",
    )


@router.get("/openapi.json", include_in_schema=False)
def admin_openapi(
    request: Request,
    admin=Depends(require_admin_user),
):
    return request.app.openapi()


@router.get("/favicon.ico", include_in_schema=False)
def favicon():
    return FileResponse("static/favicon.ico", media_type="image/x-icon")
from pathlib import Path
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy.orm import Session

from audit_helpers import create_audit_log
from dependencies import current_user, get_db
from document_helpers import document_file_exists, save_upload_file
from models import User
from rbac import has_permission, require_permission
from utils import normalize_text


router = APIRouter()
require_user_management = require_permission("users.manage", audit_denied=True)

# QR — только изображения (без pdf/heic, которые допускает общий save_upload_file).
QR_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png"}
_QR_MEDIA_TYPES = {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png"}


def _users_redirect(user_id, filters):
    """Назад в список на этого сотрудника, сохранив фильтры (как в update_user)."""
    query = {key: value for key, value in (filters or {}).items() if value}
    url = "/admin/users"
    if query:
        url = f"{url}?{urlencode(query)}"
    return RedirectResponse(url=f"{url}#user-{user_id}", status_code=302)


@router.post("/admin/users/{user_id}/qr")
async def upload_qr(
    request: Request,
    user_id: int,
    qr_image: UploadFile = File(...),
    f_user_id: str = Form(default=""),
    f_phone: str = Form(default=""),
    f_employee_name: str = Form(default=""),
    f_role: str = Form(default=""),
    session: Session = Depends(get_db),
    admin=Depends(require_user_management),
):
    filters = {"user_id": f_user_id, "phone": f_phone, "employee_name": f_employee_name, "role": f_role}
    user = session.query(User).filter(User.id == user_id).first()
    if not user:
        return _users_redirect(user_id, filters)

    if not qr_image or not qr_image.filename:
        return _users_redirect(user_id, filters)

    if Path(qr_image.filename).suffix.lower() not in QR_IMAGE_EXTENSIONS:
        # Только изображения; молча возвращаемся (валидация типа).
        return _users_redirect(user_id, filters)

    try:
        stored_path, _ = await save_upload_file(qr_image, folder="qr", prefix=f"qr_{user_id}")
    except ValueError:
        return _users_redirect(user_id, filters)

    if not stored_path:
        return _users_redirect(user_id, filters)

    old_path = user.qr_image_path
    user.qr_image_path = stored_path
    create_audit_log(
        session, request, admin, "user_qr_uploaded", "user", user.id, user.employee_name,
        old_value={"qr_image_path": old_path}, new_value={"qr_image_path": stored_path},
    )
    session.commit()
    return _users_redirect(user_id, filters)


@router.post("/admin/users/{user_id}/qr/delete")
def delete_qr(
    request: Request,
    user_id: int,
    f_user_id: str = Form(default=""),
    f_phone: str = Form(default=""),
    f_employee_name: str = Form(default=""),
    f_role: str = Form(default=""),
    session: Session = Depends(get_db),
    admin=Depends(require_user_management),
):
    filters = {"user_id": f_user_id, "phone": f_phone, "employee_name": f_employee_name, "role": f_role}
    user = session.query(User).filter(User.id == user_id).first()
    if not user or not user.qr_image_path:
        return _users_redirect(user_id, filters)

    old_path = user.qr_image_path
    # Убираем файл с диска (best-effort) и очищаем поле.
    if document_file_exists(old_path):
        try:
            Path(old_path).unlink()
        except OSError:
            pass
    user.qr_image_path = None
    create_audit_log(
        session, request, admin, "user_qr_deleted", "user", user.id, user.employee_name,
        old_value={"qr_image_path": old_path}, new_value={"qr_image_path": None},
    )
    session.commit()
    return _users_redirect(user_id, filters)


@router.get("/users/{user_id}/qr")
def serve_qr(
    user_id: int,
    session: Session = Depends(get_db),
    viewer=Depends(current_user),
):
    """Отдаёт QR inline. Доступ: сам сотрудник — свой; HR/админ (employees.view) — любой."""
    user = session.query(User).filter(User.id == user_id).first()
    if not user or not user.qr_image_path:
        return RedirectResponse(url="/", status_code=302)

    is_self = viewer.id == user.id
    if not (is_self or has_permission(viewer, "employees.view")):
        return RedirectResponse(url="/", status_code=302)

    if not document_file_exists(user.qr_image_path):
        return RedirectResponse(url="/", status_code=302)

    ext = Path(user.qr_image_path).suffix.lower()
    filename = normalize_text(user.employee_name).replace('"', "") or f"qr_{user_id}"
    return FileResponse(
        Path(user.qr_image_path),
        media_type=_QR_MEDIA_TYPES.get(ext, "application/octet-stream"),
        headers={
            "Content-Disposition": f"inline; filename*=UTF-8''{quote(f'QR_{filename}{ext}')}",
            "X-Content-Type-Options": "nosniff",
        },
    )

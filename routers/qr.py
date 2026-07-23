from pathlib import Path
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy.orm import Session

from audit_helpers import create_audit_log
from dependencies import current_user, get_db
from document_helpers import document_file_exists, save_upload_file
from models import EmployeeQr, User
from rbac import has_permission, require_permission
from utils import normalize_text


router = APIRouter()
require_user_management = require_permission("users.manage", audit_denied=True)

# QR — только изображения (без pdf/heic, которые допускает общий save_upload_file).
QR_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png"}
_QR_MEDIA_TYPES = {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png"}

MAX_QR_PER_USER = 3  # до 3 QR на сотрудника (несколько специальностей)


def next_qr_sort_order(session, user_id):
    """Следующий sort_order для нового QR сотрудника (в конец)."""
    orders = [q.sort_order or 0 for q in
              session.query(EmployeeQr).filter(EmployeeQr.user_id == user_id).all()]
    return (max(orders) + 1) if orders else 0


def _users_redirect(user_id, filters, error=None, message=None):
    """Назад в список на этого сотрудника, сохранив фильтры (как в update_user)."""
    query = {key: value for key, value in (filters or {}).items() if value}
    if error:
        query["error"] = error
    if message:
        query["message"] = message
    url = "/admin/users"
    if query:
        url = f"{url}?{urlencode(query)}"
    return RedirectResponse(url=f"{url}#user-{user_id}", status_code=302)


def _qr_access_allowed(viewer, owner_id):
    """Доступ к картинке QR: сам сотрудник — свой; HR/админ (employees.view) — любой."""
    return viewer.id == owner_id or has_permission(viewer, "employees.view")


def _serve_image(path, download_name):
    """Общая отдача изображения inline с nosniff."""
    if not document_file_exists(path):
        return RedirectResponse(url="/", status_code=302)
    ext = Path(path).suffix.lower()
    return FileResponse(
        Path(path),
        media_type=_QR_MEDIA_TYPES.get(ext, "application/octet-stream"),
        headers={
            "Content-Disposition": f"inline; filename*=UTF-8''{quote(f'{download_name}{ext}')}",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post("/admin/users/{user_id}/qr")
async def upload_qr(
    request: Request,
    user_id: int,
    qr_image: UploadFile = File(...),
    label: str = Form(default=""),
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
        return _users_redirect(user_id, filters, error="QR: только изображения PNG/JPG")

    # Ограничение — до 3 QR на сотрудника.
    count = session.query(EmployeeQr).filter(EmployeeQr.user_id == user_id).count()
    if count >= MAX_QR_PER_USER:
        return _users_redirect(user_id, filters, error=f"У сотрудника уже {MAX_QR_PER_USER} QR — удалите лишний")

    try:
        stored_path, _ = await save_upload_file(qr_image, folder="qr", prefix=f"qr_{user_id}")
    except ValueError:
        return _users_redirect(user_id, filters, error="QR: недопустимый формат файла")

    if not stored_path:
        return _users_redirect(user_id, filters)

    qr = EmployeeQr(
        user_id=user_id,
        image_path=stored_path,
        label=normalize_text(label) or None,
        sort_order=next_qr_sort_order(session, user_id),
    )
    session.add(qr)
    session.flush()
    create_audit_log(
        session, request, admin, "user_qr_uploaded", "user", user.id, user.employee_name,
        new_value={"qr_id": qr.id, "image_path": stored_path, "label": qr.label},
    )
    session.commit()
    return _users_redirect(user_id, filters, message="QR добавлен")


@router.post("/admin/users/{user_id}/qr/{qr_id}/label")
def edit_qr_label(
    request: Request,
    user_id: int,
    qr_id: int,
    label: str = Form(default=""),
    f_user_id: str = Form(default=""),
    f_phone: str = Form(default=""),
    f_employee_name: str = Form(default=""),
    f_role: str = Form(default=""),
    session: Session = Depends(get_db),
    admin=Depends(require_user_management),
):
    filters = {"user_id": f_user_id, "phone": f_phone, "employee_name": f_employee_name, "role": f_role}
    qr = session.query(EmployeeQr).filter(
        EmployeeQr.id == qr_id, EmployeeQr.user_id == user_id
    ).first()
    if not qr:
        return _users_redirect(user_id, filters)

    old_label = qr.label
    qr.label = normalize_text(label) or None
    create_audit_log(
        session, request, admin, "user_qr_label_updated", "user", user_id, f_employee_name or str(user_id),
        old_value={"label": old_label}, new_value={"label": qr.label},
    )
    session.commit()
    return _users_redirect(user_id, filters, message="Подпись обновлена")


@router.post("/admin/users/{user_id}/qr/{qr_id}/delete")
def delete_qr_by_id(
    request: Request,
    user_id: int,
    qr_id: int,
    f_user_id: str = Form(default=""),
    f_phone: str = Form(default=""),
    f_employee_name: str = Form(default=""),
    f_role: str = Form(default=""),
    session: Session = Depends(get_db),
    admin=Depends(require_user_management),
):
    filters = {"user_id": f_user_id, "phone": f_phone, "employee_name": f_employee_name, "role": f_role}
    qr = session.query(EmployeeQr).filter(
        EmployeeQr.id == qr_id, EmployeeQr.user_id == user_id
    ).first()
    if not qr:
        return _users_redirect(user_id, filters)

    old_path = qr.image_path
    if document_file_exists(old_path):
        try:
            Path(old_path).unlink()
        except OSError:
            pass
    session.delete(qr)
    create_audit_log(
        session, request, admin, "user_qr_deleted", "user", user_id, f_employee_name or str(user_id),
        old_value={"qr_id": qr_id, "image_path": old_path},
    )
    session.commit()
    return _users_redirect(user_id, filters, message="QR удалён")


@router.get("/users/{user_id}/qr/{qr_id}")
def serve_qr_by_id(
    user_id: int,
    qr_id: int,
    session: Session = Depends(get_db),
    viewer=Depends(current_user),
):
    """Отдаёт конкретный QR inline. Доступ: сам сотрудник — свой; HR/админ — любой."""
    if not _qr_access_allowed(viewer, user_id):
        return RedirectResponse(url="/", status_code=302)
    qr = session.query(EmployeeQr).filter(
        EmployeeQr.id == qr_id, EmployeeQr.user_id == user_id
    ).first()
    if not qr:
        return RedirectResponse(url="/", status_code=302)
    name = normalize_text(qr.label) or f"qr_{qr_id}"
    return _serve_image(qr.image_path, f"QR_{name}")


@router.post("/admin/users/{user_id}/qr/delete")
def delete_qr_legacy(
    request: Request,
    user_id: int,
    f_user_id: str = Form(default=""),
    f_phone: str = Form(default=""),
    f_employee_name: str = Form(default=""),
    f_role: str = Form(default=""),
    session: Session = Depends(get_db),
    admin=Depends(require_user_management),
):
    """Legacy: удаление единичного qr_image_path (для QR, ещё не перенесённых в employee_qr)."""
    filters = {"user_id": f_user_id, "phone": f_phone, "employee_name": f_employee_name, "role": f_role}
    user = session.query(User).filter(User.id == user_id).first()
    if not user or not user.qr_image_path:
        return _users_redirect(user_id, filters)

    old_path = user.qr_image_path
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
    return _users_redirect(user_id, filters, message="QR удалён")


@router.get("/users/{user_id}/qr")
def serve_qr(
    user_id: int,
    session: Session = Depends(get_db),
    viewer=Depends(current_user),
):
    """Legacy отдача единичного qr_image_path (fallback, пока не перенесён в employee_qr)."""
    user = session.query(User).filter(User.id == user_id).first()
    if not user or not user.qr_image_path:
        return RedirectResponse(url="/", status_code=302)
    if not _qr_access_allowed(viewer, user.id):
        return RedirectResponse(url="/", status_code=302)
    filename = normalize_text(user.employee_name).replace('"', "") or f"qr_{user_id}"
    return _serve_image(user.qr_image_path, f"QR_{filename}")

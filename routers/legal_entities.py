from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from audit_helpers import create_audit_log
from dependencies import get_db, require_admin_user, require_economist_user
from models import LegalEntity
from rbac import has_permission, record_denied_action, require_permission
from time_helpers import now_utc
from utils import normalize_text


router = APIRouter()
templates = Jinja2Templates(directory="templates")
require_legal_entity_hard_delete = require_permission("legal_entities.hard_delete", audit_denied=True)


def _redirect(base_path="/admin/legal-entities", **params):
    query = {key: value for key, value in params.items() if value}
    url = base_path
    if query:
        url = f"{url}?{urlencode(query)}"
    return RedirectResponse(url=url, status_code=302)


def _render_page(request, session, user, base_path, back_url, message="", error=""):
    entities = (
        session.query(LegalEntity)
        .order_by(LegalEntity.is_active.desc(), LegalEntity.name.asc())
        .all()
    )
    return templates.TemplateResponse(
        request,
        "legal_entities.html",
        {
            "admin": user,
            "entities": entities,
            "base_path": base_path,
            "back_url": back_url,
            "users_url": "/admin/users" if base_path.startswith("/admin") else None,
            "message": message or None,
            "error": error or None,
            "can_hard_delete": has_permission(user, "legal_entities.hard_delete"),
        },
    )


def _entity_payload(entity):
    return {
        "name": entity.name,
        "short_name": entity.short_name,
        "inn": entity.inn,
        "comment": entity.comment,
        "is_active": entity.is_active,
    }


def _add_entity(session, request, user, base_path, name, short_name, inn, comment):
    name_clean = normalize_text(name)
    if not name_clean:
        return _redirect(base_path, error="Название юрлица обязательно")

    entity = LegalEntity(
        name=name_clean,
        short_name=normalize_text(short_name) or None,
        inn=normalize_text(inn) or None,
        comment=normalize_text(comment) or None,
        is_active=True,
        created_at=now_utc(),
    )
    session.add(entity)
    session.flush()
    create_audit_log(
        session,
        request,
        user,
        "legal_entity_created",
        "legal_entity",
        entity.id,
        entity.name,
        new_value=_entity_payload(entity),
    )
    session.commit()
    return _redirect(base_path, message="Юрлицо добавлено")


def _update_entity(session, request, user, base_path, entity_id, name, short_name, inn, comment, is_active):
    entity = session.query(LegalEntity).filter(LegalEntity.id == entity_id).first()
    if not entity:
        return _redirect(base_path, error="Юрлицо не найдено")

    name_clean = normalize_text(name)
    if not name_clean:
        return _redirect(base_path, error="Название юрлица обязательно")

    old_value = _entity_payload(entity)
    entity.name = name_clean
    entity.short_name = normalize_text(short_name) or None
    entity.inn = normalize_text(inn) or None
    entity.comment = normalize_text(comment) or None
    entity.is_active = is_active == "1"
    entity.updated_at = now_utc()
    create_audit_log(
        session,
        request,
        user,
        "legal_entity_updated",
        "legal_entity",
        entity.id,
        entity.name,
        old_value=old_value,
        new_value=_entity_payload(entity),
    )
    session.commit()
    return _redirect(base_path, message="Юрлицо обновлено")


def _set_entity_active(session, request, user, base_path, entity_id, is_active):
    entity = session.query(LegalEntity).filter(LegalEntity.id == entity_id).first()
    if not entity:
        return _redirect(base_path, error="Юрлицо не найдено")

    old_value = _entity_payload(entity)
    entity.is_active = is_active
    entity.updated_at = now_utc()
    create_audit_log(
        session,
        request,
        user,
        "legal_entity_activated" if is_active else "legal_entity_deactivated",
        "legal_entity",
        entity.id,
        entity.name,
        old_value=old_value,
        new_value=_entity_payload(entity),
    )
    session.commit()
    return _redirect(
        base_path,
        message="Юрлицо активировано" if is_active else "Юрлицо деактивировано",
    )


def _remove_entity(session, request, user, base_path, entity_id):
    entity = session.query(LegalEntity).filter(LegalEntity.id == entity_id).first()
    if not entity:
        return _redirect(base_path, error="Юрлицо не найдено")

    old_value = _entity_payload(entity)
    entity_id_value = entity.id
    entity_name = entity.name
    create_audit_log(
        session,
        request,
        user,
        "legal_entity_deleted",
        "legal_entity",
        entity_id_value,
        entity_name,
        old_value=old_value,
    )
    session.delete(entity)
    session.commit()
    return _redirect(base_path, message="Юрлицо удалено")


@router.get("/admin/legal-entities", response_class=HTMLResponse)
def legal_entities_page(
    request: Request,
    message: str = "",
    error: str = "",
    session: Session = Depends(get_db),
    admin=Depends(require_admin_user),
):
    return _render_page(
        request,
        session,
        admin,
        "/admin/legal-entities",
        "/admin",
        message=message,
        error=error,
    )


@router.get("/economist/legal-entities", response_class=HTMLResponse)
def economist_legal_entities_page(
    request: Request,
    message: str = "",
    error: str = "",
    session: Session = Depends(get_db),
    user=Depends(require_economist_user),
):
    return _render_page(
        request,
        session,
        user,
        "/economist/legal-entities",
        "/economist",
        message=message,
        error=error,
    )


@router.post("/admin/legal-entities/add")
def add_legal_entity(
    request: Request,
    name: str = Form(...),
    short_name: str = Form(default=""),
    inn: str = Form(default=""),
    comment: str = Form(default=""),
    session: Session = Depends(get_db),
    admin=Depends(require_admin_user),
):
    try:
        return _add_entity(
            session,
            request,
            admin,
            "/admin/legal-entities",
            name,
            short_name,
            inn,
            comment,
        )

    except Exception as exc:
        session.rollback()
        return _redirect("/admin/legal-entities", error=str(exc))


@router.post("/economist/legal-entities/add")
def economist_add_legal_entity(
    request: Request,
    name: str = Form(...),
    short_name: str = Form(default=""),
    inn: str = Form(default=""),
    comment: str = Form(default=""),
    session: Session = Depends(get_db),
    user=Depends(require_economist_user),
):
    try:
        return _add_entity(
            session,
            request,
            user,
            "/economist/legal-entities",
            name,
            short_name,
            inn,
            comment,
        )

    except Exception as exc:
        session.rollback()
        return _redirect("/economist/legal-entities", error=str(exc))


@router.post("/admin/legal-entities/update")
def update_legal_entity(
    request: Request,
    entity_id: int = Form(...),
    name: str = Form(...),
    short_name: str = Form(default=""),
    inn: str = Form(default=""),
    comment: str = Form(default=""),
    is_active: str = Form(default=""),
    session: Session = Depends(get_db),
    admin=Depends(require_admin_user),
):
    try:
        return _update_entity(
            session,
            request,
            admin,
            "/admin/legal-entities",
            entity_id,
            name,
            short_name,
            inn,
            comment,
            is_active,
        )

    except Exception as exc:
        session.rollback()
        return _redirect("/admin/legal-entities", error=str(exc))


@router.post("/economist/legal-entities/update")
def economist_update_legal_entity(
    request: Request,
    entity_id: int = Form(...),
    name: str = Form(...),
    short_name: str = Form(default=""),
    inn: str = Form(default=""),
    comment: str = Form(default=""),
    is_active: str = Form(default=""),
    session: Session = Depends(get_db),
    user=Depends(require_economist_user),
):
    try:
        return _update_entity(
            session,
            request,
            user,
            "/economist/legal-entities",
            entity_id,
            name,
            short_name,
            inn,
            comment,
            is_active,
        )

    except Exception as exc:
        session.rollback()
        return _redirect("/economist/legal-entities", error=str(exc))


@router.post("/admin/legal-entities/delete")
def delete_legal_entity(
    request: Request,
    entity_id: int = Form(...),
    hard_delete: str = Form(default=""),
    session: Session = Depends(get_db),
    admin=Depends(require_admin_user),
):
    if hard_delete == "1":
        return _remove_entity(session, request, admin, "/admin/legal-entities", entity_id)
    return _set_entity_active(session, request, admin, "/admin/legal-entities", entity_id, False)


@router.post("/admin/legal-entities/activate")
def activate_legal_entity(
    request: Request,
    entity_id: int = Form(...),
    session: Session = Depends(get_db),
    admin=Depends(require_admin_user),
):
    return _set_entity_active(session, request, admin, "/admin/legal-entities", entity_id, True)


@router.post("/admin/legal-entities/remove")
def remove_legal_entity(
    request: Request,
    entity_id: int = Form(...),
    session: Session = Depends(get_db),
    admin=Depends(require_legal_entity_hard_delete),
):
    return _remove_entity(session, request, admin, "/admin/legal-entities", entity_id)


@router.post("/economist/legal-entities/delete")
def economist_delete_legal_entity(
    request: Request,
    entity_id: int = Form(...),
    hard_delete: str = Form(default=""),
    session: Session = Depends(get_db),
    user=Depends(require_economist_user),
):
    if hard_delete == "1":
        if not has_permission(user, "legal_entities.hard_delete"):
            record_denied_action(session, request, user, "legal_entities.hard_delete")
            return _redirect(
                "/economist/legal-entities",
                error="Физическое удаление доступно только суперадминистратору",
            )
        return _remove_entity(session, request, user, "/economist/legal-entities", entity_id)
    return _set_entity_active(session, request, user, "/economist/legal-entities", entity_id, False)

@router.post("/economist/legal-entities/activate")
def economist_activate_legal_entity(
    request: Request,
    entity_id: int = Form(...),
    session: Session = Depends(get_db),
    user=Depends(require_economist_user),
):
    return _set_entity_active(session, request, user, "/economist/legal-entities", entity_id, True)


@router.post("/economist/legal-entities/remove")
def economist_remove_legal_entity(
    request: Request,
    entity_id: int = Form(...),
    session: Session = Depends(get_db),
    user=Depends(require_legal_entity_hard_delete),
):
    return _remove_entity(session, request, user, "/economist/legal-entities", entity_id)




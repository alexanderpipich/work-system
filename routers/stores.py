import json

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session

from audit_helpers import create_audit_log
from dependencies import get_db
from models import STORE_CONTACT_ROLES, Shift, Store, StoreContact
from rbac import require_permission
from store_helpers import extract_tk_number, migrate_legacy_store_settings, populate_stores_from_shifts
from time_helpers import now_utc

router = APIRouter()
templates = Jinja2Templates(directory="templates")

_view = require_permission("stores.view")
_manage = require_permission("stores.manage")


def _shift_tks(session: Session) -> set:
    rows = session.query(Shift.store).distinct().all()
    result = set()
    for (store_str,) in rows:
        tk = extract_tk_number(store_str)
        if tk is not None:
            result.add(tk)
    return result


# ── populate ─────────────────────────────────────────────────────────────────

@router.post("/admin/stores/migrate-legacy")
def admin_stores_migrate_legacy(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_manage),
):
    report = migrate_legacy_store_settings(session)
    return JSONResponse(report)


@router.post("/admin/stores/populate")
def admin_stores_populate(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_manage),
):
    report = populate_stores_from_shifts(session)
    return JSONResponse(report)


# ── list ──────────────────────────────────────────────────────────────────────

@router.get("/admin/stores", response_class=HTMLResponse)
def admin_stores_list(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_view),
    message: str = "",
    error: str = "",
):
    stores = session.query(Store).order_by(Store.tk_number.asc()).all()
    contact_counts = dict(
        session.query(StoreContact.store_id, func.count(StoreContact.id))
        .filter(StoreContact.is_active == True)
        .group_by(StoreContact.store_id)
        .all()
    )
    shift_tks = _shift_tks(session)
    return templates.TemplateResponse("admin_stores.html", {
        "request": request,
        "user": user,
        "stores": stores,
        "contact_counts": contact_counts,
        "shift_tks": shift_tks,
        "message": message,
        "error": error,
    })


# ── detail ────────────────────────────────────────────────────────────────────

@router.get("/admin/stores/{store_id}", response_class=HTMLResponse)
def admin_store_detail(
    store_id: int,
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_view),
    message: str = "",
    error: str = "",
):
    store = session.query(Store).filter(Store.id == store_id).first()
    if not store:
        return RedirectResponse("/admin/stores", status_code=302)
    contacts = (
        session.query(StoreContact)
        .filter(StoreContact.store_id == store_id, StoreContact.is_active == True)
        .order_by(StoreContact.id.asc())
        .all()
    )
    return templates.TemplateResponse("admin_store_detail.html", {
        "request": request,
        "user": user,
        "store": store,
        "contacts": contacts,
        "roles": STORE_CONTACT_ROLES,
        "message": message,
        "error": error,
    })


# ── add store ─────────────────────────────────────────────────────────────────

@router.post("/admin/stores/add")
def admin_stores_add(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_manage),
    tk_number: int = Form(...),
    display_name: str = Form(""),
    city: str = Form(""),
    format: str = Form(""),
    object_address: str = Form(""),
    comment: str = Form(""),
):
    if session.query(Store).filter(Store.tk_number == tk_number).first():
        return RedirectResponse(
            f"/admin/stores?error=ТК {tk_number} уже существует", status_code=302
        )
    store = Store(
        tk_number=tk_number,
        display_name=display_name.strip() or None,
        city=city.strip() or None,
        format=format.strip() or None,
        object_address=object_address.strip() or None,
        comment=comment.strip() or None,
        created_at=now_utc(),
    )
    session.add(store)
    session.flush()
    create_audit_log(
        session, request, user, "create", "store",
        entity_id=str(store.id),
        entity_name=display_name or str(tk_number),
    )
    session.commit()
    return RedirectResponse(f"/admin/stores/{store.id}?message=Магазин создан", status_code=302)


# ── update store ──────────────────────────────────────────────────────────────

@router.post("/admin/stores/{store_id}/update")
def admin_store_update(
    store_id: int,
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_manage),
    display_name: str = Form(""),
    city: str = Form(""),
    format: str = Form(""),
    object_address: str = Form(""),
    comment: str = Form(""),
    is_active: str = Form(""),
):
    store = session.query(Store).filter(Store.id == store_id).first()
    if not store:
        return RedirectResponse("/admin/stores", status_code=302)
    old = {"display_name": store.display_name, "city": store.city,
           "format": store.format, "object_address": store.object_address,
           "is_active": store.is_active}
    if display_name.strip():
        store.display_name = display_name.strip()
    if city.strip():
        store.city = city.strip()
    if format.strip():
        store.format = format.strip()
    store.object_address = object_address.strip() or None
    store.comment = comment.strip() or None
    store.is_active = is_active == "1"
    store.updated_at = now_utc()
    new = {"display_name": store.display_name, "city": store.city,
           "format": store.format, "object_address": store.object_address,
           "is_active": store.is_active}
    create_audit_log(
        session, request, user, "update", "store",
        entity_id=str(store_id), entity_name=store.display_name,
        old_value=json.dumps(old, ensure_ascii=False),
        new_value=json.dumps(new, ensure_ascii=False),
    )
    session.commit()
    return RedirectResponse(f"/admin/stores/{store_id}?message=Сохранено", status_code=302)


# ── add contact ───────────────────────────────────────────────────────────────

@router.post("/admin/stores/{store_id}/contacts/add")
def admin_store_contact_add(
    store_id: int,
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_manage),
    email: str = Form(...),
    role: str = Form("other"),
    name: str = Form(""),
    for_planning: str = Form(""),
    for_reconciliation: str = Form(""),
    for_unplanned: str = Form(""),
):
    if not session.query(Store).filter(Store.id == store_id).first():
        return RedirectResponse("/admin/stores", status_code=302)
    contact = StoreContact(
        store_id=store_id,
        email=email.strip(),
        role=role if role in STORE_CONTACT_ROLES else "other",
        name=name.strip() or None,
        for_planning=for_planning == "1",
        for_reconciliation=for_reconciliation == "1",
        for_unplanned=for_unplanned == "1",
    )
    session.add(contact)
    session.flush()
    create_audit_log(
        session, request, user, "create", "store_contact",
        entity_id=str(contact.id), entity_name=email,
        comment=f"store_id={store_id}",
    )
    session.commit()
    return RedirectResponse(f"/admin/stores/{store_id}?message=Контакт добавлен", status_code=302)


# ── update contact ────────────────────────────────────────────────────────────

@router.post("/admin/stores/{store_id}/contacts/{contact_id}/update")
def admin_store_contact_update(
    store_id: int,
    contact_id: int,
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_manage),
    email: str = Form(...),
    role: str = Form("other"),
    name: str = Form(""),
    for_planning: str = Form(""),
    for_reconciliation: str = Form(""),
    for_unplanned: str = Form(""),
):
    contact = session.query(StoreContact).filter(
        StoreContact.id == contact_id,
        StoreContact.store_id == store_id,
    ).first()
    if not contact:
        return RedirectResponse(f"/admin/stores/{store_id}", status_code=302)
    old = {"email": contact.email, "role": contact.role, "name": contact.name,
           "for_planning": contact.for_planning, "for_reconciliation": contact.for_reconciliation,
           "for_unplanned": contact.for_unplanned}
    contact.email = email.strip()
    contact.role = role if role in STORE_CONTACT_ROLES else "other"
    contact.name = name.strip() or None
    contact.for_planning = for_planning == "1"
    contact.for_reconciliation = for_reconciliation == "1"
    contact.for_unplanned = for_unplanned == "1"
    new = {"email": contact.email, "role": contact.role, "name": contact.name,
           "for_planning": contact.for_planning, "for_reconciliation": contact.for_reconciliation,
           "for_unplanned": contact.for_unplanned}
    create_audit_log(
        session, request, user, "update", "store_contact",
        entity_id=str(contact_id), entity_name=email,
        old_value=json.dumps(old, ensure_ascii=False),
        new_value=json.dumps(new, ensure_ascii=False),
    )
    session.commit()
    return RedirectResponse(f"/admin/stores/{store_id}?message=Контакт обновлён", status_code=302)


# ── delete contact ────────────────────────────────────────────────────────────

@router.post("/admin/stores/{store_id}/contacts/{contact_id}/delete")
def admin_store_contact_delete(
    store_id: int,
    contact_id: int,
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_manage),
):
    contact = session.query(StoreContact).filter(
        StoreContact.id == contact_id,
        StoreContact.store_id == store_id,
    ).first()
    if contact:
        contact.is_active = False
        create_audit_log(
            session, request, user, "delete", "store_contact",
            entity_id=str(contact_id), entity_name=contact.email,
            comment=f"store_id={store_id}",
        )
        session.commit()
    return RedirectResponse(f"/admin/stores/{store_id}?message=Контакт удалён", status_code=302)

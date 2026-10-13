"""Справочник регионов (П4): CRUD для кадровика, HR-руководителя, суперадмина."""

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from audit_helpers import create_audit_log
from dependencies import get_db
from models import Region
from rbac import require_permission
from region_helpers import REGION_FIELDS, missing_petition_fields
from utils import normalize_text

router = APIRouter()
templates = Jinja2Templates(directory="templates")
_regions_manage = require_permission("regions.manage")


def _redirect(**params):
    query = {k: v for k, v in params.items() if v}
    return RedirectResponse("/admin/regions" + (f"?{urlencode(query)}" if query else ""), status_code=302)


@router.get("/admin/regions", response_class=HTMLResponse)
def regions_page(request: Request, message: str = "", error: str = "",
                 session: Session = Depends(get_db), user=Depends(_regions_manage)):
    regions = session.query(Region).order_by(Region.is_active.desc(), Region.name.asc()).all()
    return templates.TemplateResponse(request, "regions.html", {
        "regions": regions,
        "missing": {r.id: missing_petition_fields(r) for r in regions},
        "message": message or None,
        "error": error or None,
    })


def save_region_fields(session, request, user, region, form):
    """Записать поля региона из формы (только присланные). Возвращает ошибку или None."""
    old_value = {f: getattr(region, f) for f in REGION_FIELDS} if region.id else None
    for field in REGION_FIELDS:
        if field in form:
            setattr(region, field, normalize_text(form.get(field)) or None)
    if "is_active" in form:
        region.is_active = form.get("is_active") == "1"
    if not region.name:
        return "Название региона обязательно"
    duplicate = session.query(Region).filter(Region.name == region.name, Region.id != region.id).first()
    if duplicate:
        return "Регион «%s» уже есть" % region.name
    session.add(region)
    session.flush()
    create_audit_log(session, request, user, "region_updated" if old_value else "region_created", "region",
                     region.id, region.name, old_value=old_value,
                     new_value={f: getattr(region, f) for f in REGION_FIELDS})
    return None


@router.post("/admin/regions/save")
async def regions_save(request: Request, session: Session = Depends(get_db), user=Depends(_regions_manage)):
    form = await request.form()
    region_id = int(form.get("region_id") or 0)
    region = session.query(Region).filter(Region.id == region_id).first() if region_id else Region(is_active=True)
    if region is None:
        return _redirect(error="Регион не найден")
    error = save_region_fields(session, request, user, region, form)
    if error:
        session.rollback()
        return _redirect(error=error)
    session.commit()
    return _redirect(message="Регион сохранён")

"""Справочник «Подразделения МВД» — адресаты ходатайств и уведомлений (/admin/mvd-authorities).

Права — как у «Регионов» (regions.manage). Список сгруппирован по регионам; карточка — одна форма.
Подразделение по умолчанию — одно на регион (mvd_authorities.set_region_default). Удаления нет —
подразделение деактивируют. Подбор адресата для сотрудника — mvd_authorities.authority_for_work.
"""

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from audit_helpers import create_audit_log
from dependencies import get_db
from models import MvdAuthority, Region
from mvd_authorities import MVD_FIELDS, missing_petition_fields, set_region_default, stores_by_authority
from rbac import require_permission
from time_helpers import now_utc
from utils import normalize_text

router = APIRouter()
templates = Jinja2Templates(directory="templates")
URL = "/admin/mvd-authorities"
_regions_manage = require_permission("regions.manage")
TRACKED = MVD_FIELDS + ("region_id", "is_region_default", "is_active")


def _redirect(entity=0, **params):
    query = {k: v for k, v in {**params, "entity": entity}.items() if v}
    anchor = f"#mvd-{entity}" if entity else ""
    return RedirectResponse(URL + (f"?{urlencode(query)}" if query else "") + anchor, status_code=302)


@router.get(URL, response_class=HTMLResponse)
def mvd_authorities_page(request: Request, message: str = "", error: str = "", entity: int = 0,
                         session: Session = Depends(get_db), user=Depends(_regions_manage)):
    regions = session.query(Region).order_by(Region.is_active.desc(), Region.name).all()
    authorities = session.query(MvdAuthority).order_by(
        MvdAuthority.is_region_default.desc(), MvdAuthority.is_active.desc(), MvdAuthority.name).all()
    groups = [{"region": region, "authorities": [a for a in authorities if a.region_id == region.id]}
              for region in regions]
    known = {region.id for region in regions}
    orphans = [a for a in authorities if a.region_id not in known]
    if orphans:
        groups.append({"region": None, "authorities": orphans})
    return templates.TemplateResponse(request, "mvd_authorities.html", {
        "groups": groups,
        "regions": regions,
        "missing": {a.id: missing_petition_fields(a) for a in authorities},
        "stores": stores_by_authority(session),
        "open_entity": entity,
        "message": message or None,
        "error": error or None,
    })


@router.post(URL + "/save")
async def mvd_authority_save(request: Request, session: Session = Depends(get_db), user=Depends(_regions_manage)):
    form = await request.form()
    authority_id = int(form.get("authority_id") or 0)
    authority = session.get(MvdAuthority, authority_id) if authority_id else MvdAuthority(is_active=True,
                                                                                         is_region_default=False)
    if authority is None:
        return _redirect(error="Подразделение не найдено")
    before = {field: getattr(authority, field) for field in TRACKED} if authority_id else {}
    for field in MVD_FIELDS:
        if field in form:
            setattr(authority, field, normalize_text(form.get(field)) or None)
    if not authority.name:
        return _redirect(authority_id, error="Краткое наименование обязательно")
    duplicate = session.query(MvdAuthority).filter(MvdAuthority.name == authority.name,
                                                   MvdAuthority.id != (authority.id or 0)).first()
    if duplicate:
        return _redirect(authority_id, error=f"Подразделение «{authority.name}» уже есть")
    region_id = int(form.get("region_id") or 0)
    if region_id and session.get(Region, region_id) is None:
        return _redirect(authority_id, error="Регион не найден")
    authority.region_id = region_id or None
    authority.is_region_default = form.get("is_region_default") == "1"
    if "is_active" in form:
        authority.is_active = form.get("is_active") == "1"
    session.add(authority)
    session.flush()
    for other in set_region_default(session, authority):
        create_audit_log(session, request, user, "mvd_authority.updated", "mvd_authority", other.id, other.name,
                         old_value={"is_region_default": True}, new_value={"is_region_default": False},
                         comment=f"по умолчанию теперь {authority.name}")
    after = {field: getattr(authority, field) for field in TRACKED}
    changed = [field for field in TRACKED if before.get(field) != after[field]] if authority_id else list(TRACKED)
    if authority_id and not changed:
        session.commit()
        return _redirect(authority.id, message="Изменений нет")
    authority.updated_at = now_utc()
    create_audit_log(session, request, user, "mvd_authority.updated" if authority_id else "mvd_authority.created",
                     "mvd_authority", authority.id, authority.name,
                     old_value={f: before[f] for f in changed} if authority_id else None,
                     new_value={f: after[f] for f in changed})
    session.commit()
    return _redirect(authority.id, message="Подразделение сохранено" if authority_id else "Подразделение добавлено")

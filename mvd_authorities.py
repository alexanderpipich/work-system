"""Подразделения МВД — адресаты ходатайств и уведомлений (справочник /admin/mvd-authorities).

Адресат для сотрудника (`authority_for_work`) — по основному магазину за 14 дней
(`contract_data.recent_work`):
1. подразделение, закреплённое в карточке магазина (`Store.mvd_authority_id`);
2. подразделение региона магазина, в `cities` которого есть город магазина (`Store.city`);
3. подразделение по умолчанию региона магазина (`is_region_default`);
4. не нашлось (смен нет, магазина нет в справочнике, регион ТК не определён) — подразделение
   по умолчанию региона сотрудника (по городу последних смен — как раньше брался адресат региона);
иначе пусто — выбрать в форме.

Регион магазина — по `Store.city`, затем по тарифному региону (`region_helpers.region_for_city`).
"""

import json

from sqlalchemy import text

from models import MvdAuthority, Region, Store
from region_helpers import city_key, region_for_city
from utils import normalize_text

MVD_FIELDS = ("name", "addressee_dative", "chief_rank_dative", "chief_name_dative", "chief_name",
              "address", "cities", "comment")
# Без этих полей ходатайство уйдёт с «НЕТ ДАННЫХ» в шапке «КОМУ».
PETITION_MVD_FIELDS = ("addressee_dative", "chief_rank_dative", "chief_name_dative")


def ensure_mvd_authority_columns(engine):
    """Postgres: колонка закрепления у магазина (таблицу mvd_authorities создаёт create_all)."""
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE stores ADD COLUMN IF NOT EXISTS mvd_authority_id INTEGER"))


def active_authorities(session):
    """Активные подразделения: по региону, внутри — по умолчанию первым, затем по имени."""
    return session.query(MvdAuthority).filter(MvdAuthority.is_active == True).order_by(  # noqa: E712
        MvdAuthority.region_id, MvdAuthority.is_region_default.desc(), MvdAuthority.name).all()


def authority_cities(authority):
    return {city_key(c) for c in (authority.cities or "").split(",") if normalize_text(c)}


def region_default(session, region):
    if region is None:
        return None
    return session.query(MvdAuthority).filter(
        MvdAuthority.region_id == region.id, MvdAuthority.is_region_default == True,  # noqa: E712
        MvdAuthority.is_active == True).order_by(MvdAuthority.id).first()  # noqa: E712


def store_region(session, store):
    return region_for_city(session, store.city) or region_for_city(session, store.rate_region)


def authority_for_store(session, store):
    """(подразделение, как выбрано) для магазина; (None, причина) — не нашлось."""
    if store.mvd_authority_id:
        authority = session.get(MvdAuthority, store.mvd_authority_id)
        if authority is not None and authority.is_active:
            return authority, "закреплено в карточке магазина"
    region = store_region(session, store)
    if region is None:
        return None, "регион магазина не определён по городу"
    key = city_key(store.city)
    if key:
        for authority in session.query(MvdAuthority).filter(
                MvdAuthority.region_id == region.id, MvdAuthority.is_active == True).order_by(  # noqa: E712
                MvdAuthority.id).all():
            if key in authority_cities(authority):
                return authority, f"г. {normalize_text(store.city)}"
    authority = region_default(session, region)
    if authority is not None:
        return authority, f"по умолчанию региона «{region.name}»"
    return None, f"у региона «{region.name}» нет подразделения по умолчанию"


def authority_for_work(session, work, fallback_region=None):
    """(подразделение или None, подсказка) по основному магазину за 14 дней (work — recent_work)."""
    store = work["store"] if work else None
    if store is not None:
        authority, how = authority_for_store(session, store)
        if authority is not None:
            return authority, f"по {work['store_label']}, {how}"
        why = f"{work['store_label']}: {how}"
    else:
        why = f"{work['store_label']} нет в справочнике магазинов" if work else "смен за 14 дней нет"
    authority = region_default(session, fallback_region)
    if authority is not None:
        return authority, f"{why} — по умолчанию региона «{fallback_region.name}»"
    return None, f"{why} — выберите подразделение"


def set_region_default(session, authority):
    """Подразделение по умолчанию — одно на регион: снять флаг у остальных подразделений региона.
    Возвращает снятые подразделения (для аудита)."""
    if not authority.is_region_default or authority.region_id is None:
        return []
    others = session.query(MvdAuthority).filter(
        MvdAuthority.region_id == authority.region_id, MvdAuthority.id != authority.id,
        MvdAuthority.is_region_default == True).all()  # noqa: E712
    for other in others:
        other.is_region_default = False
    return others


def _json_names():
    """Имена подразделений из data/reference/mvd_authorities.json по имени региона —
    чтобы перенесённое из региона подразделение совпало с записью справочника (сид не задвоит)."""
    from reference_data import REFERENCE_DIR

    path = REFERENCE_DIR / "mvd_authorities.json"
    if not path.exists():
        return {}
    records = json.loads(path.read_text(encoding="utf-8"))
    return {r.get("region_name"): r["name"] for r in records if r.get("is_region_default")}


def migrate_region_addressees(session):
    """Перенос адресата УВМ из регионов: у региона с заполненными uvm_* и без подразделений —
    подразделение по умолчанию с этими данными. Идемпотентно. Коммит — на вызывающем."""
    names = _json_names()
    created = []
    for region in session.query(Region).order_by(Region.id).all():
        if not any(normalize_text(getattr(region, f)) for f in ("uvm_addressee", "uvm_rank", "uvm_person")):
            continue
        if session.query(MvdAuthority.id).filter(MvdAuthority.region_id == region.id).first():
            continue
        addressee = normalize_text(region.uvm_addressee)
        name = names.get(region.name) or (addressee[len("Начальнику "):] if addressee.startswith("Начальнику ")
                                          else addressee) or f"УВМ — {region.name}"
        if session.query(MvdAuthority.id).filter(MvdAuthority.name == name).first():
            name = f"{name} ({region.name})"
        authority = MvdAuthority(
            name=name, region_id=region.id, addressee_dative=addressee or None,
            chief_rank_dative=normalize_text(region.uvm_rank) or None,
            chief_name_dative=normalize_text(region.uvm_person) or None,
            is_region_default=True, is_active=True,
            comment="перенесено из региона")
        session.add(authority)
        created.append(authority)
    session.flush()
    return created


def run_startup_migration(session_factory):
    import logging

    session = session_factory()
    try:
        created = migrate_region_addressees(session)
        session.commit()
        if created:
            logging.getLogger("uvicorn.error").info(
                "mvd authorities: перенесено из регионов — %s", ", ".join(a.name for a in created))
    except Exception:
        session.rollback()
        logging.getLogger(__name__).exception("mvd authorities migration failed")
    finally:
        session.close()


def missing_petition_fields(authority):
    return [field for field in PETITION_MVD_FIELDS if not normalize_text(getattr(authority, field, None))]


def stores_by_authority(session):
    """{id подразделения: [номера ТК, закреплённых вручную]} — для списка подразделений."""
    result = {}
    for store in session.query(Store).filter(Store.mvd_authority_id != None).all():  # noqa: E711
        result.setdefault(store.mvd_authority_id, []).append(store.tk_number)
    return {key: sorted(value) for key, value in result.items()}

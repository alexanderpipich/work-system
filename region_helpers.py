"""Регионы работы (П4): орган выдачи и территория патента. Адресат ходатайства — подразделение
МВД (mvd_authorities.py); поля Region.uvm_* остались в базе, но не используются.

Регион сотрудника — по городу его последних смен (город, где смену поймали в
выгрузке; это не закрепление за магазином). В форме документа его можно сменить.
"""

from models import Region, Shift
from utils import normalize_person_name, normalize_text

REGION_FIELDS = ("name", "cities", "patent_authority", "patent_territory")


def city_key(city):
    """«г. Москва», «Москва» → «москва»."""
    key = normalize_person_name(city)
    for prefix in ("г. ", "г.", "город "):
        if key.startswith(prefix):
            key = key[len(prefix):].strip()
    return key


def region_cities(region):
    return {city_key(c) for c in (region.cities or "").split(",") if normalize_text(c)}


def region_for_city(session, city):
    key = city_key(city)
    if not key:
        return None
    for region in session.query(Region).filter(Region.is_active == True).order_by(Region.id).all():  # noqa: E712
        if key in region_cities(region):
            return region
    return None


def last_shift_city(session, employee_name):
    row = (
        session.query(Shift.city)
        .filter(Shift.employee == normalize_text(employee_name), Shift.city != None)  # noqa: E711
        .order_by(Shift.shift_date.desc(), Shift.id.desc())
        .first()
    )
    return row[0] if row else None


def region_for_employee(session, employee_name):
    """Регион по городу последних смен; None — смен нет или город не привязан к региону."""
    return region_for_city(session, last_shift_city(session, employee_name))


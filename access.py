from rbac import canonical_role, get_scope_values
from utils import normalize_text


def get_economist_cities(user):
    raw = getattr(user, "economist_stores", None) or ""
    return [normalize_text(city) for city in raw.split(",") if normalize_text(city)]


def get_user_cities(session, user):
    values = get_scope_values(session, user, "city")
    return None if values is None else sorted(values)


def get_user_stores(session, user):
    values = get_scope_values(session, user, "store")
    if values is None:
        return None
    return sorted(values)


def apply_shift_scope(query, session, user, model):
    cities = get_user_cities(session, user)
    stores = get_user_stores(session, user)
    if cities is not None:
        query = query.filter(model.city.in_(cities or ["__none__"]))
    if stores is not None:
        query = query.filter(model.store.in_(stores or ["__none__"]))
    return query


def accessible_employee_names(session, user):
    from models import Shift

    query = apply_shift_scope(session.query(Shift.employee).distinct(), session, user, Shift)
    return sorted({normalize_text(row[0]) for row in query.all() if row[0]})


def scope_allows_store(session, user, city, store):
    cities = get_user_cities(session, user)
    stores = get_user_stores(session, user)
    city_ok = cities is None or normalize_text(city) in set(cities)
    store_ok = stores is None or normalize_text(store) in set(stores)
    return city_ok and store_ok
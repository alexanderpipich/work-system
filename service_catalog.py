"""Справочник услуг — миграция и диагностика (переделка услуг, этап 1).

Наполняет `Service` из существующих `Rate.service` + `Shift.service`, связывает
`Rate` (service_id + level из разбора `Nур_`). НИЧЕГО не склеивает автоматически
(дубли написания Вингараж → две записи), НЕ трогает Shift и не удаляет
`Rate.service` (deprecated). Идемпотентно.

Разбор имени переиспользует `service_matrix.parse_service_name` (сделан для матрицы).
"""

from models import Rate, Service, Shift
from service_matrix import normalize_service_base, parse_service_name
from time_helpers import now_utc
from utils import normalize_text


def _base_of(service):
    """(level|None, базовое имя) из текстового имени услуги."""
    level, base = parse_service_name(service)
    return level, normalize_text(base)


def _distinct_services(session, column):
    return [row[0] for row in session.query(column).distinct().all() if normalize_text(row[0])]


def collect_base_names(session):
    """Уникальные базовые имена услуг из ставок и смен (без склейки написаний)."""
    names = {}
    for service in _distinct_services(session, Rate.service):
        _, base = _base_of(service)
        if base:
            names.setdefault(base, base)
    for service in _distinct_services(session, Shift.service):
        _, base = _base_of(service)
        if base:
            names.setdefault(base, base)
    return sorted(names.values())


def build_service_resolver(session):
    """Фабрика резолвера услуги смены → (service_id, level) с кэшем.

    Один запрос Service на весь расчёт: строит карту имя/алиас → id (имя
    приоритетнее алиаса, как в странах). Возвращает callable `resolve(shift)`,
    кэширующий по тексту `shift.service` — много смен с одной услугой не бьют в БД.
    """
    name_map = {}
    alias_map = {}
    for svc in session.query(Service).all():
        name_map.setdefault(normalize_text(svc.name), svc.id)
    for svc in session.query(Service).all():
        for alias in (svc.aliases or "").split(","):
            alias_key = normalize_text(alias)
            if alias_key and alias_key not in name_map:
                alias_map.setdefault(alias_key, svc.id)
    lookup = {**alias_map, **name_map}  # имя услуги приоритетнее алиаса

    cache = {}

    def resolve(shift):
        key = normalize_text(getattr(shift, "service", ""))
        if key in cache:
            return cache[key]
        level, base = _base_of(key)
        service_id = lookup.get(normalize_text(base)) if base else None
        result = (service_id, level)
        cache[key] = result
        return result

    return resolve


def resolve_shift_service(session, shift):
    """Разовый резолв услуги смены → (service_id, level). Для цикла используйте
    build_service_resolver (кэш + один запрос)."""
    return build_service_resolver(session)(shift)


def service_diagnostics(session):
    """Переиспользуемая диагностика (для отчёта миграции и UI этапа 5).

    Возвращает: услуги смен без тарифа, дубли написания (кандидаты на чистку),
    смены без Service в справочнике, число смен без уровня.
    """
    rate_bases = set()
    for service in _distinct_services(session, Rate.service):
        _, base = _base_of(service)
        if base:
            rate_bases.add(base)

    service_names = {normalize_text(s.name) for s in session.query(Service).all()}

    shift_services = _distinct_services(session, Shift.service)
    shifts_without_tariff = set()
    shifts_without_service = set()
    shifts_without_level = 0
    for service in shift_services:
        level, base = _base_of(service)
        if not base:
            continue
        if level is None:
            shifts_without_level += 1
        if base not in rate_bases:
            shifts_without_tariff.add(base)
        if base not in service_names:
            shifts_without_service.add(base)

    # Дубли написания: разные исходные базовые имена, схлопывающиеся одной
    # нормализацией (Вингараж с пробелом/подчёркиванием). Только показать.
    groups = {}
    for base in rate_bases | {b for b in (_base_of(s)[1] for s in shift_services) if b}:
        groups.setdefault(normalize_service_base(base), set()).add(base)
    duplicate_spelling = sorted(
        [sorted(variants) for variants in groups.values() if len(variants) > 1]
    )

    # Rate без service_id — не мигрированные/ручные записи. Подбор (этап 2) для
    # них падает на матчинг по тексту (страховка сумм), но их стоит домигрировать.
    rates_without_service_id = (
        session.query(Rate).filter(Rate.service_id.is_(None)).count()
    )

    return {
        "no_tariff_services": sorted(shifts_without_tariff),
        "duplicate_spelling": duplicate_spelling,
        "shifts_without_service": sorted(shifts_without_service),
        "shifts_without_level": shifts_without_level,
        "rates_without_service_id": rates_without_service_id,
    }


def migrate_services(session):
    """Идемпотентная миграция. Возвращает отчёт (dict).

    1) создать Service из уникальных базовых имён (Rate + Shift), не склеивая;
    2) связать каждый Rate → service_id + level (из `Nур_`);
    3) собрать диагностику. Shift не трогается, Rate.service остаётся.
    """
    existing = {normalize_text(s.name): s for s in session.query(Service).all()}
    created = 0
    for name in collect_base_names(session):
        if normalize_text(name) in existing:
            continue
        service = Service(name=name, is_active=True, created_at=now_utc())
        session.add(service)
        session.flush()
        existing[normalize_text(name)] = service
        created += 1

    linked = 0
    unlinked = []
    for rate in session.query(Rate).all():
        level, base = _base_of(rate.service)
        service = existing.get(normalize_text(base)) if base else None
        if service is None:
            unlinked.append(rate.service)
            continue
        rate.service_id = service.id
        rate.level = level
        linked += 1

    session.commit()

    diagnostics = service_diagnostics(session)
    report = {
        "services_total": session.query(Service).count(),
        "services_created": created,
        "rates_linked": linked,
        "rates_unlinked": sorted(set(unlinked)),
        **diagnostics,
    }
    return report

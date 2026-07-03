"""
Матчинг строки гражданства → Country.id с учётом алиасов сокращений.

Справочник `Country` хранит полные названия; загрузчики (Excel users) встречают
сокращения («РФ», «РБ», «Беларусь»). `Country.aliases` — CSV дополнительных
написаний. Единая точка сопоставления, чтобы «РФ»→«Россия» работало везде.

Приоритет: точное имя страны выигрывает над алиасом при коллизии.
"""

from models import Country
from utils import normalize_text


def parse_aliases(raw):
    """CSV-строка алиасов → список нормализованных непустых значений (без дублей)."""
    result = []
    for part in (raw or "").split(","):
        alias = normalize_text(part)
        if alias and alias not in result:
            result.append(alias)
    return result


def build_country_matcher(session, active_only=True):
    """dict {casefold(имя|алиас) → country_id}. Имя страны приоритетнее алиаса."""
    query = session.query(Country)
    if active_only:
        query = query.filter(Country.is_active == True)
    countries = query.all()

    matcher = {}
    # Сначала алиасы (низкий приоритет): первый занявший ключ остаётся.
    for c in countries:
        for alias in parse_aliases(c.aliases):
            matcher.setdefault(alias.casefold(), c.id)
    # Затем имена (высокий приоритет): перекрывают любой алиас с тем же ключом.
    for c in countries:
        matcher[normalize_text(c.name).casefold()] = c.id
    return matcher


def match_country_id(session, value, matcher=None):
    """Сопоставить строку гражданства с country_id (или None). Учитывает алиасы.

    matcher — опциональный предпостроенный dict (для батча в загрузчике, чтобы не
    перестраивать на каждой строке)."""
    key = normalize_text(value).casefold()
    if not key:
        return None
    if matcher is None:
        matcher = build_country_matcher(session)
    return matcher.get(key)

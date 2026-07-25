"""Матрица услуг по уровням — диагностика (вариант А, ТЗ matrica_uslug).

Читает услуги «на лету» из Rate.service и Shift.service. Справочника услуг НЕТ,
модель НЕ меняется, подбор ставки (pick_rate) НЕ трогается. Нормализация здесь —
ТОЛЬКО для группировки/отображения, имена в БД не переписываются.

Формат уровня канонический: загрузчик тарифов пишет `f"{n}ур_{service}"`
(routers/rates.py). Обратного разбора имени в коде не было — он тут.
"""

import re

from utils import normalize_text


# Уровень в начале имени: "2ур_", "2ур ", "2 ур_" — цифра, опц. пробел, «ур»,
# затем разделитель (подчёркивание или пробел), затем базовое имя.
_LEVEL_PREFIX_RE = re.compile(r"^\s*(\d+)\s*ур[_\s]+(.+)$", re.IGNORECASE)

# Колонки матрицы: уровни 1..5 + «без уровня» (None).
LEVEL_COLUMNS = [1, 2, 3, 4, 5]
_LEVEL_BUCKETS = LEVEL_COLUMNS + [None]


def parse_service_name(value):
    """`"2ур_Услуги по выкладке"` → `(2, "Услуги по выкладке")`.

    Без префикса уровня → `(None, исходное имя)`. Регистр/пробелы вокруг
    нормализуются. Поддержаны варианты разделителя `2ур_`, `2ур `, `2 ур_`.
    """
    text = normalize_text(value)
    if not text:
        return None, ""

    match = _LEVEL_PREFIX_RE.match(text)
    if match:
        level = int(match.group(1))
        base = match.group(2).strip()
        return level, base

    return None, text


def normalize_service_base(name):
    """Ключ ГРУППИРОВКИ базового имени (НЕ для записи в БД).

    Нижний регистр, ё→е, схлопывание пробелов/подчёркиваний в один пробел,
    обрезка краёв. Цель — чтобы `Вингараж Универсальные услуги` и
    `Вингараж_Универсальные услуги` дали ОДИН ключ и стали видны как дубль.
    """
    text = normalize_text(name).lower().replace("ё", "е")
    text = re.sub(r"[\s_]+", " ", text)
    return text.strip()


def _level_bucket(level):
    return level if level in LEVEL_COLUMNS else None


def _empty_cell():
    return {"rates": [], "count": 0, "min": None, "max": None, "has_shift": False, "orphan": False}


def levenshtein(a, b):
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            insert = current[j - 1] + 1
            delete = previous[j] + 1
            replace = previous[j - 1] + (0 if ca == cb else 1)
            current.append(min(insert, delete, replace))
        previous = current
    return previous[-1]


def is_base_rate(rate):
    """Базовая тарифная сетка (слой 0 pick_rate): пустые store И employee_name.

    Формат/регион остаются ИЗМЕРЕНИЯМИ сетки (одна услуга в ГМ и СМ стоит
    по-разному) — заполненный format НЕ делает ставку индивидуальной.
    """
    return not normalize_text(rate.get("store")) and not normalize_text(rate.get("employee_name"))


def _field(obj, name, default=None):
    """Достать поле из dict или ORM-объекта — матрица принимает и то, и другое."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _service_alias_list(service):
    return [normalize_text(a) for a in str(_field(service, "aliases") or "").split(",") if normalize_text(a)]


def build_service_matrix(services, rate_rows, shift_services, rated_service_ids=None):
    """Матрица услуг из справочника `Service` (этап 5, финал).

    - `services` — записи Service (id, name, aliases, is_active): по одной СТРОКЕ на услугу;
    - `rate_rows` — dict `{service_id, level, city, format, store, employee_name, hourly_rate}`
      (обычно уже отфильтрованы по региону/формату для клеток);
    - `shift_services` — тексты услуг смен (для диагностики «без справочника»);
    - `rated_service_ids` — множество id услуг, у которых ЕСТЬ хоть один Rate (глобально, до
      фильтра по региону) — для метки «есть в тарифах» и «услуги без тарифа». Если None —
      выводится из rate_rows.

    Диагностика: дубли НАПИСАНИЯ (разные Service с одним base_key — чистятся слиянием) отделены
    от дублей КЛЮЧА (одна услуга+уровень+регион+формат с двумя базовыми ценами — ошибка данных).
    В клетки идёт только базовая сетка (store/employee пусты); индивидуальные — счётчик + метка.
    """
    services = list(services)
    rate_rows = list(rate_rows)
    shift_texts = [normalize_text(s) for s in shift_services if normalize_text(s)]
    if rated_service_ids is None:
        rated_service_ids = {r.get("service_id") for r in rate_rows if r.get("service_id") is not None}

    # Индекс имя/алиас (нормализованный base) → услуга: резолв смен и «без справочника».
    known_bases = set()
    for service in services:
        known_bases.add(normalize_service_base(_field(service, "name")))
        for alias in _service_alias_list(service):
            known_bases.add(normalize_service_base(alias))

    rows = []
    rows_by_id = {}
    individual_rates = 0
    for service in services:
        service_id = _field(service, "id")
        name = normalize_text(_field(service, "name"))
        row = {
            "service_id": service_id,
            "name": name,
            "aliases": normalize_text(_field(service, "aliases")),
            "alias_list": _service_alias_list(service),
            "is_active": bool(_field(service, "is_active", True)),
            "base_key": normalize_service_base(name),
            "cells": {bucket: _empty_cell() for bucket in _LEVEL_BUCKETS},
            "individual_count": 0,
            "in_rates": service_id in rated_service_ids,
            "is_duplicate": False,
            "dup_group": [],
            "has_key_error": False,
            "similar_to": [],
        }
        rows_by_id[service_id] = row
        rows.append(row)

    for rate in rate_rows:
        row = rows_by_id.get(rate.get("service_id"))
        if row is None:
            continue
        if not is_base_rate(rate):
            row["individual_count"] += 1
            individual_rates += 1
            continue
        bucket = _level_bucket(rate.get("level"))
        row["cells"][bucket]["rates"].append({
            "city": rate.get("city"),
            "format": rate.get("format"),
            "store": rate.get("store"),
            "employee_name": rate.get("employee_name"),
            "hourly_rate": rate.get("hourly_rate"),
        })

    for row in rows:
        for cell in row["cells"].values():
            values = [r["hourly_rate"] for r in cell["rates"] if r["hourly_rate"] is not None]
            cell["count"] = len(cell["rates"])
            cell["min"] = min(values) if values else None
            cell["max"] = max(values) if values else None
            # Регион+формат — измерения сетки. Дубль КЛЮЧА (ошибка целостности) =
            # одна и та же (регион, формат) базовая ставка под этой услугой+уровнем
            # встречается дважды → инвариант «одна цена на ключ» нарушен.
            region_format = {}
            for r in cell["rates"]:
                key = (normalize_text(r.get("city")), normalize_text(r.get("format")))
                region_format[key] = region_format.get(key, 0) + 1
            cell["region_format_count"] = len(region_format)
            cell["has_real_dup"] = any(n > 1 for n in region_format.values())
        row["has_key_error"] = any(cell["has_real_dup"] for cell in row["cells"].values())

    # Дубли НАПИСАНИЯ: разные Service с одним base_key (Вингараж пробел/подчёрк).
    groups = {}
    for row in rows:
        if row["base_key"]:
            groups.setdefault(row["base_key"], []).append(row)
    duplicate_groups = 0
    for members in groups.values():
        if len(members) > 1:
            duplicate_groups += 1
            info = [
                {"service_id": m["service_id"], "name": m["name"], "in_rates": m["in_rates"]}
                for m in members
            ]
            for row in members:
                row["is_duplicate"] = True
                row["dup_group"] = info

    rows.sort(key=lambda r: (r["base_key"], r["name"].lower()))

    # Похожие имена (опечатки) — по РАЗНЫМ base_key; приставка «не» (квалиф/неквалиф) не в счёт.
    distinct = sorted(groups.keys())
    similar_pairs = {}
    for i in range(len(distinct)):
        for j in range(i + 1, len(distinct)):
            a, b = distinct[i], distinct[j]
            if not a or not b or abs(len(a) - len(b)) > 2:
                continue
            if b == "не" + a or a == "не" + b:
                continue
            if 1 <= levenshtein(a, b) <= 2:
                similar_pairs.setdefault(a, set()).add(b)
                similar_pairs.setdefault(b, set()).add(a)
    for row in rows:
        for other_key in sorted(similar_pairs.get(row["base_key"], set())):
            for other in groups.get(other_key, []):
                row["similar_to"].append(other["name"])

    # Услуги смен без справочника Service (по-прежнему диагностируем, этап 4).
    unmatched_shift_services = sorted({
        text for text in shift_texts
        if normalize_service_base(parse_service_name(text)[1]) not in known_bases
    })
    # Услуги в справочнике без единого тарифа (ЧТС будет 0).
    no_tariff_services = sorted(row["name"] for row in rows if not row["in_rates"])

    counters = {
        "services": len(rows),
        "duplicates": duplicate_groups,
        "key_errors": sum(1 for r in rows if r["has_key_error"]),
        "no_tariff_services": len(no_tariff_services),
        "unmatched_shift_services": len(unmatched_shift_services),
        "typos": sum(1 for r in rows if r["similar_to"]),
        "individual_rates": individual_rates,
    }

    return {
        "rows": rows,
        "levels": LEVEL_COLUMNS,
        "counters": counters,
        "no_tariff_services": no_tariff_services,
        "unmatched_shift_services": unmatched_shift_services,
    }

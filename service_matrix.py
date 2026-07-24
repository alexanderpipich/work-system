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


def build_service_matrix(rate_rows, shift_rows):
    """Собрать матрицу услуг из ставок и услуг смен.

    `rate_rows` — итерабельность dict `{service, city, format, store,
    employee_name, hourly_rate}`; `shift_rows` — dict `{service}` (уникальные
    услуги смен). Возвращает `{rows, levels, counters, no_rate_services,
    rate_no_shift_services}`.

    В КЛЕТКИ и диагностику по тарифам попадает ТОЛЬКО базовая сетка (слой 0).
    Индивидуальные ставки (слои 1/2 — по ТК/сотруднику) не мешаются в сетку:
    считаются отдельным счётчиком и помечаются на строке услуги.
    """
    rate_rows = list(rate_rows)
    shift_rows = list(shift_rows)

    base_rate_service_strings = {
        normalize_text(r.get("service"))
        for r in rate_rows
        if normalize_text(r.get("service")) and is_base_rate(r)
    }
    shift_service_strings = {
        normalize_text(s.get("service")) for s in shift_rows if normalize_text(s.get("service"))
    }
    individual_rates = sum(
        1 for r in rate_rows if normalize_text(r.get("service")) and not is_base_rate(r)
    )

    bases = {}

    def get_row(service):
        level, base = parse_service_name(service)
        base_key = normalize_service_base(base)
        row = bases.get(base_key)
        if row is None:
            row = {
                "base_key": base_key,
                "base_variants": set(),
                "original_services": set(),
                "individual_count": 0,
                "cells": {bucket: _empty_cell() for bucket in _LEVEL_BUCKETS},
            }
            bases[base_key] = row
        row["base_variants"].add(base)
        row["original_services"].add(normalize_text(service))
        return row, _level_bucket(level)

    for rate in rate_rows:
        service = rate.get("service")
        if not normalize_text(service):
            continue
        row, bucket = get_row(service)
        if not is_base_rate(rate):
            # Индивидуальная ставка (слой 1/2) — в клетки НЕ кладём, только сигнал.
            row["individual_count"] += 1
            continue
        row["cells"][bucket]["rates"].append({
            "city": rate.get("city"),
            "format": rate.get("format"),
            "store": rate.get("store"),
            "employee_name": rate.get("employee_name"),
            "hourly_rate": rate.get("hourly_rate"),
        })

    for shift in shift_rows:
        service = shift.get("service")
        if not normalize_text(service):
            continue
        row, bucket = get_row(service)
        row["cells"][bucket]["has_shift"] = True

    rows = []
    for row in bases.values():
        for cell in row["cells"].values():
            values = [r["hourly_rate"] for r in cell["rates"] if r["hourly_rate"] is not None]
            cell["count"] = len(cell["rates"])
            cell["min"] = min(values) if values else None
            cell["max"] = max(values) if values else None
            cell["orphan"] = cell["has_shift"] and cell["count"] == 0
        variants = sorted(row["base_variants"])
        # Представительное имя строки — самый короткий вариант (обычно эталон).
        row["base_display"] = sorted(row["base_variants"], key=lambda x: (len(x), x))[0] if variants else ""
        row["variants"] = variants
        row["original_services"] = sorted(row["original_services"])
        row["is_duplicate"] = len(row["base_variants"]) > 1
        row["has_no_rate"] = any(cell["orphan"] for cell in row["cells"].values())
        row["similar_to"] = []
        rows.append(row)

    rows.sort(key=lambda r: r["base_display"].lower())

    # Похожие имена (опечатки): пары базовых ключей с расстоянием Левенштейна 1..2.
    for i in range(len(rows)):
        for j in range(i + 1, len(rows)):
            a, b = rows[i]["base_key"], rows[j]["base_key"]
            if not a or not b or abs(len(a) - len(b)) > 2:
                continue
            if 1 <= levenshtein(a, b) <= 2:
                rows[i]["similar_to"].append(rows[j]["base_display"])
                rows[j]["similar_to"].append(rows[i]["base_display"])

    # Диагностика по тарифам — только против БАЗОВОЙ сетки (индивидуальные
    # ставки не должны раздувать «тарифы без смен»).
    no_rate_services = sorted(s for s in shift_service_strings if s not in base_rate_service_strings)
    rate_no_shift_services = sorted(
        s for s in base_rate_service_strings if s not in shift_service_strings
    )

    counters = {
        "bases": len(rows),
        "duplicates": sum(1 for r in rows if r["is_duplicate"]),
        "no_rate_services": len(no_rate_services),
        "rate_no_shift_services": len(rate_no_shift_services),
        "typos": sum(1 for r in rows if r["similar_to"]),
        "individual_rates": individual_rates,
    }

    return {
        "rows": rows,
        "levels": LEVEL_COLUMNS,
        "counters": counters,
        "no_rate_services": no_rate_services,
        "rate_no_shift_services": rate_no_shift_services,
    }

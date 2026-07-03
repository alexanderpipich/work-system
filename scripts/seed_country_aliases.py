"""
Засидить типовые алиасы сокращений стран в `Country.aliases`.

После добавления поля `Country.aliases` — предзаполнить известные сокращения,
чтобы загрузчики сразу матчили «РФ»→«Россия» и т.п. Матч по имени страны
(нормализация). Идемпотентно: заполняет ТОЛЬКО пустое поле aliases — ручные
правки владельца не затирает.

Run on Render Shell from the app root (ПОСЛЕ деплоя кода с полем aliases):
    python scripts/seed_country_aliases.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import SessionLocal
from models import Country
from utils import normalize_text

# Имя страны (как в справочнике) → список типовых алиасов.
SEED = {
    "Россия": ["РФ", "Российская Федерация", "Россия"],
    "Белорусь": ["РБ", "Беларусь", "Республика Беларусь", "Белоруссия"],
    "Армения": ["Республика Армения", "Армения"],
    "Кыргызстан": ["Киргизия", "Кыргызская Республика", "КР"],
    "Таджикистан": ["Республика Таджикистан", "Таджикистан"],
    "Узбекистан": ["Республика Узбекистан", "Узбекистан"],
}


def main():
    session = SessionLocal()
    try:
        # Нормализованное имя → список алиасов.
        seed_by_name = {normalize_text(k).casefold(): v for k, v in SEED.items()}

        filled = 0
        skipped_has = 0
        no_match = []

        for country in session.query(Country).all():
            key = normalize_text(country.name).casefold()
            aliases = seed_by_name.get(key)
            if aliases is None:
                continue
            if normalize_text(country.aliases):
                skipped_has += 1  # уже заполнено (в т.ч. вручную) — не трогаем
                continue
            # Не дублируем само имя страны в алиасах.
            cleaned = [a for a in aliases if normalize_text(a).casefold() != key]
            country.aliases = ", ".join(cleaned)
            filled += 1

        # Страны из SEED, которых нет в справочнике (для сведения).
        present = {normalize_text(c.name).casefold() for c in session.query(Country).all()}
        for name_key in seed_by_name:
            if name_key not in present:
                no_match.append(name_key)

        session.commit()

        print()
        print("=" * 56)
        print("  SEED АЛИАСОВ СТРАН — ГОТОВО")
        print("=" * 56)
        print(f"  Заполнено (было пусто)        : {filled}")
        print(f"  Пропущено (уже были алиасы)   : {skipped_has}")
        if no_match:
            print(f"  Нет в справочнике (не сидили) : {', '.join(no_match)}")
        print("=" * 56)
        print()

    except Exception as exc:
        session.rollback()
        print(f"\nERROR — rolled back: {exc}", file=sys.stderr)
        raise
    finally:
        session.close()


if __name__ == "__main__":
    main()

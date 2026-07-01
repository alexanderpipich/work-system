"""
Блок 1 нормализации — развязка гражданства: перенос данных в канон User.

Гражданство сотрудника — теперь ТОЛЬКО `User.citizenship_country_id` (FK на Country).
Legacy-источники (`Requisite.citizenship`, `User.citizenship_country` строка) больше
не читаются кодом. Этот скрипт переносит существующие данные, НИЧЕГО не теряя:

Для каждого User без `citizenship_country_id`:
  1) берём строку гражданства из `User.citizenship_country`, иначе из активного
     `Requisite.citizenship` сотрудника;
  2) матчим строку → Country по имени (нормализация + casefold) — как загрузчик users;
  3) совпало → проставляем `User.citizenship_country_id`;
  4) для сохранности отображения: если `User.citizenship_country` пуст, а строка
     нашлась в реквизите — копируем строку в `User.citizenship_country`;
  5) не совпало со справочником → в ОТЧЁТ для ручной доработки (данные не трогаем).

Идемпотентно: заполняет только ПУСТЫЕ поля, существующие привязки не перезаписывает.
Requisite.citizenship остаётся в БД как deprecated (не удаляется этим скриптом).

Run on Render Shell from the app root:
    python scripts/migrate_citizenship_decouple.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import SessionLocal
from models import Country, Requisite, User
from utils import normalize_text


def main():
    session = SessionLocal()
    try:
        countries = session.query(Country).filter(Country.is_active == True).all()
        country_by_name = {normalize_text(c.name).casefold(): c.id for c in countries}

        # Активные реквизиты по ФИО (строка гражданства как запасной источник).
        req_citizenship = {}
        for r in session.query(Requisite).filter(Requisite.is_active == True).all():
            name = normalize_text(r.employee_name)
            cit = normalize_text(r.citizenship)
            if name and cit and name not in req_citizenship:
                req_citizenship[name] = cit

        linked = 0
        string_filled = 0
        already_linked = 0
        unmatched = []
        no_citizenship = 0

        for user in session.query(User).all():
            if user.citizenship_country_id:
                already_linked += 1
                continue

            name = normalize_text(user.employee_name)
            user_str = normalize_text(user.citizenship_country)
            source_str = user_str or req_citizenship.get(name, "")

            if not source_str:
                no_citizenship += 1
                continue

            # Сохранность отображения: перенести строку в User, если там пусто.
            if not user_str and source_str:
                user.citizenship_country = source_str
                string_filled += 1

            country_id = country_by_name.get(source_str.casefold())
            if country_id:
                user.citizenship_country_id = country_id
                linked += 1
            else:
                unmatched.append((user.employee_name or "?", source_str))

        session.commit()

        print()
        print("=" * 64)
        print("  БЛОК 1 — РАЗВЯЗКА ГРАЖДАНСТВА: ПЕРЕНОС ДАННЫХ — ГОТОВО")
        print("=" * 64)
        print(f"  Привязано к справочнику (country_id)   : {linked}")
        print(f"  Строка гражданства перенесена в User   : {string_filled}")
        print(f"  Уже были привязаны (пропущено)         : {already_linked}")
        print(f"  Без гражданства вообще                 : {no_citizenship}")
        print(f"  НЕ сматчено со справочником (вручную)  : {len(unmatched)}")
        if unmatched:
            print("-" * 64)
            print("  Требуют ручной доработки (ФИО → строка гражданства):")
            for name, cit in unmatched:
                print(f"    {name[:40]:40s} → «{cit}»")
        print("=" * 64)
        print("  Requisite.citizenship оставлен как deprecated (не удалён).")
        print("=" * 64)
        print()

    except Exception as exc:
        session.rollback()
        print(f"\nERROR — rolled back: {exc}", file=sys.stderr)
        raise
    finally:
        session.close()


if __name__ == "__main__":
    main()

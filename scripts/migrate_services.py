"""
Переделка услуг — ЭТАП 1: наполнить справочник Service и связать Rate.

Идемпотентно: собирает уникальные базовые имена услуг из Rate.service +
Shift.service (разбор `Nур_` → уровень), создаёт записи Service (дубли написания
НЕ склеивает — Вингараж с пробелом/подчёркиванием = две записи), связывает каждый
Rate → service_id + level. Shift НЕ трогается, `Rate.service` (deprecated) остаётся
для отката/сверки. Повторный прогон не плодит дубли и не трогает aliases.

Запуск на Render Shell из корня приложения (ПОСЛЕ деплоя, как прочие migrate_*):
    python scripts/migrate_services.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.orm import sessionmaker

from database import engine
from models import Service
from service_catalog import migrate_services


def _print_list(title, items, limit=50):
    print(f"  {title}: {len(items)}")
    for item in items[:limit]:
        print(f"    - {item}")
    if len(items) > limit:
        print(f"    … и ещё {len(items) - limit}")


def main():
    # Таблица services создаётся Base.metadata.create_all в приложении; здесь —
    # на всякий случай (запуск скрипта в отрыве), checkfirst не тронет существующую.
    Service.__table__.create(bind=engine, checkfirst=True)
    print("[ok] ensured table services")

    session = sessionmaker(bind=engine)()
    try:
        report = migrate_services(session)
    finally:
        session.close()

    print("\n=== Отчёт миграции услуг (этап 1) ===")
    print(f"  Услуг в справочнике всего: {report['services_total']}")
    print(f"  Создано услуг за прогон:   {report['services_created']}")
    print(f"  Rate связано:              {report['rates_linked']}")
    _print_list("Rate НЕ связано (имя не сматчилось)", report["rates_unlinked"])
    _print_list("Услуги из смен без тарифа (ЧТС=0)", report["no_tariff_services"])
    _print_list("Смены без Service в справочнике", report["shifts_without_service"])
    print(f"  Смен без уровня (level NULL): {report['shifts_without_level']}")
    print(f"  Дубли написания (кандидаты на чистку владельцем): {len(report['duplicate_spelling'])}")
    for pair in report["duplicate_spelling"]:
        print(f"    - {' | '.join(pair)}")
    print("\nDone.")


if __name__ == "__main__":
    main()

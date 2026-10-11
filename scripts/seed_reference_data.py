"""
Загрузить справочники из data/reference/*.json в базу. Идемпотентно.

Сверка по естественным ключам (см. reference_data.py). Запускать после первого
старта приложения (таблицы создаёт create_all).

    python scripts/seed_reference_data.py                    # только добавить недостающее
    python scripts/seed_reference_data.py --update           # и обновить отличающееся по JSON
    python scripts/seed_reference_data.py --only stores,store_contacts --update
    python scripts/seed_reference_data.py --only stores --update --force-region 352,353,610

Без --update существующие записи не трогаются (их могли поправить в базе руками),
в отчёте — «есть: N» и сколько из них отличается от JSON. При --update у магазинов
не перезаписывается уже известный город (по нему подбираются ставки) — расхождения
печатаются списком.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import SessionLocal                                           # noqa: E402
from reference_data import TABLES, read_reference_files, seed_reference_data  # noqa: E402


def print_stats(stats, update):
    for table, counts in stats.items():
        line = f"{table}: вставлено {counts['inserted']}"
        if update:
            line += f", обновлено {counts['updated']}"
        line += f", есть {counts['existing']}"
        if counts["differs"]:
            line += f" (отличаются от JSON: {counts['differs']} — обновить: --update)"
        if counts["unresolved"]:
            line += f", пропущено {len(counts['unresolved'])}"
        print(line)
        if counts["unresolved"]:
            print("  пропущено: " + ", ".join(counts["unresolved"]))
        for key, field, db_value, json_value in counts["kept"]:
            print(f"  {key}: {field} оставлен из базы {db_value!r}, в JSON {json_value!r}")


def main():
    parser = argparse.ArgumentParser(description="Загрузка справочников из data/reference")
    parser.add_argument("--update", action="store_true",
                        help="обновить существующие записи, отличающиеся от JSON")
    parser.add_argument("--only", default="",
                        help="через запятую: " + ",".join(table for table, _ in TABLES))
    parser.add_argument("--force-region", default="",
                        help="с --update: номера ТК через запятую, у которых тарифный регион "
                             "перезаписывается по JSON, даже если в базе уже заполнен (город не трогается)")
    args = parser.parse_args()
    only = [name.strip() for name in args.only.split(",") if name.strip()] or None
    force_tk = {int(tk) for tk in args.force_region.replace(" ", "").split(",") if tk}
    if force_tk and not args.update:
        print("--force-region работает только вместе с --update")
        return 1

    data = read_reference_files()
    if not data:
        print("Нет файлов в data/reference — нечего загружать.")
        return 1
    session = SessionLocal()
    try:
        stats = seed_reference_data(session, data, update=args.update, only=only,
                                    force={"stores": (force_tk, {"rate_region"})} if force_tk else None)
        session.commit()
    except ValueError as error:
        session.rollback()
        print(error)
        return 1
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
    print_stats(stats, args.update)
    return 0


if __name__ == "__main__":
    sys.exit(main())

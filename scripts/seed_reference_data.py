"""
Загрузить справочники из data/reference/*.json в базу. Идемпотентно.

Сверка по естественным ключам (см. reference_data.py): новое вставляется,
отличающееся обновляется по JSON, совпадающее пропускается. Запускать после
первого старта приложения (таблицы создаёт create_all).

    python scripts/seed_reference_data.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import SessionLocal                                   # noqa: E402
from reference_data import read_reference_files, seed_reference_data  # noqa: E402


def main():
    data = read_reference_files()
    if not data:
        print("Нет файлов в data/reference — нечего загружать.")
        return 1
    session = SessionLocal()
    try:
        stats = seed_reference_data(session, data)
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
    for table, counts in stats.items():
        print(f"{table}: вставлено {counts['inserted']}, обновлено {counts['updated']}, "
              f"пропущено {counts['skipped']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

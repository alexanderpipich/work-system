"""
Выгрузить справочники из текущей базы в data/reference/*.json.

Запускается на базе-источнике (локальный дамп прода); результат коммитится —
это справочники для чистого старта. Список таблиц и формат — reference_data.py.

    python scripts/export_reference_data.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import SessionLocal                                          # noqa: E402
from reference_data import REFERENCE_DIR, export_reference_data, write_reference_files  # noqa: E402


def main():
    session = SessionLocal()
    try:
        data = export_reference_data(session)
    finally:
        session.close()
    write_reference_files(data)
    for table, records in data.items():
        print(f"{table}: {len(records)}")
    print(f"Записано в {REFERENCE_DIR}")


if __name__ == "__main__":
    main()

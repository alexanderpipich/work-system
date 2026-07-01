"""
Блок 2 нормализации — одноразовый АУДИТ ИНН (read-only, ничего не пишет).

Проходит сотрудников, собирает ИНН из трёх точек (User.inn, активный
Requisite.inn, номер документа-ИНН) и выводит, где они расходятся или где
пусто. Модератор (человек) разбирает вручную — скрипт НИЧЕГО не меняет.
Для фактической синхронизации конкретного сотрудника используйте
`inn_sync.set_employee_inn()` через обычные точки записи (реквизиты/документ/
профиль) в приложении — там оно фиксируется в audit-log.

Run on Render Shell from the app root (read-only, безопасно повторять):
    python scripts/audit_inn_sync.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import SessionLocal
from inn_sync import active_requisite_for_user, inn_document_for_user
from models import User
from utils import normalize_text


def main():
    session = SessionLocal()
    try:
        users = session.query(User).order_by(User.employee_name.asc()).all()

        divergent = []
        empty_everywhere = 0
        in_sync = 0

        for user in users:
            requisite = active_requisite_for_user(session, user)
            document = inn_document_for_user(session, user)

            values = {
                "User.inn": normalize_text(user.inn),
                "Requisite.inn": normalize_text(requisite.inn) if requisite else "",
                "Document.document_number": normalize_text(document.document_number) if document else "",
            }
            non_empty = {v for v in values.values() if v}

            if not non_empty:
                empty_everywhere += 1
            elif len(non_empty) == 1:
                in_sync += 1
            else:
                divergent.append((user.employee_name or f"user#{user.id}", values))

        print()
        print("=" * 70)
        print("  БЛОК 2 — АУДИТ ИНН (read-only, ничего не изменено)")
        print("=" * 70)
        print(f"  Сотрудников всего            : {len(users)}")
        print(f"  Синхронизированы (1 значение): {in_sync}")
        print(f"  Пусто везде                  : {empty_everywhere}")
        print(f"  РАСХОДЯТСЯ — требуют разбора : {len(divergent)}")
        if divergent:
            print("-" * 70)
            for name, values in divergent:
                print(f"  {name[:40]:40s}")
                for point, val in values.items():
                    print(f"      {point:28s} = «{val}»" if val else f"      {point:28s} = (пусто)")
        print("=" * 70)
        print("  Разбор — вручную (модератор — человек). Синхронизация — через")
        print("  обычные формы приложения (реквизиты/документ-ИНН/профиль),")
        print("  каждая фиксируется в audit-log (inn_synced / inn_conflict_detected).")
        print("=" * 70)
        print()

    finally:
        session.close()


if __name__ == "__main__":
    main()

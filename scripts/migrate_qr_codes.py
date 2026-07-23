"""
Create the `employee_qr` table and transfer the legacy `users.qr_image_path`
into the first EmployeeQr row per employee.

005: до 3 QR на сотрудника с подписью специальности. Старое поле `User.qr_image_path`
остаётся (deprecated, один цикл) — единичная картинка переносится в первую запись
EmployeeQr (label "Основной", sort_order 0). Идемпотентно: таблица создаётся checkfirst,
перенос делается только для сотрудников, у которых ЕСТЬ legacy-путь и ещё НЕТ ни одной
записи EmployeeQr.

Run on Render Shell from the app root:
    python scripts/migrate_qr_codes.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import engine
from sqlalchemy.orm import sessionmaker

from models import EmployeeQr, User


def migrate_qr_codes(session):
    """Разовый перенос legacy qr_image_path → EmployeeQr. Возвращает число перенесённых."""
    transferred = 0
    users = session.query(User).filter(
        User.qr_image_path.isnot(None), User.qr_image_path != ""
    ).all()
    for user in users:
        already = session.query(EmployeeQr).filter(EmployeeQr.user_id == user.id).count()
        if already:
            continue
        session.add(EmployeeQr(
            user_id=user.id,
            image_path=user.qr_image_path,
            label="Основной",
            sort_order=0,
        ))
        transferred += 1
    session.commit()
    return transferred


def main():
    EmployeeQr.__table__.create(bind=engine, checkfirst=True)
    print("[ok] ensured table employee_qr")
    session = sessionmaker(bind=engine)()
    try:
        moved = migrate_qr_codes(session)
        print(f"[ok] transferred {moved} legacy qr_image_path → employee_qr")
    finally:
        session.close()
    print("Done.")


if __name__ == "__main__":
    main()

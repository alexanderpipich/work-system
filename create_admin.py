"""Создать или обновить superadmin — первый вход в пустую базу.

Секретов в коде нет: телефон, ФИО и пароль передаются аргументами или через
env (ADMIN_PHONE / ADMIN_NAME / ADMIN_PASSWORD). Без пароля спросит интерактивно.

    python create_admin.py --phone 79990000000 --name "Иванов Иван Иванович"

Поиск — по телефону, затем по ФИО (employee_name_norm): если сотрудник уже есть
(например, заведён импортом без кабинета), ему выдаются логин, пароль и роль
superadmin, второй User не создаётся. Пароль помечается временным.
"""

import argparse
import getpass
import os
import sys

from audit_helpers import create_audit_log
from database import SessionLocal
from models import User
from utils import find_user_by_name, get_password_hash, normalize_phone, normalize_text


def ensure_admin(session, phone, name, password):
    """Вернуть (user, created). Коммит — на вызывающем."""
    user = session.query(User).filter(User.phone == phone).first() or find_user_by_name(session, name)
    created = user is None
    if created:
        user = User(employee_name=name)
        session.add(user)
    user.phone = phone
    user.password_hash = get_password_hash(password)
    user.password_is_temporary = True
    user.is_admin = True
    user.role = "superadmin"
    session.flush()
    create_audit_log(
        session, None, None,
        "user_created" if created else "user_updated", "user", user.id, user.employee_name,
        new_value={"phone": user.phone, "role": user.role}, comment="create_admin.py",
    )
    return user, created


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--phone", default=os.getenv("ADMIN_PHONE", ""))
    parser.add_argument("--name", default=os.getenv("ADMIN_NAME", ""))
    parser.add_argument("--password", default=os.getenv("ADMIN_PASSWORD", ""))
    args = parser.parse_args(argv)

    phone = normalize_phone(args.phone)
    name = normalize_text(args.name)
    password = args.password or getpass.getpass("Пароль: ")
    if not (phone and name and password.strip()):
        print("Нужны телефон, ФИО и пароль.")
        return 1

    session = SessionLocal()
    try:
        user, created = ensure_admin(session, phone, name, password)
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
    action = "Создан" if created else "Обновлён"
    print(f"{action} superadmin: {user.employee_name}, логин {phone}. Смените пароль после входа.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

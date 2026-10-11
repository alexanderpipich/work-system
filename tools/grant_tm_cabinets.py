"""Выдать кабинеты ТМ — П4.4, блок C.

Всем User с ролью tm (и старой hr_manager) без телефона или пароля:
- логин-телефон из служебного диапазона 70000000001, 70000000002, … по порядку
  (занятые пропускаются) — не совпадёт с реальным номером и сразу видно, что
  это служебный логин; владелец может заменить его на реальный в /admin/users;
- случайный пароль из 8 символов, password_is_temporary = True (при входе
  попросит сменить).
ФИО не меняется (ТМ с именем из одного слова — «Амин», «Татьяна» — остаются как есть).

Сухой прогон по умолчанию: показывает, кому какой логин достанется, пароли не
создаются. С --apply пароли печатаются ОДИН раз — сохраните таблицу и раздайте ТМ.
В аудит пароль не пишется.

    python tools/grant_tm_cabinets.py
    python tools/grant_tm_cabinets.py --apply
"""

import argparse
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_helpers import create_audit_log           # noqa: E402
from database import SessionLocal                    # noqa: E402
from models import User                              # noqa: E402
from utils import get_password_hash                  # noqa: E402

SERVICE_PHONE_START = 70000000001
TM_ROLES = ("tm", "hr_manager")
# Без похожих символов (0/O, 1/l/I) — пароль диктуют по телефону.
PASSWORD_ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
PASSWORD_LENGTH = 8


def generate_password():
    return "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(PASSWORD_LENGTH))


def tms_without_cabinet(session):
    return (session.query(User)
            .filter(User.role.in_(TM_ROLES), (User.phone == None) | (User.password_hash == None))  # noqa: E711
            .order_by(User.id).all())


def service_phones(session, count):
    """count свободных номеров служебного диапазона по порядку."""
    used = {phone for (phone,) in session.query(User.phone).filter(User.phone != None)}  # noqa: E711
    phones, number = [], SERVICE_PHONE_START
    while len(phones) < count:
        if str(number) not in used:
            phones.append(str(number))
        number += 1
    return phones


def grant_tm_cabinets(session, apply=False):
    """[(user, логин, пароль|None)]. Коммит — на вызывающем."""
    users = tms_without_cabinet(session)
    missing_phone = [user for user in users if not user.phone]
    phones = iter(service_phones(session, len(missing_phone)))
    result = []
    for user in users:
        phone = user.phone or next(phones)
        password = generate_password() if apply else None
        if apply:
            user.phone = phone
            user.password_hash = get_password_hash(password)
            user.password_is_temporary = True
            create_audit_log(session, None, None, "user.cabinet_granted", "user", user.id, user.employee_name,
                             new_value={"phone": phone, "password_is_temporary": True},
                             comment="tools/grant_tm_cabinets.py")
        result.append((user, phone, password))
    return result


def main():
    parser = argparse.ArgumentParser(description="Кабинеты ТМ: служебный логин и временный пароль")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    session = SessionLocal()
    try:
        result = grant_tm_cabinets(session, apply=args.apply)
        if not result:
            print("Все ТМ уже с кабинетом.")
            return
        if args.apply:
            session.commit()
        print(f"{'ФИО':<30} {'Логин':<13} Пароль")
        for user, phone, password in result:
            print(f"{user.employee_name:<30} {phone:<13} {password or '— (сухой прогон)'}")
        if args.apply:
            print(f"\nКабинеты выданы: {len(result)}. Пароли больше нигде не сохранены — "
                  "раздайте ТМ сейчас; при первом входе система попросит сменить пароль.")
        else:
            print(f"\nБудет выдано кабинетов: {len(result)} (сухой прогон, --apply для записи)")
    finally:
        session.close()


if __name__ == "__main__":
    main()

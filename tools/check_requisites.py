"""Диагностика реквизитов: что РЕАЛЬНО лежит в базе.

Только чтение — ничего не меняет. Печатает repr() значений, чтобы было видно
скрытые пробелы, хвосты «.0» и научную нотацию, которые в интерфейсе не видны.

    python tools/check_requisites.py                  # только проблемные
    python tools/check_requisites.py --all            # все активные
    python tools/check_requisites.py --name Иванова   # поиск по ФИО
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import SessionLocal        # noqa: E402
from models import Requisite             # noqa: E402
from utils import requisite_issues       # noqa: E402


def problems(req):
    """Что не так с реквизитом. Пусто — значит годен к выплате.

    Критерий берётся из utils.requisite_issues — тот же, по которому генератор
    реестра решает, выпускать ли строку в платёжку.
    """
    return requisite_issues(req.inn, req.account_number, req.bik)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true", help="печатать и годные тоже")
    ap.add_argument("--name", default="", help="фильтр по части ФИО")
    args = ap.parse_args()

    session = SessionLocal()
    try:
        query = session.query(Requisite).filter(Requisite.is_active == True)  # noqa: E712
        if args.name:
            query = query.filter(Requisite.employee_name.ilike("%%%s%%" % args.name))
        rows = query.order_by(Requisite.employee_name).all()

        shown = broken = 0
        for req in rows:
            issues = problems(req)
            if issues:
                broken += 1
            if not issues and not args.all:
                continue
            shown += 1
            print("%s  (id=%s)" % (req.employee_name, req.id))
            print("    ИНН   %r" % (req.inn,))
            print("    счёт  %r" % (req.account_number,))
            print("    БИК   %r" % (req.bik,))
            for issue in issues:
                print("    !! %s" % issue)
            if not issues:
                print("    ok")
            print()

        print("активных реквизитов: %d, с проблемами: %d, показано: %d"
              % (len(rows), broken, shown))
        if broken:
            print("\nНаучная нотация означает, что цифры уже утеряны в базе —")
            print("восстановить нельзя, такие реквизиты надо вводить заново.")
    finally:
        session.close()


if __name__ == "__main__":
    main()

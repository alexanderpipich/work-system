"""Починка реквизитов, испорченных проходом через float.

По умолчанию — СУХОЙ ПРОГОН: только показывает, что изменилось бы. Запись в базу
происходит исключительно при явном --apply и пишется в журнал аудита.

Чинится то, где цифры целы: хвост «.0» отрезается, съеденный ведущий ноль ИНН/БИК
восстанавливается (длины известны заранее). Научная нотация НЕ чинится — во float
поместилось 17 значащих цифр из 20, младшие утеряны безвозвратно; такие реквизиты
выводятся списком на переввод.

    python tools/repair_requisites.py            # посмотреть, что будет
    python tools/repair_requisites.py --apply    # записать
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_helpers import create_audit_log   # noqa: E402
from database import SessionLocal            # noqa: E402
from models import Requisite                 # noqa: E402
from utils import repair_requisite, requisite_issues  # noqa: E402

FIELDS = ("inn", "account_number", "bik")
LABELS = {"inn": "ИНН", "account_number": "счёт", "bik": "БИК"}


def plan_for(req):
    """(что поменять, что не чинится) для одного реквизита."""
    repaired = repair_requisite(req.inn, req.account_number, req.bik)
    changes, hopeless = {}, []
    for field, new in zip(FIELDS, repaired):
        old = getattr(req, field)
        if new is None:
            if (old or "").strip():
                hopeless.append("%s=%r" % (LABELS[field], old))
            continue
        if new != (old or ""):
            changes[field] = (old, new)
    return changes, hopeless


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true",
                        help="записать изменения (по умолчанию только показать)")
    parser.add_argument("--all", action="store_true",
                        help="включая неактивные реквизиты")
    args = parser.parse_args()

    session = SessionLocal()
    try:
        query = session.query(Requisite)
        if not args.all:
            query = query.filter(Requisite.is_active == True)  # noqa: E712
        rows = query.order_by(Requisite.employee_name).all()

        fixed = touched = 0
        needs_reentry = []

        for req in rows:
            changes, hopeless = plan_for(req)
            if not changes and not hopeless:
                continue

            print("%s  (id=%s)" % (req.employee_name, req.id))
            for field, (old, new) in changes.items():
                print("    %-6s %r -> %r" % (LABELS[field], old, new))
            for item in hopeless:
                print("    !! не чинится: %s" % item)
            print()

            if hopeless:
                needs_reentry.append((req.employee_name, req.id, ", ".join(hopeless)))
            if not changes:
                continue

            touched += 1
            fixed += len(changes)
            if args.apply:
                old_value = {f: getattr(req, f) for f in FIELDS}
                for field, (_, new) in changes.items():
                    setattr(req, field, new)
                create_audit_log(
                    session, None, None,
                    "requisite_repaired", "requisite", req.id, req.employee_name,
                    old_value=old_value,
                    new_value={f: getattr(req, f) for f in FIELDS},
                    comment="Автопочинка идентификаторов, испорченных float "
                            "(tools/repair_requisites.py)",
                )

        if args.apply:
            session.commit()
            print("ЗАПИСАНО: реквизитов %d, полей %d. Каждое изменение в журнале аудита."
                  % (touched, fixed))
        else:
            print("СУХОЙ ПРОГОН, база не изменена.")
            print("Починилось бы: реквизитов %d, полей %d." % (touched, fixed))
            print("Запись: python tools/repair_requisites.py --apply")

        if needs_reentry:
            print("\nВВЕСТИ ЗАНОВО РУКАМИ (цифры утеряны, восстановить нечем) — %d:"
                  % len(needs_reentry))
            for name, req_id, what in needs_reentry:
                print("  %-40s id=%-6s %s" % (name, req_id, what))

        still_bad = [r for r in rows if requisite_issues(r.inn, r.account_number, r.bik)]
        print("\nВсего реквизитов: %d, останется с проблемами: %d"
              % (len(rows), len(still_bad)))
    finally:
        session.close()


if __name__ == "__main__":
    main()

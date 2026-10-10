"""Диагностика дублей ФИО в users: несколько User на одно employee_name.

Только чтение — ничего не меняет. Колонка users.employee_name не уникальна, а
поиск по ФИО (user_by_employee_name, реестр документов) берёт первую строку без
ORDER BY — какую именно, решает Postgres. Скрипт показывает, чем дубли
отличаются, чтобы решить, какую запись оставить.

    python tools/check_duplicate_users.py                  # все дубли
    python tools/check_duplicate_users.py --name Рахимбаев # поиск по ФИО

Дата создания берётся из audit_logs (user_created / user_created_from_shifts):
в users такой колонки нет, и у записей старше аудита её не будет.
Смены (shifts) привязаны к ФИО, а не к User, поэтому считаются на группу.
"""

import argparse
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import func                                        # noqa: E402

from database import SessionLocal                                  # noqa: E402
from document_helpers import citizenship_display, user_by_employee_name  # noqa: E402
from models import AuditLog, EmployeeDocument, Shift, User         # noqa: E402
from utils import normalize_text                                   # noqa: E402

CREATE_ACTIONS = ("user_created", "user_created_from_shifts")


def duplicate_groups(session, name_filter=""):
    """{нормализованное ФИО: [User, ...]} — только где User больше одного."""
    query = session.query(User)
    if name_filter:
        query = query.filter(User.employee_name.ilike("%%%s%%" % name_filter))
    groups = defaultdict(list)
    for user in query.order_by(User.id).all():
        groups[normalize_text(user.employee_name)].append(user)
    return {name: users for name, users in sorted(groups.items()) if len(users) > 1}


def created_at_by_user(session, user_ids):
    rows = (
        session.query(AuditLog.entity_id, func.min(AuditLog.created_at))
        .filter(
            AuditLog.entity_type == "user",
            AuditLog.action.in_(CREATE_ACTIONS),
            AuditLog.entity_id.in_([str(uid) for uid in user_ids]),
        )
        .group_by(AuditLog.entity_id)
        .all()
    )
    return {int(entity_id): created for entity_id, created in rows}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="", help="фильтр по части ФИО")
    args = ap.parse_args()

    session = SessionLocal()
    try:
        groups = duplicate_groups(session, args.name)
        if not groups:
            print("дублей ФИО в users не найдено")
            return

        user_ids = [u.id for users in groups.values() for u in users]
        names = list(groups)
        created = created_at_by_user(session, user_ids)
        docs_by_user = dict(
            session.query(EmployeeDocument.user_id, func.count(EmployeeDocument.id))
            .filter(EmployeeDocument.user_id.in_(user_ids))
            .group_by(EmployeeDocument.user_id)
            .all()
        )
        orphan_docs = dict(
            session.query(EmployeeDocument.employee_name, func.count(EmployeeDocument.id))
            .filter(EmployeeDocument.employee_name.in_(names), EmployeeDocument.user_id.is_(None))
            .group_by(EmployeeDocument.employee_name)
            .all()
        )
        shifts_by_name = dict(
            session.query(Shift.employee, func.count(Shift.id))
            .filter(Shift.employee.in_(names))
            .group_by(Shift.employee)
            .all()
        )

        conflicts = 0
        for name, users in groups.items():
            picked = user_by_employee_name(session, name)
            citizenships = {citizenship_display(session, u) for u in users}
            differs = len(citizenships) > 1 or len({bool(u.is_student) for u in users}) > 1
            conflicts += differs

            print("%s  (записей: %d, смен на ФИО: %d)" % (name, len(users), shifts_by_name.get(name, 0)))
            for user in users:
                when = created.get(user.id)
                print("    id=%-5s роль=%-12s гражданство=%-14s тел=%-14s создан=%s  документов=%d%s%s" % (
                    user.id,
                    user.role or "—",
                    citizenship_display(session, user) or "—",
                    user.phone or "—",
                    when.strftime("%Y-%m-%d %H:%M") if when else "—",
                    docs_by_user.get(user.id, 0),
                    "  студент" if user.is_student else "",
                    "  ← берёт реестр" if picked is not None and picked.id == user.id else "",
                ))
                if user.employee_name != name:
                    print("        ФИО в базе: %r" % (user.employee_name,))
            if orphan_docs.get(name):
                print("    документов без user_id на это ФИО: %d" % orphan_docs[name])
            if differs:
                print("    !! записи различаются гражданством/студенчеством — набор документов зависит от выбора")
            print()

        print("ФИО с дублями: %d, записей: %d, с расхождением гражданства: %d"
              % (len(groups), len(user_ids), conflicts))
    finally:
        session.rollback()
        session.close()


if __name__ == "__main__":
    main()

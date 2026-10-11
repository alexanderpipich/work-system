"""
Выключить у всех контактов ТК флаги рассылок: БП (for_planning), сверки
(for_reconciliation), смены без плана (for_unplanned). Контакты остаются
активными и видны в карточке ТК; включать рассылку — по одному в карточке.

    python scripts/disable_store_mailings.py           # сухой прогон
    python scripts/disable_store_mailings.py --apply
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_helpers import create_audit_log  # noqa: E402
from database import SessionLocal           # noqa: E402
from models import StoreContact             # noqa: E402

FLAGS = ("for_planning", "for_reconciliation", "for_unplanned")


def disable_store_mailings(session, apply=False):
    """{флаг: сколько контактов было включено}. Коммит — на вызывающем."""
    counts = {flag: 0 for flag in FLAGS}
    for contact in session.query(StoreContact).all():
        for flag in FLAGS:
            if getattr(contact, flag):
                counts[flag] += 1
                if apply:
                    setattr(contact, flag, False)
    if apply and any(counts.values()):
        create_audit_log(session, None, None, "store_contacts.mailings_disabled", "store_contact", None,
                         "Рассылки ТК выключены у всех контактов", new_value=counts)
    return counts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    session = SessionLocal()
    try:
        counts = disable_store_mailings(session, apply=args.apply)
        print(f"БП: {counts['for_planning']}, сверки: {counts['for_reconciliation']}, "
              f"смены без плана: {counts['for_unplanned']}")
        if args.apply:
            session.commit()
            print("Флаги рассылок выключены.")
        else:
            print("Сухой прогон — столько контактов с включённым флагом; --apply для записи.")
    finally:
        session.close()


if __name__ == "__main__":
    main()

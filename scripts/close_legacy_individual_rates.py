"""
Закрыть индивидуальные ставки из старой базы (П4.5): active_to = 31.08.2026.

Не удаляет (правило «старое не режем»): до 31.08 ставки действуют как раньше,
с 01.09 подбор берёт базовую сетку. Закрываются 12 личных ставок и 3 ставки по ТК,
найденные при сверке с ведомостью за сентябрь, — только открытые (без active_to
или с более поздним) и только из списка ниже: новые индивидуальные ставки не трогаются.

    python scripts/close_legacy_individual_rates.py           # сухой прогон
    python scripts/close_legacy_individual_rates.py --apply
"""

import argparse
import os
import sys
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_helpers import create_audit_log                       # noqa: E402
from database import SessionLocal                                # noqa: E402
from models import Rate                                          # noqa: E402
from store_helpers import extract_tk_number                      # noqa: E402
from utils import normalize_person_name, normalize_text          # noqa: E402

CLOSE_DATE = date(2026, 8, 31)
LEGACY_EMPLOYEES = [
    "Загребельная Ольга Евгеньевна", "Иванова Татьяна Михайловна", "Эшкабилов Отабек Байпулатович",
    "Ковалева Людмила Владимировна", "Арден Юлия Владимировна", "Громова Людмила Евгеньевна",
    "Бикбаева Екатерина Сергеевна", "Мирзокулова Рушана Шухрат Кизи", "Зоиров Хуршед Шукурович",
    "Рабимов Рустам Негматович", "Набережная Наталья Александровна", "Гелдиева Багул",
]
LEGACY_STORE_TKS = [1344, 115, 48]  # Лента-1344 Химки, Лента-115 Брянск, Лента-48 «Повар осн.»


def legacy_rates(session):
    """Открытые на CLOSE_DATE индивидуальные ставки из списка."""
    employees = {normalize_person_name(name) for name in LEGACY_EMPLOYEES}
    result = []
    for rate in session.query(Rate).order_by(Rate.id).all():
        if rate.active_to is not None and rate.active_to <= CLOSE_DATE:
            continue
        by_employee = normalize_person_name(rate.employee_name) in employees if rate.employee_name else False
        by_store = (not normalize_text(rate.employee_name) and normalize_text(rate.store)
                    and extract_tk_number(rate.store) in LEGACY_STORE_TKS)
        if by_employee or by_store:
            result.append(rate)
    return result


def close_legacy_rates(session, apply=False):
    """[Rate] — закрытые (или к закрытию). Коммит — на вызывающем."""
    rates = legacy_rates(session)
    if apply:
        for rate in rates:
            old = rate.active_to
            rate.active_to = CLOSE_DATE
            create_audit_log(session, None, None, "rate.legacy_closed", "rate", rate.id,
                             rate.employee_name or rate.store,
                             old_value={"active_to": old.isoformat() if old else None},
                             new_value={"active_to": CLOSE_DATE.isoformat()},
                             comment="scripts/close_legacy_individual_rates.py")
    return rates


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    session = SessionLocal()
    try:
        rates = close_legacy_rates(session, apply=args.apply)
        for rate in rates:
            who = rate.employee_name or rate.store
            print(f"  {who} · {rate.service} · {rate.format or '—'} · {rate.hourly_rate:g} ₽")
        if args.apply:
            session.commit()
            print(f"Закрыто ставок: {len(rates)} (действуют по {CLOSE_DATE:%d.%m.%Y})")
        else:
            print(f"Будет закрыто: {len(rates)} (сухой прогон, --apply для записи)")
    finally:
        session.close()


if __name__ == "__main__":
    main()

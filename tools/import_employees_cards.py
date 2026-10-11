"""Импорт сотрудников, ТМ и карт из файла авансов («Аванс_…xlsx») — П1-Г.

Сухой прогон по умолчанию: всё считается в транзакции и откатывается.
С --apply — записывает, на каждую запись create_audit_log.

    python tools/import_employees_cards.py --file "Аванс_28.09.2026-04.10.2026.xlsx"
    python tools/import_employees_cards.py --file ... --apply

Колонки ищутся по заголовку (регистр, ё/е, пробелы не важны): Сотрудник,
Номер карты, Месяц, Год, Телефон, Получатель ФИО, Банк получателя, Менеджер,
Способ выплаты, Назначение. «Итого к выплате», «Проект» и прочие игнорируются.

- Сотрудник: User по employee_name_norm; нет — создаётся без кабинета
  (role=employee, phone и password_hash пустые).
- ТМ («Менеджер»): ФИО сравнивается по множеству слов («Пиунов Андрей» =
  «Андрей Пиунов»). Сначала точное совпадение с любым User; затем — однозначно
  содержащий эти слова User не с ролью employee («Пипич» → superadmin
  «Пипич Александр Владимирович», роль не меняется). Иначе создаётся User с
  ролью tm и ФИО как в файле. Сотруднику ставится tm_id.
- Реквизит: активная запись сотрудника обновляется, нет — создаётся. Карта
  короче 16 цифр не сохраняется (строка в «проблемы»), остальное сохраняется.
  Банк — через алиасы; «наличные» в банке/месяце/способе/номере карты →
  payout_method=cash.
  Получатель ≠ сотрудник → третье лицо. Реквизит из реального файла выплат
  помечается проверенным (is_verified) — иначе табель его не примет.
"""

import argparse
import os
import re
import sys
from collections import Counter, OrderedDict
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_helpers import create_audit_log                             # noqa: E402
from models import Requisite, User                                     # noqa: E402
from rbac import ROLE_EMPLOYEE, ROLE_TM, canonical_role                # noqa: E402
from time_helpers import now_utc                                       # noqa: E402
from utils import (                                                    # noqa: E402
    PAYOUT_CARD,
    PAYOUT_CARD_PHONE,
    PAYOUT_CASH,
    card_number_issues,
    find_user_by_name,
    normalize_card_expiry,
    normalize_card_number,
    normalize_card_phone,
    normalize_person_name,
    normalize_text,
)

# Поле → варианты заголовка (после _header_key).
COLUMNS = {
    "employee": ["сотрудник"],
    "card": ["номер карты"],
    "month": ["месяц"],
    "year": ["год"],
    "phone": ["телефон"],
    "recipient": ["получатель фио"],
    "bank": ["банк получателя"],
    "manager": ["менеджер"],
    "method": ["способ выплаты"],
    "purpose": ["назначение"],
}

# Ключ банка (_bank_key) → каноничное имя.
BANK_ALIASES = {
    "сбер": "Сбербанк", "сбербанк": "Сбербанк",
    "тбанк": "Т-Банк", "тинькоф": "Т-Банк", "тинькофф": "Т-Банк",
    "альфа": "Альфа-Банк", "альфабанк": "Альфа-Банк",
    "озон": "Озон Банк", "озонбанк": "Озон Банк",
    "втб": "ВТБ",
    "яндекс": "Яндекс Банк", "яндексбанк": "Яндекс Банк",
    "райффайзен": "Райффайзенбанк", "райффайзенбанк": "Райффайзенбанк",
    "райфайзен": "Райффайзенбанк", "райфайзенбанк": "Райффайзенбанк",
    "газпром": "Газпромбанк", "газпромбанк": "Газпромбанк",
    # П4.2: редкие банки из файлов авансов.
    "псб": "ПСБ", "промсвязьбанк": "ПСБ",
    "росбанк": "Росбанк",
    "ренесанс": "Ренессанс Банк", "ренессанс": "Ренессанс Банк", "ренессансбанк": "Ренессанс Банк",
    "фора": "Фора-Банк", "форабанк": "Фора-Банк",
    "мтс": "МТС Банк", "мтсбанк": "МТС Банк",
    "отп": "ОТП Банк", "отпбанк": "ОТП Банк",
    "рсб": "Банк Русский Стандарт", "русскийстандарт": "Банк Русский Стандарт",
    "халва": "Совкомбанк", "совком": "Совкомбанк", "совкомбанк": "Совкомбанк",  # «Халва» — карта Совкомбанка
    "санктпетербург": "Банк «Санкт-Петербург»", "банксанктпетербург": "Банк «Санкт-Петербург»",
    "кредитевропа": "Кредит Европа Банк", "кредитевропабанк": "Кредит Европа Банк",
    "вбрр": "ВБРР",
}
CASH_WORD = "наличные"


def _header_key(value):
    return normalize_person_name(value)


def _bank_key(value):
    return re.sub(r"[\s.\-]+", "", normalize_person_name(value))


def canonical_bank(value):
    """(имя банка, известен ли). Неизвестный банк сохраняется как ввели."""
    raw = normalize_text(value)
    if not raw:
        return "", True
    canon = BANK_ALIASES.get(_bank_key(raw))
    return (canon, True) if canon else (raw, False)


def payout_method_from(method, bank, month, card=None):
    """Способ выплаты из колонок файла. «наличные» где угодно (в т.ч. вместо
    номера карты) — наличные."""
    if any(_bank_key(v) == CASH_WORD for v in (method, bank, month, card)):
        return PAYOUT_CASH
    key = _bank_key(method)
    if key == "карта":
        return PAYOUT_CARD
    return PAYOUT_CARD_PHONE  # «Карта/номер телефона», «Карта/телефон», пусто


def name_words(value):
    return frozenset(normalize_person_name(value).split())


def read_rows(path):
    """[(номер строки Excel, {поле: значение})], пропуская строки без сотрудника."""
    import openpyxl

    workbook = openpyxl.load_workbook(path, read_only=True, data_only=True)
    sheet = workbook.worksheets[0]
    rows = sheet.iter_rows(values_only=True)
    header = [_header_key(cell) for cell in next(rows)]
    index = {}
    for field, variants in COLUMNS.items():
        for position, title in enumerate(header):
            if title in variants:
                index[field] = position
                break
    if "employee" not in index:
        raise ValueError("Не найдена колонка «Сотрудник»")

    result = []
    for number, row in enumerate(rows, start=2):
        record = {field: (row[pos] if pos < len(row) else None) for field, pos in index.items()}
        if normalize_text(record.get("employee")):
            result.append((number, record))
    workbook.close()
    return result


class TmResolver:
    """Менеджер из файла → User (существующий или новый tm)."""

    def __init__(self, session, apply):
        self.session = session
        self.apply = apply
        self.cache = {}
        self.created = []
        self.linked_existing = OrderedDict()

    def resolve(self, raw_name):
        name = normalize_text(raw_name)
        words = name_words(name)
        if not words:
            return None
        if words in self.cache:
            return self.cache[words]

        users = self.session.query(User).all()
        exact = [u for u in users if name_words(u.employee_name) == words]
        broader = [
            u for u in users
            if words < name_words(u.employee_name) and canonical_role(u) != ROLE_EMPLOYEE
        ]
        if len(exact) == 1:
            user = exact[0]
        elif not exact and len(broader) == 1:
            user = broader[0]
        else:
            user = None

        if user is None:
            user = User(employee_name=name, role=ROLE_TM, is_admin=False)
            self.session.add(user)
            self.session.flush()
            self.created.append(name)
            if self.apply:
                create_audit_log(
                    self.session, None, None, "user_created", "user", user.id, user.employee_name,
                    new_value={"role": ROLE_TM}, comment="import_employees_cards: ТМ из колонки «Менеджер»",
                )
        elif user.employee_name != name:
            self.linked_existing[name] = "%s (ID %s, %s)" % (user.employee_name, user.id, user.role)
        self.cache[words] = user
        return user


def _active_requisite(session, user):
    return (
        session.query(Requisite)
        .filter(Requisite.is_active == True, Requisite.user_id == user.id)  # noqa: E712
        .order_by(Requisite.id.desc())
        .first()
        or session.query(Requisite)
        .filter(Requisite.is_active == True, Requisite.employee_name == user.employee_name)  # noqa: E712
        .order_by(Requisite.id.desc())
        .first()
    )


def import_rows(session, rows, apply=False, source="file"):
    """Импорт строк. Возвращает отчёт (dict). Коммит/откат — на вызывающем."""
    tms = TmResolver(session, apply)
    stats = Counter()
    problems = []
    unknown_banks = Counter()

    for number, record in rows:
        name = normalize_text(record.get("employee"))

        user = find_user_by_name(session, name)
        created_user = user is None
        if created_user:
            user = User(employee_name=name, role=ROLE_EMPLOYEE, is_admin=False)
            session.add(user)
            session.flush()
            stats["employees_created"] += 1
        old_tm = user.tm_id

        tm = tms.resolve(record.get("manager"))
        if tm is not None and tm.id != user.id:
            user.tm_id = tm.id
        elif normalize_text(record.get("manager")) == "":
            stats["no_manager"] += 1
        if not created_user and user.tm_id != old_tm:
            stats["employees_updated"] += 1
        elif not created_user:
            stats["employees_unchanged"] += 1

        if apply and (created_user or user.tm_id != old_tm):
            create_audit_log(
                session, None, None, "user_created" if created_user else "user_updated",
                "user", user.id, user.employee_name,
                old_value=None if created_user else {"tm_id": old_tm},
                new_value={"tm_id": user.tm_id, "role": user.role},
                comment="import_employees_cards: %s" % source,
            )

        # --- реквизит
        method = payout_method_from(record.get("method"), record.get("bank"), record.get("month"), record.get("card"))
        bank, known = canonical_bank(record.get("bank"))
        if _bank_key(bank) == CASH_WORD:
            bank = ""
        elif not known:
            unknown_banks[bank] += 1

        card = normalize_card_number(normalize_text(record.get("card")))
        if _bank_key(card) == CASH_WORD:
            card = ""
        card_problem = card_number_issues(card) if card else []
        if card_problem:
            problems.append((number, name, "%s — карта «%s» не сохранена" % (card_problem[0], card)))
            card = ""
        if method == PAYOUT_CARD and not card:
            problems.append((number, name, "способ «Карта», а годной карты нет"))

        recipient = normalize_text(record.get("recipient"))
        third_party = bool(recipient) and normalize_person_name(recipient) != normalize_person_name(name)

        requisite = _active_requisite(session, user)
        created_req = requisite is None
        if created_req:
            requisite = Requisite(
                user_id=user.id, employee_name=user.employee_name, is_active=True, created_at=now_utc(),
            )
            session.add(requisite)
        old_value = None if created_req else {
            "payout_method": requisite.payout_method, "card_number": requisite.card_number,
            "card_phone": requisite.card_phone, "card_expiry": requisite.card_expiry,
            "bank_name": requisite.bank_name, "is_third_party": requisite.is_third_party,
            "recipient_name": requisite.recipient_name,
        }

        requisite.user_id = user.id
        requisite.payout_method = method
        if card:
            requisite.card_number = card
        phone = normalize_card_phone(record.get("phone"))
        if phone:
            requisite.card_phone = phone
        expiry = normalize_card_expiry(record.get("month"), record.get("year")) if record.get("year") else ""
        if expiry:
            requisite.card_expiry = expiry
        if bank:
            requisite.bank_name = bank
        requisite.is_third_party = third_party
        requisite.recipient_name = recipient if third_party else None
        if not requisite.is_verified:
            requisite.is_verified = True
            requisite.verified_at = now_utc()
        requisite.updated_at = now_utc()
        session.flush()

        if third_party:
            stats["third_party"] += 1
        stats["methods_" + method] += 1
        new_value = {
            "payout_method": requisite.payout_method, "card_number": requisite.card_number,
            "card_phone": requisite.card_phone, "card_expiry": requisite.card_expiry,
            "bank_name": requisite.bank_name, "is_third_party": requisite.is_third_party,
            "recipient_name": requisite.recipient_name,
        }
        if created_req:
            stats["requisites_created"] += 1
        elif new_value != old_value:
            stats["requisites_updated"] += 1
        else:
            stats["requisites_unchanged"] += 1
        if apply and new_value != old_value:
            create_audit_log(
                session, None, None, "requisite_updated", "requisite", requisite.id, requisite.employee_name,
                old_value=old_value, new_value=new_value, comment="import_employees_cards: %s" % source,
            )

    return {
        "rows": len(rows),
        "stats": stats,
        "tm_created": tms.created,
        "tm_linked_existing": dict(tms.linked_existing),
        "problems": problems,
        "unknown_banks": unknown_banks,
    }


def print_report(report, apply):
    stats = report["stats"]
    print("Режим: %s" % ("ЗАПИСЬ (--apply)" if apply else "сухой прогон, ничего не записано"))
    print("Строк с сотрудником: %d" % report["rows"])
    print("Сотрудники: создано %d, обновлён ТМ %d, без изменений %d" % (
        stats["employees_created"], stats["employees_updated"], stats["employees_unchanged"]))
    print("ТМ: создано %d — %s" % (len(report["tm_created"]), ", ".join(report["tm_created"]) or "—"))
    for name, target in report["tm_linked_existing"].items():
        print("    «%s» → существующий %s" % (name, target))
    print("Строк без менеджера: %d" % stats["no_manager"])
    print("Реквизиты: создано %d, обновлено %d, без изменений %d" % (
        stats["requisites_created"], stats["requisites_updated"], stats["requisites_unchanged"]))
    print("Третьи лица: %d" % stats["third_party"])
    print("Способы: карта/телефон %d, карта %d, наличные %d" % (
        stats["methods_" + PAYOUT_CARD_PHONE], stats["methods_" + PAYOUT_CARD], stats["methods_" + PAYOUT_CASH]))
    if report["unknown_banks"]:
        print("Банки вне справочника алиасов (сохранены как в файле): %s" % ", ".join(
            "%s ×%d" % item for item in report["unknown_banks"].most_common()))
    print("Проблемные строки: %d" % len(report["problems"]))
    for number, name, reason in report["problems"]:
        print("    строка %d · %s · %s" % (number, name, reason))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Импорт сотрудников и карт из файла авансов")
    parser.add_argument("--file", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)

    from database import SessionLocal

    rows = read_rows(args.file)
    session = SessionLocal()
    try:
        report = import_rows(session, rows, apply=args.apply, source=Path(args.file).name)
        if args.apply:
            session.commit()
        else:
            session.rollback()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
    print_report(report, args.apply)
    return 0


if __name__ == "__main__":
    sys.exit(main())

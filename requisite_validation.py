"""Единый критерий пригодности реквизитов к выплате.

Критериев исторически два, и они НЕ ПЕРЕСЕКАЮТСЯ ни одним условием:

- фиксация табеля (`routers/payroll.py`) смотрит только на флаги строки —
  есть ли активная запись и проверена ли она, а в поля не заглядывает вовсе;
- проверка формата (`utils.requisite_issues`, ТЗ 004) смотрит только на
  содержимое ИНН/счёта/БИК и ничего не знает про флаги.

Отсюда дыра: реквизит с пустым ИНН и счётом проходит фиксацию табеля и
уходит в реестр пустыми ячейками. Модуль сводит оба слоя в один критерий и
разделяет последствия — одно дело «табель не зафиксировать», другое
«зафиксируется, но в банк уйдёт мусор».

П1-Г: основной путь выплаты — карта (payout_method), ИНН/счёт/БИК остались
альтернативой; для выплаты достаточно, чтобы годился хотя бы один путь.
"""

from utils import (
    PAYOUT_CARD,
    PAYOUT_CARD_PHONE,
    PAYOUT_CASH,
    luhn_valid,
    normalize_card_number,
    normalize_text,
    payout_method_issues,
    requisite_issues,
)

# Блокирует фиксацию табеля — ровно те условия, что проверяет payroll.
BLOCKS_PAYROLL = "blocks_payroll"
# Табель зафиксируется, но в платёжку уйдёт пустое или битое значение.
BAD_FOR_BANK = "bad_for_bank"
# Подозрительно, но выплате не мешает (контрольная сумма карты).
WARNING = "warning"


def _bank_issues(requisite):
    """Проблемы для выплаты. Пусто, если годен хотя бы один путь (П1-Г):
    наличные; карта; банк + телефон; ИНН + счёт + БИК. Выбранный способ решает
    только, какие проблемы показать, когда не годится ни один путь."""
    method = getattr(requisite, "payout_method", None) or PAYOUT_CARD_PHONE
    if method == PAYOUT_CASH:
        return []
    card_number = getattr(requisite, "card_number", None)
    card_phone = getattr(requisite, "card_phone", None)
    paths = {
        PAYOUT_CARD: payout_method_issues(PAYOUT_CARD, card_number, card_phone, requisite.bank_name),
        PAYOUT_CARD_PHONE: payout_method_issues(PAYOUT_CARD_PHONE, card_number, card_phone, requisite.bank_name),
    }
    if not all(paths.values()):
        return []
    legacy_issues = requisite_issues(requisite.inn, requisite.account_number, requisite.bik)
    if not legacy_issues:
        return []
    # Ни один путь не годен. Счёт показываем, только если его начинали заполнять,
    # иначе у каждой карты висели бы «ИНН/счёт/БИК не заполнены».
    started_legacy = any(normalize_text(v) for v in (requisite.inn, requisite.account_number, requisite.bik))
    method_issues = paths.get(method) or payout_method_issues(method, card_number, card_phone, requisite.bank_name)
    return method_issues + (legacy_issues if started_legacy else [])


def requisite_problems(requisite):
    """Что не так с реквизитом: [(вид, текст), ...]. Пустой список — годен."""
    problems = []

    if not requisite.is_active:
        problems.append((BLOCKS_PAYROLL, "Реквизит неактивен — табель не зафиксировать"))
    if not requisite.is_verified:
        problems.append((BLOCKS_PAYROLL, "Реквизиты не проверены — табель не зафиксировать"))

    for issue in _bank_issues(requisite):
        problems.append((BAD_FOR_BANK, issue))

    card = normalize_card_number(getattr(requisite, "card_number", None))
    if card.isdigit() and len(card) >= 16 and not luhn_valid(card):
        problems.append((WARNING, "Номер карты не проходит проверку Luhn — сверьте с сотрудником"))

    return problems


def blocks_payroll(requisite):
    """Остановит ли этот реквизит фиксацию табеля (критерий payroll как есть)."""
    return any(kind == BLOCKS_PAYROLL for kind, _ in requisite_problems(requisite))


def is_payable(requisite):
    """Годен ли реквизит и для фиксации, и для выплаты. Предупреждения не мешают."""
    return not any(kind != WARNING for kind, _ in requisite_problems(requisite))


def split_by_validity(requisites):
    """(проблемные, годные) — внутри каждого списка алфавит по ФИО.

    Проблемные наверх: их надо чинить, а не листать до них через весь реестр.
    """
    problematic, clean = [], []
    for requisite in requisites:
        (clean if is_payable(requisite) else problematic).append(requisite)

    def by_name(row):
        return normalize_text(row.employee_name).lower()

    return sorted(problematic, key=by_name), sorted(clean, key=by_name)

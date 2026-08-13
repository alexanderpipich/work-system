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
"""

from utils import normalize_text, requisite_issues

# Блокирует фиксацию табеля — ровно те условия, что проверяет payroll.
BLOCKS_PAYROLL = "blocks_payroll"
# Табель зафиксируется, но в платёжку уйдёт пустое или битое значение.
BAD_FOR_BANK = "bad_for_bank"


def requisite_problems(requisite):
    """Что не так с реквизитом: [(вид, текст), ...]. Пустой список — годен."""
    problems = []

    if not requisite.is_active:
        problems.append((BLOCKS_PAYROLL, "Реквизит неактивен — табель не зафиксировать"))
    if not requisite.is_verified:
        problems.append((BLOCKS_PAYROLL, "Реквизиты не проверены — табель не зафиксировать"))

    for issue in requisite_issues(requisite.inn, requisite.account_number, requisite.bik):
        problems.append((BAD_FOR_BANK, issue))

    return problems


def blocks_payroll(requisite):
    """Остановит ли этот реквизит фиксацию табеля (критерий payroll как есть)."""
    return any(kind == BLOCKS_PAYROLL for kind, _ in requisite_problems(requisite))


def is_payable(requisite):
    """Годен ли реквизит и для фиксации, и для выплаты."""
    return not requisite_problems(requisite)


def split_by_validity(requisites):
    """(проблемные, годные) — внутри каждого списка алфавит по ФИО.

    Проблемные наверх: их надо чинить, а не листать до них через весь реестр.
    """
    problematic, clean = [], []
    for requisite in requisites:
        (problematic if requisite_problems(requisite) else clean).append(requisite)

    def by_name(row):
        return normalize_text(row.employee_name).lower()

    return sorted(problematic, key=by_name), sorted(clean, key=by_name)

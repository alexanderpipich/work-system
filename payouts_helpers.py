"""Выплаты (П3): еженедельные авансы, табель за период, реестр выплат xlsx.

Правило: одна смена оплачивается один раз. Ключ смены — (сотрудник, магазин,
услуга, дата); оплачена, если её строка есть в прогоне fixed/sent/closed.
Аванс берёт только неоплаченные смены отмеченных сотрудников; табель за период
берёт все смены и вычитает уже выплаченное (advanced_amount).

Расчёт строк — payroll_run_helpers.build_run_items, тот же, что у fix_payroll.
"""

import os
from collections import OrderedDict
from datetime import timedelta
from io import BytesIO

from audit_helpers import create_audit_log
from file_storage import storage_save
from legal_entity_helpers import active_legal_entities
from manual_adjustments import parse_money
from models import (AdvanceSelection, AuditLog, ManualPayrollAdjustment, PayrollRun, PayrollRunItem,
                    ReferralPayout, ReferralPromo, Requisite, Shift, User)
from payroll_run_helpers import (ALL_STORES, PAID_RUN_STATUSES, RUN_KIND_ADVANCE, RUN_KIND_PERIOD,
                                 build_run_items, paid_shift_twins, shift_pay_key)
from referral_helpers import apply_confirmed_payouts_to_run
from service_catalog import build_service_resolver
from shift_helpers import is_no_plan_shift
from time_helpers import now_utc
from utils import (PAYOUT_CARD, PAYOUT_CARD_PHONE, PAYOUT_CASH, card_number_issues, find_user_by_name,
                   load_rates, normalize_card_number, normalize_person_name, normalize_text, pick_rate)

REFERRAL_SERVICE_ADVANCE = "Приведи друга"
REFERRAL_SERVICES = {REFERRAL_SERVICE_ADVANCE, "Премия АПД"}
CARRY_OVER_ACTION = "advance.selection.carry_over"
XLSX_CONTENT_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
REGISTRY_PREFIX = "generated_files/payouts"
REGISTRY_COLUMNS = [
    "Сотрудник", "Номер карты", "Месяц", "Год", "Телефон", "Адрес эл. почты", "Получатель ФИО",
    "Получатель Фамилия", "Получатель Имя2", "Получатель Отчество", "Банк получателя", "Комментарии",
    "Итого к выплате", "Проект", "Менеджер", "Назначение", "Способ выплаты", "Статус", "Исполнил",
    "Проверка карты", "Проверка тел",
]
PAYOUT_METHOD_LABELS = {
    PAYOUT_CARD_PHONE: "Карта/Номер телефона",
    PAYOUT_CARD: "Карта",
    PAYOUT_CASH: "Наличные",
}
NO_CARD_COMMENT = "нет карты — выплата невозможна"


def payout_project():
    """Колонка «Проект» реестра; задаётся env PAYOUT_PROJECT."""
    return os.getenv("PAYOUT_PROJECT", "Лента Оффлайн")


# ── Неделя аванса ────────────────────────────────────────────────────────────

def week_monday(day):
    return day - timedelta(days=day.weekday())


def default_week(today):
    """Прошлая неделя Пн–Вс."""
    return week_monday(today) - timedelta(days=7)


def advance_run_for_week(session, week_start):
    return (
        session.query(PayrollRun)
        .filter(PayrollRun.kind == RUN_KIND_ADVANCE, PayrollRun.date_from == week_start)
        .order_by(PayrollRun.id.desc())
        .first()
    )


def is_frozen(run):
    return bool(run and run.status in PAID_RUN_STATUSES)


def week_selection(session, week_start):
    """{нормализованное ФИО: AdvanceSelection}."""
    return {
        normalize_person_name(row.employee_name): row
        for row in session.query(AdvanceSelection).filter(AdvanceSelection.week_start == week_start).all()
    }


def carry_over_selection(session, request, user, week_start):
    """При первом открытии недели скопировать отметки прошлой недели.

    «Первое открытие» отмечается записью аудита advance.selection.carry_over —
    иначе снятые вручную галочки возвращались бы при каждом заходе.
    Возвращает число скопированных (None — неделя уже открывалась или заморожена).
    """
    marker = week_start.isoformat()
    done = session.query(AuditLog.id).filter(
        AuditLog.action == CARRY_OVER_ACTION, AuditLog.entity_id == marker,
    ).first()
    if done or is_frozen(advance_run_for_week(session, week_start)):
        return None
    existing = week_selection(session, week_start)
    copied = []
    for key, row in week_selection(session, week_start - timedelta(days=7)).items():
        if key in existing:
            continue
        session.add(AdvanceSelection(week_start=week_start, employee_name=row.employee_name,
                                     user_id=row.user_id, selected_by=row.selected_by))
        copied.append(row.employee_name)
    create_audit_log(session, request, user, CARRY_OVER_ACTION, "advance_week", marker,
                     f"Аванс {week_start:%d.%m.%Y}", new_value={"copied": len(copied)})
    session.commit()
    return len(copied)


def can_select(user, employee_user, permissions):
    """Может ли пользователь ставить/снимать галочку этому сотруднику."""
    if "payouts.advances.select_any" in permissions:
        return True
    if "payouts.advances.select_own" in permissions:
        return bool(employee_user and employee_user.tm_id == user.id)
    return False


def set_selection(session, request, user, week_start, employee_name, checked):
    employee_name = normalize_text(employee_name)
    key = normalize_person_name(employee_name)
    current = week_selection(session, week_start).get(key)
    if checked and not current:
        employee_user = find_user_by_name(session, employee_name)
        session.add(AdvanceSelection(week_start=week_start, employee_name=employee_name,
                                     user_id=employee_user.id if employee_user else None,
                                     selected_by=user.id))
        create_audit_log(session, request, user, "advance.selection.add", "advance_week",
                         week_start.isoformat(), employee_name)
    elif not checked and current:
        session.delete(current)
        create_audit_log(session, request, user, "advance.selection.remove", "advance_week",
                         week_start.isoformat(), employee_name)


def _week_shifts(session, week_start, names=None):
    query = session.query(Shift).filter(
        Shift.shift_date >= week_start,
        Shift.shift_date <= week_start + timedelta(days=6),
    )
    shifts = query.order_by(Shift.employee.asc(), Shift.store.asc(), Shift.service.asc(),
                            Shift.shift_date.asc()).all()
    if names is not None:
        keys = {normalize_person_name(n) for n in names}
        shifts = [s for s in shifts if normalize_person_name(s.employee) in keys]
    return shifts


def week_deductions(session, week_start):
    """{нормализованное ФИО: ManualPayrollAdjustment} — вычеты аванса недели (магазин «*»)."""
    rows = session.query(ManualPayrollAdjustment).filter(
        ManualPayrollAdjustment.store == ALL_STORES,
        ManualPayrollAdjustment.date_from == week_start,
        ManualPayrollAdjustment.date_to == week_start + timedelta(days=6),
        ManualPayrollAdjustment.status.in_(["active", "applied"]),
    ).order_by(ManualPayrollAdjustment.id.asc()).all()
    return {normalize_person_name(row.employee_name): row for row in rows}


def active_requisite(session, user, employee_name):
    query = session.query(Requisite).filter(Requisite.is_active == True)  # noqa: E712
    if user:
        found = query.filter(Requisite.user_id == user.id).order_by(Requisite.id.desc()).first()
        if found:
            return found
    return query.filter(Requisite.employee_name == normalize_text(employee_name)).order_by(Requisite.id.desc()).first()


def has_card(requisite):
    return bool(requisite and requisite.card_number and not card_number_issues(requisite.card_number))


def advance_week_rows(session, week_start):
    """Строки экрана аванса: по сотруднику — смены недели, расчёт, вычет, отметка."""
    run = advance_run_for_week(session, week_start)
    shifts = _week_shifts(session, week_start)
    twins = paid_shift_twins(session, shifts, exclude_run_id=run.id if run else None)
    rates = load_rates(session)
    resolve = build_service_resolver(session)
    selection = week_selection(session, week_start)
    previous = week_selection(session, week_start - timedelta(days=7))
    deductions = week_deductions(session, week_start)

    users = {u.employee_name_norm: u for u in session.query(User).all()}
    tm_names = {u.id: u.employee_name for u in users.values()}

    rows = OrderedDict()

    def row_for(name):
        key = normalize_person_name(name)
        if key not in rows:
            user = users.get(key)
            requisite = active_requisite(session, user, name)
            deduction = deductions.get(key)
            rows[key] = {
                "employee_name": normalize_text(name),
                "user": user,
                "tm_id": user.tm_id if user else None,
                "tm_name": tm_names.get(user.tm_id) if user and user.tm_id else "",
                "selected": key in selection,
                "hours": 0.0,
                "calc": 0.0,
                "paid_hours": 0.0,
                "shifts": [],
                "no_shifts": False,
                "deduction": deduction.amount if deduction else 0.0,
                "deduction_comment": (deduction.comment or "") if deduction else "",
                "has_card": has_card(requisite),
                "requisite": requisite,
            }
        return rows[key]

    for shift in shifts:
        row = row_for(shift.employee)
        twin = twins.get(shift_pay_key(shift.employee, shift.store, shift.service, shift.shift_date))
        rate = pick_rate(rates, shift, resolve=resolve)
        rate_value = rate.hourly_rate if rate else 0
        no_plan = is_no_plan_shift(shift)
        amount = 0 if (no_plan or twin) else (shift.hours or 0) * rate_value
        if twin:
            status = "Оплачено в табеле №%s" % twin.run_id
            row["paid_hours"] += shift.hours or 0
        elif no_plan:
            status = "Смена без плана — не оплачивается"
        elif not rate:
            status = "Не найдена ЧТС"
        else:
            status = ""
        row["hours"] += shift.hours or 0
        row["calc"] += amount
        row["shifts"].append({"shift": shift, "rate": rate_value, "amount": amount,
                              "paid": bool(twin), "status": status, "no_rate": not rate and not no_plan and not twin})

    for key in list(selection) + list(previous):
        if key not in rows:
            source = selection.get(key) or previous.get(key)
            row = row_for(source.employee_name)
            row["no_shifts"] = True

    result = list(rows.values())
    for row in result:
        row["to_pay"] = row["calc"] + row["deduction"]
        row["no_rate"] = any(item["no_rate"] for item in row["shifts"])
    result.sort(key=lambda r: normalize_person_name(r["employee_name"]))
    return result


# ── Вычеты аванса ────────────────────────────────────────────────────────────

def save_week_deduction(session, request, user, week_start, employee_name, amount_raw, comment):
    """Вычет (или доплата) аванса — ManualPayrollAdjustment по (сотрудник, «*», неделя).

    Возвращает текст ошибки или None. Комментарий обязателен для ненулевой суммы.
    """
    employee_name = normalize_text(employee_name)
    amount = parse_money(amount_raw)
    comment = normalize_text(comment)
    week_end = week_start + timedelta(days=6)
    if amount and not comment:
        return "%s: укажите комментарий к вычету (ЛМК, штраф…)" % employee_name
    current = session.query(ManualPayrollAdjustment).filter(
        ManualPayrollAdjustment.employee_name == employee_name,
        ManualPayrollAdjustment.store == ALL_STORES,
        ManualPayrollAdjustment.date_from == week_start,
        ManualPayrollAdjustment.date_to == week_end,
        ManualPayrollAdjustment.status == "active",
    ).first()
    if not amount:
        if current:
            current.status = "deleted"
            current.deleted_by = user.id
            current.deleted_at = now_utc()
            create_audit_log(session, request, user, "manual_adjustment_deleted", "manual_payroll_adjustment",
                             current.id, f"{employee_name} / аванс {week_start}",
                             old_value={"amount": current.amount, "comment": current.comment})
        return None
    if current:
        if current.amount == amount and (current.comment or "") == comment:
            return None
        old = {"amount": current.amount, "comment": current.comment}
        current.amount = amount
        current.comment = comment
        create_audit_log(session, request, user, "manual_adjustment_updated", "manual_payroll_adjustment",
                         current.id, f"{employee_name} / аванс {week_start}", old_value=old,
                         new_value={"amount": amount, "comment": comment})
        return None
    adjustment = ManualPayrollAdjustment(
        employee_name=employee_name, store=ALL_STORES, date_from=week_start, date_to=week_end,
        amount=amount, comment=comment, status="active", created_by=user.id, created_at=now_utc(),
    )
    session.add(adjustment)
    session.flush()
    create_audit_log(session, request, user, "manual_adjustment_created", "manual_payroll_adjustment",
                     adjustment.id, f"{employee_name} / аванс {week_start}",
                     new_value={"amount": amount, "comment": comment, "store": ALL_STORES})
    return None


# ── Фиксация / расфиксация ───────────────────────────────────────────────────

def default_legal_entity(session):
    entities = active_legal_entities(session)
    return entities[0].name if entities else None


def fix_advance(session, request, user, week_start):
    """Зафиксировать аванс недели. Возвращает (run, ошибки)."""
    run = advance_run_for_week(session, week_start)
    if is_frozen(run):
        return run, ["Аванс за эту неделю уже зафиксирован"]

    selection = week_selection(session, week_start)
    names = [row.employee_name for row in selection.values()]
    shifts = _week_shifts(session, week_start, names)
    twins = paid_shift_twins(session, shifts, exclude_run_id=run.id if run else None)
    shifts = [s for s in shifts
              if shift_pay_key(s.employee, s.store, s.service, s.shift_date) not in twins]

    rates = load_rates(session)
    resolve = build_service_resolver(session)
    errors = [
        f"{s.employee} / {s.store} / {s.shift_date:%d.%m.%Y} — не найдена ЧТС"
        for s in shifts if not is_no_plan_shift(s) and not pick_rate(rates, s, resolve=resolve)
    ]
    if not selection:
        errors.append("Никто не отмечен")
    if errors:
        return run, errors

    if run is None:
        run = PayrollRun(kind=RUN_KIND_ADVANCE, date_from=week_start, date_to=week_start + timedelta(days=6),
                         created_by=user.id, created_at=now_utc())
        session.add(run)
    run.status = "fixed"
    run.fixed_by = user.id
    run.fixed_at = now_utc()
    run.legal_entity = run.legal_entity or default_legal_entity(session)
    session.flush()

    items = build_run_items(
        session, run, shifts,
        date_from=run.date_from, date_to=run.date_to, rates=rates, resolve=resolve,
        apply_lmk=False, apply_auto=False, manual="employee", link_paid=False,
    )
    # Вычеты, попавшие в строки, — применены этим авансом (при расфиксации вернутся).
    applied_names = {normalize_text(item.employee_name) for item in items}
    for adjustment in session.query(ManualPayrollAdjustment).filter(
        ManualPayrollAdjustment.store == ALL_STORES,
        ManualPayrollAdjustment.date_from == run.date_from,
        ManualPayrollAdjustment.date_to == run.date_to,
        ManualPayrollAdjustment.status == "active",
        ManualPayrollAdjustment.applied_run_id == None,  # noqa: E711
    ).all():
        if normalize_text(adjustment.employee_name) in applied_names:
            adjustment.status = "applied"
            adjustment.applied_run_id = run.id

    referral = apply_confirmed_payouts_to_run(
        session, request, user, run.id,
        service=REFERRAL_SERVICE_ADVANCE, comment="Приведи друга (реферальная премия)",
    )
    create_audit_log(session, request, user, "payroll_run_created", "payroll_run", run.id,
                     f"Аванс {run.date_from} - {run.date_to}",
                     new_value={"kind": run.kind, "status": run.status, "items_count": len(items),
                                "employees": len(applied_names), "referral_rows": referral})
    session.commit()
    return run, []


def unfix_run(session, request, user, run):
    """fixed → draft: строки удаляются, вычеты и премии возвращаются в активные."""
    if not run or run.status != "fixed":
        return "Расфиксировать можно только зафиксированный (не отправленный) прогон"
    session.query(PayrollRunItem).filter(PayrollRunItem.run_id == run.id).delete()
    restored = 0
    for adjustment in session.query(ManualPayrollAdjustment).filter(
        ManualPayrollAdjustment.applied_run_id == run.id
    ).all():
        adjustment.status = "active"
        adjustment.applied_run_id = None
        restored += 1
    payouts = 0
    for payout in session.query(ReferralPayout).filter(ReferralPayout.run_id == run.id).all():
        payout.run_id = None
        promo = session.query(ReferralPromo).filter(ReferralPromo.id == payout.promo_id).first()
        if promo and promo.status == "paid":
            promo.status = "threshold_reached"
        payouts += 1
    old = {"status": run.status, "fixed_at": run.fixed_at}
    run.status = "draft"
    run.fixed_by = None
    run.fixed_at = None
    create_audit_log(session, request, user, "payroll_run_unfixed", "payroll_run", run.id,
                     f"{run.date_from} - {run.date_to}", old_value=old,
                     new_value={"status": "draft", "manual_restored": restored, "referral_restored": payouts})
    session.commit()
    return None


def unsend_run(session, request, user, run):
    """sent → fixed (чтобы затем расфиксировать)."""
    if not run or run.status != "sent":
        return "Вернуть в «зафиксирован» можно только отправленный прогон"
    old = {"status": run.status, "sent_at": run.sent_at}
    run.status = "fixed"
    run.sent_by = None
    run.sent_at = None
    create_audit_log(session, request, user, "payroll_run_unsent", "payroll_run", run.id,
                     f"{run.date_from} - {run.date_to}", old_value=old, new_value={"status": "fixed"})
    session.commit()
    return None


# ── Реестр выплат xlsx ───────────────────────────────────────────────────────

def _expiry_parts(card_expiry):
    if card_expiry and "/" in card_expiry:
        month, year = card_expiry.split("/", 1)
        return month, year
    return "", ""


def registry_rows(session, run):
    """Строки реестра: одна на сотрудника (Σ total_amount смен) + премии отдельно."""
    purpose = "Аванс" if run.kind == RUN_KIND_ADVANCE else "Выплата"
    items = session.query(PayrollRunItem).filter(PayrollRunItem.run_id == run.id).order_by(PayrollRunItem.id).all()
    users = {u.employee_name_norm: u for u in session.query(User).all()}
    tm_names = {u.id: u.employee_name for u in users.values()}

    totals = OrderedDict()
    referral = []
    for item in items:
        if item.shift_date is None and (item.service or "") in REFERRAL_SERVICES:
            referral.append(item)
            continue
        key = normalize_person_name(item.employee_name)
        name, amount = totals.get(key, (item.employee_name, 0.0))
        totals[key] = (name, amount + (item.total_amount or 0))

    def build(name, amount, row_purpose):
        user = users.get(normalize_person_name(name))
        requisite = active_requisite(session, user, name)
        method = (requisite.payout_method if requisite else None) or PAYOUT_CARD_PHONE
        comment = ""
        card = normalize_card_number(requisite.card_number) if requisite and requisite.card_number else ""
        if method == PAYOUT_CASH:
            label = PAYOUT_METHOD_LABELS[PAYOUT_CASH]
        elif not has_card(requisite):
            label = PAYOUT_METHOD_LABELS[PAYOUT_CASH]
            comment = NO_CARD_COMMENT
        else:
            label = PAYOUT_METHOD_LABELS.get(method, PAYOUT_METHOD_LABELS[PAYOUT_CARD_PHONE])
        month, year = _expiry_parts(requisite.card_expiry if requisite else None)
        recipient = (requisite.recipient_name if requisite and requisite.is_third_party
                     and requisite.recipient_name else name)
        return {
            "Сотрудник": name,
            "Номер карты": card,
            "Месяц": month,
            "Год": year,
            "Телефон": (requisite.card_phone or "") if requisite else "",
            "Адрес эл. почты": "",
            "Получатель ФИО": recipient,
            "Получатель Фамилия": "",
            "Получатель Имя2": "",
            "Получатель Отчество": "",
            "Банк получателя": (requisite.bank_name or "") if requisite else "",
            "Комментарии": comment,
            "Итого к выплате": round(amount, 2),
            "Проект": payout_project(),
            "Менеджер": tm_names.get(user.tm_id, "") if user and user.tm_id else "",
            "Назначение": row_purpose,
            "Способ выплаты": label,
            "Статус": "",
            "Исполнил": "",
            "Проверка карты": "",
            "Проверка тел": "",
        }

    rows = [build(name, amount, purpose) for name, amount in totals.values() if round(amount, 2) > 0]
    rows += [build(item.employee_name, item.total_amount or 0, REFERRAL_SERVICE_ADVANCE)
             for item in referral if round(item.total_amount or 0, 2) > 0]
    rows.sort(key=lambda r: (normalize_person_name(r["Сотрудник"]), r["Назначение"] == REFERRAL_SERVICE_ADVANCE))
    return rows


def registry_filename(run):
    prefix = "Аванс" if run.kind == RUN_KIND_ADVANCE else "Выплата"
    return f"{prefix}_{run.date_from:%d.%m.%Y}-{run.date_to:%d.%m.%Y}.xlsx"


def build_registry_xlsx(rows):
    from openpyxl import Workbook

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Лист"
    sheet.append(REGISTRY_COLUMNS)
    for row in rows:
        sheet.append([row[column] for column in REGISTRY_COLUMNS])
    buffer = BytesIO()
    workbook.save(buffer)
    return buffer.getvalue()


def save_registry(session, run):
    """Сформировать реестр, сохранить копию в хранилище; вернуть (ключ, имя файла)."""
    filename = registry_filename(run)
    content = build_registry_xlsx(registry_rows(session, run))
    stamp = now_utc().strftime("%Y%m%d-%H%M%S")
    key = f"{REGISTRY_PREFIX}/{run.kind}/{run.id}/{stamp}_{filename}"
    storage_save(key, content, content_type=XLSX_CONTENT_TYPE)
    return key, filename

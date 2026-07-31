"""АПД «Приведи друга» — расчётная логика (порог часов → премия выгодоприобретателю).

Хук проверки порога зовётся из загрузчика смен (как recompute мониторинга). Премия
кладётся pending-корректировкой, требующей подтверждения человека и блокирующей
формирование табеля. Всё — по образцу ЛМК/мониторинга. Одноразово (уникальный
приведённый; после выплаты акция paid).
"""

from sqlalchemy import text
from sqlalchemy import func

from audit_helpers import create_audit_log
from database import engine
from models import (
    PayrollRunItem,
    ReferralPayout,
    ReferralPromo,
    ReferralSettings,
    Shift,
)
from time_helpers import business_today, now_utc


def ensure_referral_settings():
    """Создать таблицы (create_all делает это) и синглтон настроек с дефолтами."""
    from sqlalchemy.orm import sessionmaker

    session = sessionmaker(bind=engine)()
    try:
        if session.query(ReferralSettings).first() is None:
            session.add(ReferralSettings(hours_threshold=150, bonus_amount=5000))
            session.commit()
    finally:
        session.close()


def get_referral_settings(session):
    settings = session.query(ReferralSettings).first()
    if not settings:
        settings = ReferralSettings(hours_threshold=150, bonus_amount=5000)
        session.add(settings)
        session.flush()
    return settings


def referred_hours(session, referred_employee_name):
    """Сумма всех часов приведённого (все смены за всю историю)."""
    return session.query(func.coalesce(func.sum(Shift.hours), 0)).filter(
        Shift.employee == referred_employee_name
    ).scalar() or 0


def check_referral_thresholds(session, request=None, user=None):
    """Проверить активные акции: набрал ли приведённый порог часов. Возвращает число
    сработавших. Идемпотентно (только active → после срабатывания promo уже не active)."""
    settings = get_referral_settings(session)
    threshold = settings.hours_threshold or 0
    today = business_today()
    created = 0

    for promo in session.query(ReferralPromo).filter(ReferralPromo.status == "active").all():
        hours = referred_hours(session, promo.referred_employee_name)
        if hours >= threshold:
            promo.status = "threshold_reached"
            promo.threshold_reached_at = today
            payout = ReferralPayout(
                promo_id=promo.id,
                beneficiary_user_id=promo.beneficiary_user_id,
                beneficiary_name=promo.beneficiary_name,
                amount=settings.bonus_amount or 0,
                status="pending",
                created_at=now_utc(),
            )
            session.add(payout)
            session.flush()
            create_audit_log(
                session, request, user, "referral_threshold_reached", "referral_promo",
                promo.id, promo.referred_employee_name,
                new_value={"hours": hours, "threshold": threshold, "payout_id": payout.id},
            )
            created += 1

    session.commit()
    return created


def pending_payouts(session):
    """Список pending-премий (блокируют формирование табеля)."""
    return (
        session.query(ReferralPayout)
        .filter(ReferralPayout.status == "pending")
        .order_by(ReferralPayout.id.asc())
        .all()
    )


def confirm_payout(session, request, user, payout_id):
    payout = session.query(ReferralPayout).filter(
        ReferralPayout.id == payout_id, ReferralPayout.status == "pending"
    ).first()
    if not payout:
        return None
    payout.status = "confirmed"
    payout.confirmed_by = user.id
    payout.confirmed_at = now_utc()
    create_audit_log(
        session, request, user, "referral_payout_confirmed", "referral_payout",
        payout.id, payout.beneficiary_name, new_value={"amount": payout.amount},
    )
    session.commit()
    return payout


def cancel_payout(session, request, user, payout_id):
    payout = session.query(ReferralPayout).filter(
        ReferralPayout.id == payout_id, ReferralPayout.status == "pending"
    ).first()
    if not payout:
        return None
    payout.status = "cancelled"
    payout.cancelled_by = user.id
    payout.cancelled_at = now_utc()
    promo = session.query(ReferralPromo).filter(ReferralPromo.id == payout.promo_id).first()
    if promo:
        promo.status = "cancelled"  # выплата отменена → акция закрыта без выплаты
    create_audit_log(
        session, request, user, "referral_payout_cancelled", "referral_payout",
        payout.id, payout.beneficiary_name, new_value={"amount": payout.amount},
    )
    session.commit()
    return payout


def apply_confirmed_payouts_to_run(session, request, user, run_id):
    """Подтверждённые, ещё не привязанные к табелю премии → строкой в этот прогон
    (для выгодоприобретателя) + промо paid. Возвращает число вставленных строк."""
    added = 0
    for payout in session.query(ReferralPayout).filter(
        ReferralPayout.status == "confirmed", ReferralPayout.run_id == None  # noqa: E711
    ).all():
        amount = payout.amount or 0
        session.add(PayrollRunItem(
            run_id=run_id,
            employee_name=payout.beneficiary_name or "—",
            store=None,
            service="Премия АПД",
            shift_date=None,
            hours=0, rate=0, amount=0,
            other_amount=amount, manual_adjustments_amount=amount,
            auto_adjustments_amount=0, lmk_amount=0, total_amount=amount,
            comment="Премия АПД (приведи друга)",
        ))
        payout.run_id = run_id
        promo = session.query(ReferralPromo).filter(ReferralPromo.id == payout.promo_id).first()
        if promo:
            promo.status = "paid"
        create_audit_log(
            session, request, user, "referral_payout_applied", "referral_payout",
            payout.id, payout.beneficiary_name, new_value={"run_id": run_id, "amount": amount},
        )
        added += 1
    return added

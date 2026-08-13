import os
from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


DEFAULT_APP_TIMEZONE = "Europe/Moscow"


def app_timezone():
    timezone_name = os.getenv("APP_TIMEZONE", DEFAULT_APP_TIMEZONE)
    try:
        return ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError:
        return ZoneInfo(DEFAULT_APP_TIMEZONE)


def now_utc():
    return datetime.now(timezone.utc)


def business_today():
    return datetime.now(app_timezone()).date()


# Граница закрытия прошлого месяца: до 7 числа включительно он ещё правится.
EDITABLE_PREVIOUS_MONTH_UNTIL_DAY = 7


def previous_month(today_date):
    """(месяц, год) предыдущего месяца. Порядок именно такой — не (год, месяц)."""
    if today_date.month == 1:
        return 12, today_date.year - 1
    return today_date.month - 1, today_date.year


def is_editable_month(shift_date, today_date):
    """Попадает ли дата в редактируемый период.

    Текущий месяц правится всегда, прошлый — только до 7 числа включительно,
    после чего закрывается. Одно правило на загрузчик смен и на рассылку
    «смена без плана»: иначе загрузчик уже не примет смену, а рассылка всё
    ещё будет звать по ней писать в магазин.
    """
    if shift_date.year == today_date.year and shift_date.month == today_date.month:
        return True

    prev_month, prev_year = previous_month(today_date)
    return (
        shift_date.year == prev_year
        and shift_date.month == prev_month
        and today_date.day <= EDITABLE_PREVIOUS_MONTH_UNTIL_DAY
    )


def editable_period_start(today_date):
    """Первое число самого раннего редактируемого месяца.

    Нужна там, где period фильтруется запросом в БД, а не поштучной проверкой.
    """
    if today_date.day <= EDITABLE_PREVIOUS_MONTH_UNTIL_DAY:
        month, year = previous_month(today_date)
        return date(year, month, 1)
    return date(today_date.year, today_date.month, 1)

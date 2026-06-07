import os
from datetime import datetime, timezone
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

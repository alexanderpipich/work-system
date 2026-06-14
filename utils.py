import re

from passlib.context import CryptContext
from models import Rate
from time_helpers import business_today, now_utc

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def normalize_phone(phone) -> str:
    if phone is None:
        return ""

    if isinstance(phone, float) and phone.is_integer():
        phone = int(phone)

    phone_str = str(phone).strip().replace(" ", "").replace("+", "")

    if phone_str.endswith(".0"):
        phone_str = phone_str[:-2]

    return phone_str


def normalize_text(value) -> str:
    if value is None:
        return ""
    return str(value).strip()


def normalize_format(value) -> str:
    if value is None:
        return ""

    text = str(value).upper().strip()
    compact_text = re.sub(r"\s+", "", text)

    if compact_text in {"ГМ", "СМ"}:
        return compact_text

    return text


def normalize_role(value) -> str:
    role = normalize_text(value).lower()
    allowed = {"admin", "employee", "brigadier", "economist"}

    if role in allowed:
        return role

    return "employee"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(str(plain_password).strip(), hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(str(password).strip())



def load_rates(session):
    return session.query(Rate).all()


def pick_rate(rates, shift):
    candidates = [rate for rate in rates if rate.service == shift.service]
    valid_candidates = []

    for rate in candidates:
        if rate.active_from and shift.shift_date < rate.active_from:
            continue

        if rate.active_to and shift.shift_date > rate.active_to:
            continue

        rate_format = normalize_text(rate.format)
        rate_store = normalize_text(rate.store)
        rate_employee = normalize_text(rate.employee_name)

        if rate_format and rate_format != normalize_text(shift.format):
            continue

        if rate_store and rate_store != normalize_text(shift.store):
            continue

        if rate_employee and rate_employee != normalize_text(shift.employee):
            continue

        valid_candidates.append(rate)

    def priority(rate):
        score = 0

        if normalize_text(rate.employee_name):
            score += 100

        if normalize_text(rate.store):
            score += 10

        if normalize_text(rate.format):
            score += 1

        return score

    if not valid_candidates:
        return None

    valid_candidates.sort(key=priority, reverse=True)
    return valid_candidates[0]


def get_rate_for_shift(session, shift):
    return pick_rate(load_rates(session), shift)

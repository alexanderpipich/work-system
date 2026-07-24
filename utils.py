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


# Хвост ".0" у числа, прочитанного как float (напр. "780000000000.0").
_FLOAT_TAIL_RE = re.compile(r"^(\d+)\.0+$")
# Научная нотация (напр. "4.0820810900009206e+19") — признак утери точности:
# 20-значный номер счёта не влезает во float, младшие цифры уже потеряны.
_SCIENTIFIC_RE = re.compile(r"^\d+(?:\.\d+)?[eE][+-]?\d+$")


def is_scientific_notation(value) -> bool:
    """Похоже ли значение на число в научной нотации (утерянная точность)."""
    if value is None:
        return False
    # NaN не равен сам себе (float/numpy).
    try:
        if value != value:
            return False
    except Exception:
        pass
    return bool(_SCIENTIFIC_RE.match(str(value).strip()))


def normalize_digits(value) -> str:
    """Нормализация числовых идентификаторов (ИНН/счёт/БИК).

    Сохраняет ведущие нули (БИК бывает "04..."), не пытается восстановить
    данные из научной нотации (утеряны — догадки опаснее).
    - None/NaN → "";
    - "780000000000.0" → "780000000000" (отрезать хвост .0);
    - "4.08e+19" (научная нотация) → вернуть как есть (пометить в отчёте выше);
    - иначе — обрезать пробелы, оставить как есть (ведущие нули целы).
    """
    if value is None:
        return ""
    try:
        if value != value:  # NaN
            return ""
    except Exception:
        pass
    text = str(value).strip()
    if not text:
        return ""
    match = _FLOAT_TAIL_RE.match(text)
    if match:
        return match.group(1)
    return text


def normalize_format(value) -> str:
    if value is None:
        return ""

    text = str(value).upper().strip()
    compact_text = re.sub(r"\s+", "", text)

    # РЦ узаконен как формат наравне с ГМ/СМ (в сменах встречается, тарифов нет →
    # услуги РЦ = «нет тарифа», но формат легитимный, не «прочее»).
    if compact_text in {"ГМ", "СМ", "РЦ"}:
        return compact_text

    return text


def normalize_role(value) -> str:
    role = normalize_text(value).lower()
    allowed = {"admin", "superadmin", "hr_lead", "hr_manager", "employee", "brigadier", "economist", "headhunter"}

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
        rate_city = normalize_text(rate.city)
        rate_store = normalize_text(rate.store)
        rate_employee = normalize_text(rate.employee_name)

        # Формат (ГМ/СМ) — жёсткое условие на всех слоях:
        # услуга может стоить по-разному в ГМ и СМ. Пустой формат = "любой".
        if rate_format and rate_format != normalize_text(shift.format):
            continue

        # Город берётся из столбца "Город" отчёта (Shift.city) и тарифов (Rate.city).
        # Совпадение строки в строку; пустой город = "любой".
        if rate_city and rate_city != normalize_text(getattr(shift, "city", None)):
            continue

        if rate_store and rate_store != normalize_text(shift.store):
            continue

        if rate_employee and rate_employee != normalize_text(shift.employee):
            continue

        valid_candidates.append(rate)

    def priority(rate):
        # Три слоя специфичности (формат — обязательный фильтр выше, не очки):
        #   слой 2 — индивидуальная ставка сотрудника  → максимум
        #   слой 1 — индивидуальная ставка по ТК (store)
        #   слой 0 — базовая сетка (город + формат + услуга)
        if normalize_text(rate.employee_name):
            return 1000

        if normalize_text(rate.store):
            return 100

        return 0

    if not valid_candidates:
        return None

    def specificity(rate):
        # Вторичный тай-брейк внутри одного слоя: более узкая ставка побеждает.
        # Ставка с заданным городом/форматом специфичнее, чем "любой".
        return (
            priority(rate),
            1 if normalize_text(rate.city) else 0,
            1 if normalize_text(rate.format) else 0,
        )

    valid_candidates.sort(key=specificity, reverse=True)
    return valid_candidates[0]


def get_rate_for_shift(session, shift):
    return pick_rate(load_rates(session), shift)


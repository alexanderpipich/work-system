import re

from passlib.context import CryptContext
from models import Rate, User
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


_CITY_PREFIX_RE = re.compile(r"^(?:г\.|г\s|город\s)\s*", re.IGNORECASE)


def normalize_city(value) -> str:
    """Город из выгрузки смен (П4.2): «г. Москва», «город  Москва» → «Москва».

    Пустое, NaN из pandas и строка «nan» → "" (в смену пишется NULL). Ставки
    (Rate.city) матчатся с Shift.city строка в строку — поэтому без префиксов.
    """
    if value is None:
        return ""
    try:
        if value != value:  # NaN
            return ""
    except Exception:
        pass
    text = " ".join(str(value).split())
    if text.lower() in {"", "nan", "none", "null"}:
        return ""
    return _CITY_PREFIX_RE.sub("", text).strip()


def normalize_person_name(value) -> str:
    """Ключ сравнения ФИО: пробелы схлопнуты, регистр и ё/е не различаются.

    «Иванов  Пётр» и «иванов петр» — один человек. Это ключ User.employee_name_norm;
    само ФИО хранится как ввели (normalize_text).
    """
    return " ".join(normalize_text(value).split()).casefold().replace("ё", "е")


def find_user_by_name(session, name):
    """User с тем же нормализованным ФИО или None (ФИО уникально по этому ключу)."""
    key = normalize_person_name(name)
    if not key:
        return None
    return session.query(User).filter(User.employee_name_norm == key).first()


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


# Длины числовых идентификаторов. ИНН физлица — 12 цифр, юрлица — 10.
INN_LENGTHS = (10, 12)
ACCOUNT_LENGTH = (20,)
BIK_LENGTH = (9,)


def _identifier_issue(label, value, lengths):
    """Что не так с одним идентификатором. None — годен."""
    text = normalize_digits(value)
    if not text:
        return "%s не заполнен" % label
    if is_scientific_notation(text):
        # Цифры уже схлопнулись во float — восстановить нечего, только вводить заново.
        return "%s в научной нотации, цифры утеряны: %s" % (label, text)
    if not text.isdigit():
        return "%s должен быть только из цифр: %s" % (label, text)
    if len(text) not in lengths:
        return "%s: %d цифр, ожидалось %s" % (
            label, len(text), " или ".join(str(n) for n in lengths))
    return None


def requisite_issues(inn, account_number, bik) -> list:
    """Что мешает выплате по этим реквизитам. Пустой список — годны.

    Единый критерий для генератора реестра, экрана невалидных реквизитов и
    диагностики базы: чтобы «невалидный» везде означало одно и то же.
    """
    checks = (
        ("ИНН", inn, INN_LENGTHS),
        ("Номер счёта", account_number, ACCOUNT_LENGTH),
        ("БИК", bik, BIK_LENGTH),
    )
    return [issue for issue in
            (_identifier_issue(label, value, lengths) for label, value, lengths in checks)
            if issue]


# --- Выплата на карту (П1-Г) -------------------------------------------------

PAYOUT_CARD = "card"
PAYOUT_CARD_PHONE = "card_phone"
PAYOUT_CASH = "cash"
PAYOUT_METHODS = {
    PAYOUT_CARD: "Карта",
    PAYOUT_CARD_PHONE: "Карта / номер телефона",
    PAYOUT_CASH: "Наличные",
}
CARD_MIN_DIGITS = 16  # в РФ бывают 18–19
CARD_MAX_DIGITS = 19


def normalize_card_number(value) -> str:
    """Номер карты сплошными цифрами: пробелы и дефисы ввода убираются.

    Число из Excel (float) переводится без хвоста «.0»; прочие символы
    оставляются, чтобы проверка показала мусор, а не съела его молча.
    """
    if value is None:
        return ""
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    return re.sub(r"[\s-]+", "", str(value))


def luhn_valid(card_number) -> bool:
    digits = normalize_card_number(card_number)
    if not digits.isdigit():
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = int(char)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def card_number_issues(card_number) -> list:
    """Что мешает выплате на эту карту. Luhn сюда не входит — это предупреждение."""
    card = normalize_card_number(card_number)
    if not card:
        return ["Номер карты не заполнен"]
    if not card.isdigit():
        return ["Номер карты: только цифры"]
    if not CARD_MIN_DIGITS <= len(card) <= CARD_MAX_DIGITS:
        return ["Номер карты: %d цифр, нужно %d–%d" % (len(card), CARD_MIN_DIGITS, CARD_MAX_DIGITS)]
    return []


def format_card_number(value) -> str:
    """«0000 0000 0000 0000» для показа; хвост длинной карты — последней группой."""
    card = normalize_card_number(value)
    if not card.isdigit():
        return card
    return " ".join(card[i:i + 4] for i in range(0, len(card), 4))


def normalize_card_phone(value) -> str:
    """Телефон для перевода по номеру: 11 цифр с ведущей 7.

    normalize_phone (логин) не трогает скобки и дефисы, а здесь номер идёт в банк:
    оставляем только цифры, 8XXXXXXXXXX и 10 цифр с 9 приводим к 7XXXXXXXXXX.
    """
    digits = re.sub(r"\D", "", normalize_phone(value))
    if len(digits) == 11 and digits.startswith("8"):
        digits = "7" + digits[1:]
    elif len(digits) == 10 and digits.startswith("9"):
        digits = "7" + digits
    return digits


def card_phone_issues(card_phone) -> list:
    phone = normalize_card_phone(card_phone)
    if not phone:
        return ["Телефон для выплаты не заполнен"]
    if len(phone) != 11 or not phone.startswith("7"):
        return ["Телефон для выплаты: нужно 11 цифр, начиная с 7"]
    return []


def normalize_card_expiry(month, year=None) -> str:
    """Срок карты MM/YY из «MM/YY» или пары месяц + год (числа из Excel). Иначе ""."""
    if year is None:
        match = re.fullmatch(r"\s*(\d{1,2})\s*/\s*(\d{2}|\d{4})\s*", str(month or ""))
        if not match:
            return ""
        month, year = match.groups()
    try:
        month_num = int(float(month))
        year_num = int(float(year))
    except (TypeError, ValueError):
        return ""
    if not 1 <= month_num <= 12 or year_num < 0:
        return ""
    return "%02d/%02d" % (month_num, year_num % 100)


def payout_method_issues(payout_method, card_number, card_phone, bank_name) -> list:
    """Что мешает выплате выбранным способом. Пустой список — способ годен."""
    if payout_method == PAYOUT_CASH:
        return []
    if payout_method == PAYOUT_CARD:
        return card_number_issues(card_number)
    if payout_method == PAYOUT_CARD_PHONE:
        issues = card_phone_issues(card_phone)
        if not normalize_text(bank_name):
            issues.append("Банк не указан")
        return issues
    return ["Способ выплаты не выбран"]


def is_valid_requisite(inn, account_number, bik) -> bool:
    """Годны ли реквизиты для выплаты."""
    return not requisite_issues(inn, account_number, bik)


def repair_digits(value, lengths, pad_leading_zeros=True):
    """Починить идентификатор, испорченный проходом через float. None — не чинится.

    Float портит цифровые идентификаторы двумя способами, и только один обратим:
    - «471605460681.0» — приписан хвост, цифры целы → отрезать;
    - «044030653» → «44030653.0» — съеден ведущий ноль, но длина известна заранее
      (БИК 9, ИНН 10/12), поэтому ноль восстанавливается однозначно → дописать;
    - «4.08e+19» — во float поместилось 17 значащих цифр из 20, младшие УТЕРЯНЫ.
      Восстановить нечем, догадки в платёжке недопустимы → None.

    pad_leading_zeros=False для номера счёта: счёт начинается с номера балансового
    счёта (40817 у физлиц), ведущего нуля там не бывает. Дописать ноль значит
    выдумать номер, который пройдёт проверку длины и уйдёт в банк неверным.
    """
    text = normalize_digits(value)
    if not text or is_scientific_notation(text) or not text.isdigit():
        return None
    if len(text) in lengths:
        return text
    if not pad_leading_zeros:
        return None
    # Дописываем ведущие нули до ближайшей допустимой длины. Длиннее максимума —
    # это уже не потеря нуля, а что-то другое: не трогаем.
    longer = sorted(n for n in lengths if n > len(text))
    if not longer:
        return None
    return text.zfill(longer[0])


def repair_requisite(inn, account_number, bik):
    """Починенные (инн, счёт, бик); None вместо значения — восстановлению не подлежит."""
    return (
        repair_digits(inn, INN_LENGTHS),
        repair_digits(account_number, ACCOUNT_LENGTH, pad_leading_zeros=False),
        repair_digits(bik, BIK_LENGTH),
    )


# П4.5: форматы, которые в выгрузке приходят своим кодом, а ставку берут по ГМ/СМ
# (как в ведомости коллег): Табакошоп, Зоомаркет — по МФ (СМ), Централизованное
# производство — по ГМ. Только для подбора ставки (pick_rate): Shift.format и формат
# ТК не меняются; ставка с точным форматом (если заведут) приоритетнее.
RATE_FORMAT_ALIASES = {"ТШ": "СМ", "ЗМ": "СМ", "ЦП": "ГМ"}


def normalize_format(value) -> str:
    if value is None:
        return ""

    text = str(value).upper().strip()
    compact_text = re.sub(r"\s+", "", text)

    # РЦ узаконен как формат наравне с ГМ/СМ (в сменах встречается, тарифов нет →
    # услуги РЦ = «нет тарифа», но формат легитимный, не «прочее»).
    if compact_text in {"ГМ", "СМ", "РЦ"}:
        return compact_text
    # «МФ» в таблице магазинов Ленты — тот же формат, что «СМ» в выгрузке смен (П4.3).
    if compact_text == "МФ":
        return "СМ"

    return text


def normalize_role(value) -> str:
    role = normalize_text(value).lower()
    allowed = {"admin", "superadmin", "hr_lead", "tm", "hr_clerk", "employee", "brigadier", "economist", "headhunter"}
    if role == "hr_manager":  # старое имя роли ТМ (П1)
        return "tm"

    if role in allowed:
        return role

    return "employee"


def safe_return_to(value, default: str) -> str:
    """Куда вернуть пользователя после сохранения формы.

    `return_to` приходит из скрытого поля модалки (создание ЧТС/реквизитов из
    кликабельной диагностики табеля) — принимаем ТОЛЬКО локальный путь, чтобы
    не получить open-redirect. Всё подозрительное → `default` (прежнее поведение).
    """
    target = str(value or "").strip()

    if not target:
        return default

    # Только относительный путь с одним ведущим "/". "//host" и "/\host" браузер
    # трактует как внешний адрес (protocol-relative) — отбрасываем.
    if not target.startswith("/"):
        return default

    if target.startswith("//") or target.startswith("/\\"):
        return default

    # Перевод строки в Location — заголовочная инъекция.
    if any(ch in target for ch in ("\r", "\n")):
        return default

    return target


def verify_password(plain_password: str, hashed_password: str) -> bool:
    # Сотрудник без кабинета (password_hash NULL) не проходит никакой пароль.
    if not hashed_password:
        return False
    return pwd_context.verify(str(plain_password).strip(), hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(str(password).strip())



def load_rates(session):
    return session.query(Rate).all()


def pick_rate(rates, shift, resolve=None):
    # Этап 2 переделки услуг: матчинг услуги по service_id + level (а не по тексту).
    # `resolve(shift) -> (service_id, level)` строится из справочника Service
    # (см. service_catalog.build_service_resolver). Фильтры формат/город/store/
    # employee и три слоя приоритета ниже — НЕ меняются.
    #
    # Совместимость/страховка сумм: если резолвер не передан, ИЛИ у Rate не
    # проставлен service_id (старые/ручные записи), ИЛИ услуга смены без Service
    # (target_service_id=None) — падаем на прежнее сравнение по тексту. Для
    # мигрированных данных id+level и текст дают ОДИН И ТОТ ЖЕ Rate → суммы не меняются.
    target_service_id = target_level = None
    if resolve is not None:
        target_service_id, target_level = resolve(shift)

    def _service_matches(rate):
        if resolve is not None and rate.service_id is not None and target_service_id is not None:
            return rate.service_id == target_service_id and rate.level == target_level
        return rate.service == shift.service

    candidates = [rate for rate in rates if _service_matches(rate)]
    valid_candidates = []
    region_of = getattr(resolve, "rate_region", None)
    shift_region = normalize_text(region_of(shift) if region_of else getattr(shift, "city", None))
    shift_format = normalize_text(shift.format)
    alias_format = RATE_FORMAT_ALIASES.get(normalize_format(shift_format))

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
        if rate_format and rate_format != shift_format and rate_format != alias_format:
            continue

        # Rate.city — тарифный регион. Регион смены — Store.rate_region её магазина
        # (П4.4, через резолвер), иначе столбец "Город" отчёта (Shift.city).
        # Совпадение строки в строку; пустой регион ставки = "любой".
        if rate_city and rate_city != shift_region:
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
            1 if normalize_text(rate.format) == shift_format else 0,  # точный формат лучше алиаса
        )

    valid_candidates.sort(key=specificity, reverse=True)
    return valid_candidates[0]


def get_rate_for_shift(session, shift):
    # Локальный импорт — service_catalog зависит от utils (кольцо на уровне модуля).
    from service_catalog import build_service_resolver
    return pick_rate(load_rates(session), shift, resolve=build_service_resolver(session))


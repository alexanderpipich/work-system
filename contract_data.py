"""Данные для договора и ходатайства (П4): откуда берётся каждое поле.

Источники: сотрудник (User), его документы (Паспорт, СНИЛС, ПАТЕНТ), юрлицо
(LegalEntity), регион (Region), ввод в форме. Проверка полноты показывает поле,
значение и источник; недостающее можно ввести на месте — оно сохраняется в
источник (save_fixes), а не только в документ.
"""

from datetime import date, timedelta

from audit_helpers import create_audit_log
from contract_generator import NO_DATA, fmt_day, fmt_long, fmt_quoted, fmt_short, rubles_phrase
from employee_profile import (DOC_PASSPORT, DOC_PATENT, DOC_SNILS, format_patent_number, latest_document,
                              parse_patent_number)
from models import DocumentType, EmployeeDocument, LegalEntity, Region, RegimeDocumentRule, Shift, Store
from time_helpers import now_utc
from utils import normalize_text

SOURCE_USER = "сотрудник"
SOURCE_DOC = "документ"
SOURCE_LE = "юрлицо"
SOURCE_REGION = "регион"
SOURCE_FORM = "ввод"
SOURCE_STORE = "магазин"
SOURCE_SHIFTS = "смены за 14 дней"
RECENT_DAYS = 14

LE_FIELDS = [
    ("le_full_name", "full_name", "Полное наименование юрлица"),
    ("le_short_name", "short_name", "Краткое наименование (ООО «…»)"),
    ("le_director_title", "director_title", "Должность руководителя (род. падеж)"),
    ("le_director_genitive", "director_name_genitive", "Руководитель (род. падеж)"),
    ("le_director_name", "director_name", "Руководитель (им. падеж)"),
    ("le_director_short", "director_short", "Подпись руководителя"),
    ("le_legal_address", "legal_address", "Юридический адрес"),
    ("le_actual_address", "actual_address", "Фактический адрес"),
    ("work_address", "work_address", "Адрес места работы (п. 1.3)"),
    ("le_inn", "inn", "ИНН юрлица"),
    ("le_kpp", "kpp", "КПП"),
    ("le_ogrn", "ogrn", "ОГРН"),
    ("le_bank_account", "bank_account", "Расчётный счёт"),
    ("le_bank_name", "bank_name", "Банк"),
    ("le_bik", "bik", "БИК"),
    ("le_corr_account", "corr_account", "Корр. счёт"),
]
CONTRACT_LE_KEYS = {"le_full_name", "le_short_name", "le_director_title", "le_director_genitive",
                    "le_director_short", "le_legal_address", "work_address", "le_inn", "le_kpp", "le_ogrn",
                    "le_bank_account", "le_bank_name", "le_bik", "le_corr_account"}
PETITION_LE_KEYS = {"le_full_name", "le_ogrn", "le_kpp", "le_inn", "le_legal_address", "le_actual_address",
                    "le_director_name"}
RECOMMENDATION_LE_KEYS = {"le_full_name", "le_short_name", "le_ogrn", "le_kpp", "le_inn", "le_actual_address",
                          "le_director_title", "le_director_name"}
# Должность руководителя хранится в род. падеже («генерального директора», для договора);
# в подписи письма нужен именительный — по словарю частых слов, без склонений.
_TITLE_NOMINATIVE = {"генерального": "генеральный", "исполнительного": "исполнительный",
                     "управляющего": "управляющий", "директора": "директор"}


def needs_patent(session, profile):
    """Нужен ли патент: по правилам режима гражданства (ЕАЭС и РФ — нет)."""
    country = profile["country"]
    patent_type = profile["patent_type"]
    if not country or not patent_type or profile["is_russian"]:
        return False
    return session.query(RegimeDocumentRule.id).filter(
        RegimeDocumentRule.regime_id == country.regime_id,
        RegimeDocumentRule.document_type_id == patent_type.id,
        RegimeDocumentRule.is_required == True,  # noqa: E712
    ).first() is not None


def patent_is_valid(profile, on_date):
    expiry = profile["patent_expiry"]
    return bool(profile["patent_doc"] and expiry and expiry >= on_date)


def default_legal_entity(session, profile):
    """Юрлицо бланка: из профиля сотрудника → отмеченное «по умолчанию» (активное) →
    единственное активное → None (выбрать в форме)."""
    if profile["legal_entity"]:
        return profile["legal_entity"]
    active = document_legal_entities(session)
    if active and active[0].is_default:
        return active[0]
    return active[0] if len(active) == 1 else None


def document_legal_entities(session):
    """Активные юрлица для выпадающего списка бланков: юрлицо по умолчанию — первым."""
    return session.query(LegalEntity).filter(LegalEntity.is_active == True).order_by(  # noqa: E712
        LegalEntity.is_default.desc(), LegalEntity.name).all()


def _shifts_word(n):
    if n % 10 == 1 and n % 100 != 11:
        return "смена"
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return "смены"
    return "смен"


def _of_shifts_word(n):
    """После «из N»: «из 1 смены», «из 2 смен», «из 21 смены»."""
    return "смены" if n % 10 == 1 and n % 100 != 11 else "смен"


def format_rate(value):
    """ЧТС для договора: 333 → «333,00»."""
    return f"{value:.2f}".replace(".", ",")


def _rate_short(value):
    return f"{value:g}".replace(".", ",")


def recent_work(session, user, today, days=RECENT_DAYS):
    """Где и по какой ЧТС сотрудник работал последние `days` дней (по сменам timebook).

    Основной магазин — больше смен; при равенстве — больше часов, затем самая поздняя смена.
    Ставка — ЧТС через price_shift, как в выплатах (индивидуальные ставки, регион ТК), без «Акции»:
    наиболее частая по числу смен, при равенстве — по часам; смены без ЧТС не считаются.
    Смены без плана и услуги «не из timebook» не учитываются. Смен нет — None."""
    from payroll_run_helpers import payable_shifts, price_shift
    from service_catalog import build_service_resolver
    from shift_helpers import is_no_plan_shift
    from store_helpers import extract_tk_number
    from utils import load_rates

    shifts = session.query(Shift).filter(
        Shift.employee == normalize_text(user.employee_name),
        Shift.shift_date >= today - timedelta(days=days - 1),
        Shift.shift_date <= today,
    ).all()
    resolve = build_service_resolver(session)
    shifts = [s for s in payable_shifts(shifts, resolve) if not is_no_plan_shift(s) and (s.hours or 0) > 0]
    if not shifts:
        return None

    stores = {}
    for shift in shifts:
        row = stores.setdefault(normalize_text(shift.store), {"store": shift.store, "count": 0, "hours": 0, "last": None})
        row["count"] += 1
        row["hours"] += shift.hours or 0
        row["last"] = max(filter(None, [row["last"], shift.shift_date]))
    ranked = sorted(stores.values(), key=lambda r: (r["count"], r["hours"], r["last"]), reverse=True)

    def label(row):
        tk = extract_tk_number(row["store"])
        return f"ТК {tk}" if tk is not None else row["store"]

    main = ranked[0]
    tk = extract_tk_number(main["store"])
    store = session.query(Store).filter(Store.tk_number == tk).first() if tk is not None else None
    total = len(shifts)
    address_hint = f"{label(main)}, {main['count']} из {total} {_of_shifts_word(total)}"
    if len(ranked) > 1:
        address_hint += "; также " + ", ".join(
            f"{label(r)}, {r['count']} {_shifts_word(r['count'])}" for r in ranked[1:])

    rates_by_value = {}
    rates = load_rates(session)
    for shift in shifts:
        _, rate_value, _, _ = price_shift(shift, rates, resolve, None)  # без надбавок: «Акция» временная
        if not rate_value:
            continue
        row = rates_by_value.setdefault(round(rate_value, 2), {"count": 0, "hours": 0})
        row["count"] += 1
        row["hours"] += shift.hours or 0
    rate = rate_hint = None
    if rates_by_value:
        ranked_rates = sorted(rates_by_value.items(), key=lambda item: (item[1]["count"], item[1]["hours"]),
                              reverse=True)
        rate, top = ranked_rates[0]
        counted = sum(r["count"] for r in rates_by_value.values())
        rate_hint = f"ЧТС по {top['count']} из {counted} {_of_shifts_word(counted)}"
        if len(ranked_rates) > 1:
            rate_hint += "; также " + ", ".join(
                f"{_rate_short(value)} — {r['count']} {_shifts_word(r['count'])}" for value, r in ranked_rates[1:])
    return {"store": store, "store_label": label(main), "address": normalize_text(store.object_address) if store else "",
            "address_hint": address_hint, "rate": rate, "rate_hint": rate_hint}


def contract_position(profile, with_patent, form):
    """Должность договора: введённая → профессия по патенту (при патенте) → расшифровка кода должности
    из карточки (`JOB_TITLE_NAMES`, им. падеж). Нет должности или расшифровки — пусто, поле в недостающих.
    Возвращает (должность, источник, подсказка)."""
    from models import job_title_name

    if form.get("position"):
        return form["position"], SOURCE_FORM, ""
    if with_patent:
        return profile["patent_profession"], SOURCE_DOC, "профессия по патенту"
    code = profile["job_title"]
    if not code:
        return "", SOURCE_USER, "в карточке сотрудника должности нет — введите"
    name = job_title_name(code)
    if not name:
        return "", SOURCE_USER, f"у должности «{code}» из карточки нет расшифровки — введите"
    return name, SOURCE_USER, f"из карточки сотрудника: {code}"


def citizen_word(gender):
    return {"m": "гражданин", "f": "гражданка"}.get(gender, "гражданин(ка)")


def _field(key, label, value, source, target=None, required=True):
    """Строка проверки полноты. target — куда сохранить ввод: ("user", поле),
    ("doc", тип, поле), ("le", поле), ("region", поле), ("form", поле)."""
    text = value if isinstance(value, str) else (fmt_short(value) if isinstance(value, date) else str(value or ""))
    return {"key": key, "label": label, "value": text.strip(), "source": source, "target": target,
            "missing": required and not text.strip()}


def _le_fields(entity, keys):
    rows = []
    for key, attr, label in LE_FIELDS:
        if key not in keys:
            continue
        value = getattr(entity, attr, None) if entity else None
        if key == "le_short_name" and entity and not value:
            value = entity.name
        if key == "le_director_title" and entity and not value:
            value = "генерального директора"
        rows.append(_field(key, label, value or "", SOURCE_LE, ("le", attr)))
    return rows


def _patent_line(profile):
    def part(value):
        return value if (value or "").strip() else NO_DATA
    return (f"Патент серия {part(profile['patent_series'])} №{part(profile['patent_number'])} "
            f"выдан {part(fmt_short(profile['patent_issue_date']))} {part(profile['patent_authority'])}, "
            f"серия и номер бланка {part(profile['patent_blank_series'])} {part(profile['patent_blank_number'])} "
            f"срок действия патента {part(fmt_short(profile['patent_issue_date']))}- "
            f"{part(fmt_short(profile['patent_expiry']))}")


def _patent_fields(profile, region):
    authority = profile["patent_authority"] or (region.patent_authority if region else "")
    return [
        _field("patent_series", "Серия патента", profile["patent_series"], SOURCE_DOC, ("patent", "series")),
        _field("patent_number", "Номер патента", profile["patent_number"], SOURCE_DOC, ("patent", "number")),
        _field("patent_blank_series", "Серия бланка", profile["patent_blank_series"], SOURCE_DOC, ("patent", "blank_series")),
        _field("patent_blank_number", "Номер бланка", profile["patent_blank_number"], SOURCE_DOC, ("patent", "blank_number")),
        _field("patent_issue_date", "Дата выдачи патента", profile["patent_issue_date"], SOURCE_DOC, ("doc", DOC_PATENT, "issue_date")),
        _field("patent_expiry", "Срок патента до" + (" (вычислено: год от выдачи)" if profile["patent_expiry_computed"] else ""),
               profile["patent_expiry"], SOURCE_DOC, ("doc", DOC_PATENT, "expiry_date")),
        _field("patent_authority", "Кем выдан патент", authority,
               SOURCE_DOC if profile["patent_authority"] else SOURCE_REGION, ("doc", DOC_PATENT, "extra_field_1_value")),
        _field("patent_profession", "Профессия по патенту", profile["patent_profession"], SOURCE_DOC,
               ("doc", DOC_PATENT, "extra_field_2_value")),
    ]


def contract_fields(session, profile, entity, region, form, work=None):
    """(поля проверки полноты, значения для генератора, ошибки формы). work — recent_work():
    адрес места работы из магазина, где сотрудник чаще выходил за 14 дней (иначе — из юрлица)."""
    contract_date = form.get("contract_date") or date.today()
    with_patent = needs_patent(session, profile)
    errors = []
    fields = [
        _field("fio", "ФИО", profile["fio"], SOURCE_USER),
        _field("gender", "Пол (гражданин/гражданка)" + (" — угадан по отчеству" if profile["gender_guessed"] else ""),
               {"m": "мужской", "f": "женский"}.get(profile["gender"], ""), SOURCE_USER, ("user", "gender")),
        _field("citizenship", "Гражданство (род. падеж)", profile["citizenship_genitive"], SOURCE_USER),
        _field("birth_date", "Дата рождения", profile["birth_date"], SOURCE_USER, ("user", "birth_date")),
        _field("inn", "ИНН", profile["inn"], SOURCE_USER, ("user", "inn")),
        _field("snils", "СНИЛС", profile["snils"], SOURCE_DOC, ("doc", DOC_SNILS, "document_number")),
        _field("passport_number", "Номер паспорта", profile["passport_number"], SOURCE_DOC, ("doc", DOC_PASSPORT, "document_number")),
        _field("passport_issue_date", "Дата выдачи паспорта", profile["passport_issue_date"], SOURCE_DOC, ("doc", DOC_PASSPORT, "issue_date")),
        _field("passport_issuer", "Кем выдан паспорт", profile["passport_issuer"], SOURCE_DOC,
               ("doc", DOC_PASSPORT, "extra_field_1_value"), required=False),
    ]
    if with_patent:
        fields += _patent_fields(profile, region)
    store = work["store"] if work else None
    fields += _le_fields(entity, CONTRACT_LE_KEYS - {"work_address"} if store else CONTRACT_LE_KEYS)
    if store:
        # Адрес — магазина, где сотрудник чаще выходил; «заполнить на месте» — в карточку магазина.
        address = _field("work_address", "Адрес места работы (п. 1.3)", work["address"], SOURCE_STORE,
                         ("store", store.id, "object_address"))
        address["hint"] = work["address_hint"]
        fields.append(address)

    position, position_source, position_hint = contract_position(profile, with_patent, form)
    rate_field = _field("rate", "Ставка за час, ₽", form.get("rate") or "", SOURCE_FORM, ("form", "rate"))
    if work and work["rate_hint"] and form.get("rate") == format_rate(work["rate"]):
        rate_field.update(source=SOURCE_SHIFTS, hint=work["rate_hint"])
    fields += [
        _field("contract_number", "Номер договора", form.get("contract_number"), SOURCE_FORM, ("form", "contract_number")),
        dict(_field("position", "Должность", position, position_source, ("form", "position")), hint=position_hint),
        rate_field,
        _field("city", "Город договора", form.get("city") or "", SOURCE_FORM, ("form", "city")),
    ]

    # Срок: бессрочный или до даты; с патентом — только срочный и не позже окончания патента.
    term_until = form.get("term_until")
    patent_expiry = profile["patent_expiry"] if with_patent else None
    if with_patent and form.get("term_indefinite"):
        errors.append("При патенте договор срочный — бессрочный не заключается")
    elif with_patent and not term_until:
        errors.append("При патенте договор срочный — укажите дату окончания")
    if with_patent and patent_expiry and term_until and term_until > patent_expiry:
        errors.append(f"Срок договора не может быть позже окончания патента {fmt_short(patent_expiry)}")
    if (form.get("term_indefinite") and not with_patent) or not term_until:
        term = "на неопределенный срок."
    else:
        term = f"на срок до {fmt_day(term_until)}."

    rate_value = form.get("rate")
    try:
        rate_text = rubles_phrase(float(str(rate_value).replace(",", "."))) if rate_value not in (None, "") else ""
    except ValueError:
        errors.append("Ставка — число, например 232,18")
        rate_text = ""

    values = {f["key"]: f["value"] for f in fields}
    effective = form.get("effective_date") or contract_date
    start = form.get("start_date") or contract_date
    passport = ""
    if profile["passport_number"] or profile["passport_issue_date"]:
        passport = " ".join(filter(None, [
            f"№{profile['passport_number'] or NO_DATA}",
            f"выдан {fmt_short(profile['passport_issue_date']) or NO_DATA}",
            profile["passport_issuer"],
        ]))
    values.update({
        "city": form.get("city") or "",
        "contract_date_head": fmt_day(contract_date, "г"),
        "employee_party": " ".join(filter(None, [citizen_word(profile["gender"]), profile["citizenship_genitive"],
                                                 profile["fio"]])) if profile["citizenship_genitive"] else "",
        "position": position,
        "effective_date": fmt_day(effective),
        "start_date": fmt_day(start),
        "term": term,
        "rate_phrase": rate_text,
        "birth_date": fmt_short(profile["birth_date"]),
        "passport": passport,
        "patent_line": _patent_line(profile) if with_patent else "",
        "initials": profile["initials"],
        "receipt_date": fmt_long(contract_date, "года"),
    })
    return fields, values, errors, with_patent


def petition_fields(session, profile, entity, region, form):
    petition_date = form.get("petition_date") or date.today()
    fields = [_field("fio", "ФИО", profile["fio"], SOURCE_USER)]
    fields += _patent_fields(profile, region)
    fields += _le_fields(entity, PETITION_LE_KEYS)
    fields += [
        _field("uvm_addressee", "Адресат в УВМ (дат. падеж)", region.uvm_addressee if region else "", SOURCE_REGION, ("region", "uvm_addressee")),
        _field("uvm_rank", "Звание начальника (дат. падеж)", region.uvm_rank if region else "", SOURCE_REGION, ("region", "uvm_rank")),
        _field("uvm_person", "ФИО начальника (дат. падеж)", region.uvm_person if region else "", SOURCE_REGION, ("region", "uvm_person")),
        _field("patent_territory", "Территория действия патента", region.patent_territory if region else "", SOURCE_REGION,
               ("region", "patent_territory")),
    ]
    values = {f["key"]: f["value"] for f in fields}
    addressee = values.get("uvm_addressee", "")
    head, sep, tail = addressee.partition(" по ")
    values.update({
        "empty": "",
        "uvm_addressee_1": head if sep else addressee,
        "uvm_addressee_2": f"по {tail}" if sep else "",
        "patent_series_number": f"{profile['patent_series'] or NO_DATA}    №  {profile['patent_number'] or NO_DATA}",
        "patent_blank": f"{profile['patent_blank_series'] or NO_DATA}     №   {profile['patent_blank_number'] or NO_DATA}",
        "patent_period": f"с {fmt_short(profile['patent_issue_date']) or NO_DATA} по {fmt_short(profile['patent_expiry']) or NO_DATA}",
        "patent_issue_date": fmt_short(profile["patent_issue_date"]),
        "petition_date": fmt_quoted(petition_date),
    })
    return fields, values


def signer_title(director_title):
    """«генерального директора» → «Генеральный директор» (подпись рекомендательного письма)."""
    words = [_TITLE_NOMINATIVE.get(w, w) for w in normalize_text(director_title).lower().split()] or ["директор"]
    return " ".join(words).capitalize()


def recommendation_position(session, profile, form):
    """Должность в письме: введённая, иначе из патента, иначе расшифровка кода из карточки (им. падеж)."""
    from models import job_title_name

    patent = profile["patent_profession"] if needs_patent(session, profile) else ""
    return form.get("position") or patent or job_title_name(profile["job_title"])


def recommendation_fields(session, profile, entity, form):
    """Рекомендательное письмо (П4.11): юрлицо, ФИО, город и должность; тело безличное."""
    issue_date = form.get("recommendation_date") or date.today()
    position = recommendation_position(session, profile, form)
    fields = [_field("fio", "ФИО", profile["fio"], SOURCE_USER)]
    fields += _le_fields(entity, RECOMMENDATION_LE_KEYS)
    fields += [
        _field("city", "Город работы", form.get("city") or "", SOURCE_FORM, ("form", "city")),
        _field("position", "Должность", position, SOURCE_FORM if form.get("position") else SOURCE_DOC, ("form", "position")),
    ]
    values = {f["key"]: f["value"] for f in fields}
    short_name = values.get("le_short_name", "")
    values.update({
        "signer": f"{signer_title(values.get('le_director_title'))} {short_name}" if short_name else "",
        "recommendation_date": fmt_quoted(issue_date),
    })
    return fields, values


# ── Ввод недостающего на месте ───────────────────────────────────────────────

def _parse_date(value):
    try:
        return date.fromisoformat(normalize_text(value)) if normalize_text(value) else None
    except ValueError:
        return None


def _document(session, user, type_name):
    doc_type, document = latest_document(session, user, type_name)
    if document is None and doc_type is not None:
        document = EmployeeDocument(user_id=user.id, employee_name=user.employee_name, document_type_id=doc_type.id,
                                    status="uploaded", uploaded_at=now_utc(), comment="введено при создании договора")
        session.add(document)
    return document


def save_fixes(session, request, actor, user, entity, region, fixes):
    """Сохранить введённое на месте в источник. fixes: {"user:birth_date": "...", ...}.
    Возвращает число сохранённых полей."""
    from inn_sync import set_employee_inn

    saved = 0
    patent_parts = {}
    for key, raw in fixes.items():
        value = normalize_text(raw)
        if not value:
            continue
        kind, _, rest = key.partition(":")
        if kind == "user":
            if rest == "inn":
                set_employee_inn(session, user, value, source="profile", actor=actor, request=request)
            elif rest == "birth_date":
                user.birth_date = _parse_date(value) or user.birth_date
            elif rest == "gender" and value in {"m", "f"}:
                user.gender = value
            saved += 1
        elif kind == "doc":
            type_name, _, attr = rest.partition(":")
            document = _document(session, user, type_name)
            if document is None:
                continue
            setattr(document, attr, _parse_date(value) if attr.endswith("_date") else value)
            document.updated_at = now_utc()
            saved += 1
        elif kind == "patent":
            patent_parts[rest] = value
        elif kind == "le" and entity is not None:
            setattr(entity, rest, value)
            saved += 1
        elif kind == "region" and region is not None:
            setattr(region, rest, value)
            saved += 1
        elif kind == "store":
            # Адрес места работы — в карточку магазина (Store.object_address), не в юрлицо.
            store_id, _, attr = rest.partition(":")
            store = session.get(Store, int(store_id)) if store_id.isdigit() else None
            if store is not None and attr == "object_address":
                store.object_address = value
                store.updated_at = now_utc()
                saved += 1
    if patent_parts:
        document = _document(session, user, DOC_PATENT)
        if document is not None:
            current = parse_patent_number(document.document_number)
            current.update(patent_parts)
            document.document_number = format_patent_number(current["series"], current["number"],
                                                            current["blank_series"], current["blank_number"])
            saved += len(patent_parts)
    if saved:
        create_audit_log(session, request, actor, "contract.data_filled", "user", user.id, user.employee_name,
                         new_value={k: v for k, v in fixes.items() if normalize_text(v)})
    session.flush()
    return saved


def contract_document_type(session, name):
    return session.query(DocumentType).filter(DocumentType.name == name).order_by(DocumentType.id).first()


def suggest_contract_number(session, contract_date):
    """Следующий номер договора года: «26-0001»."""
    doc_type = contract_document_type(session, "ТРУДОВОЙ ДОГОВОР")
    prefix = f"{contract_date:%y}-"
    count = 0
    if doc_type:
        count = session.query(EmployeeDocument).filter(
            EmployeeDocument.document_type_id == doc_type.id,
            EmployeeDocument.document_number.like(prefix + "%"),
        ).count()
    return f"{prefix}{count + 1:04d}"


def regions(session):
    return session.query(Region).filter(Region.is_active == True).order_by(Region.name).all()  # noqa: E712

"""Генератор трудового договора и ходатайства (П4) — порт utka/generator.py.

Подход тот же, что в УТКЕ: точечная замена текста внутри абзаца, даже если он
разбит на несколько runs; форматирование соседних runs не трогается. Отличия:
- подстановка ищется не по индексу run, а по ОБРАЗЦУ текста из шаблона внутри
  абзаца, найденного по «якорю» (кусок постоянного текста абзаца) — шаблон можно
  править, пока образцы и якоря на месте (docs/contracts.md);
- подставленное подсвечивается жёлтым (WD_COLOR_INDEX.YELLOW), прочая
  подсветка шаблона снимается;
- нет данных → «НЕТ ДАННЫХ» жёлтым (если разрешено), иначе — ошибка;
- образец, не найденный в шаблоне, — ошибка (шаблон разошёлся с картой).

Модуль чистый: на входе значения (dict), на выходе bytes .docx. Откуда берётся
каждое значение — contract_data.py.
"""

import copy
from dataclasses import dataclass
from datetime import date
from io import BytesIO
from pathlib import Path

from docx import Document
from docx.enum.text import WD_COLOR_INDEX
from docx.oxml.ns import qn
from docx.text.run import Run

TEMPLATES_DIR = Path(__file__).resolve().parent / "data" / "templates"
CONTRACT_TEMPLATE = TEMPLATES_DIR / "contract_template.docx"
PETITION_TEMPLATE = TEMPLATES_DIR / "petition_template.docx"

HIGHLIGHT = WD_COLOR_INDEX.YELLOW
NO_DATA = "НЕТ ДАННЫХ"

MONTHS_RU = {1: "января", 2: "февраля", 3: "марта", 4: "апреля", 5: "мая", 6: "июня",
             7: "июля", 8: "августа", 9: "сентября", 10: "октября", 11: "ноября", 12: "декабря"}


class TemplateMismatch(Exception):
    """Образец подстановки не найден в шаблоне — шаблон разошёлся с картой."""


# ── Даты и деньги ────────────────────────────────────────────────────────────

def fmt_short(d):
    return d.strftime("%d.%m.%Y") if d else ""


def fmt_long(d, suffix="г."):
    """«8 октября 2026 года» / «08 октября 2026 г»: без ведущего нуля — см. fmt_day."""
    return f"{d.day} {MONTHS_RU[d.month]} {d.year} {suffix}".strip() if d else ""


def fmt_day(d, suffix="года"):
    """«08 октября 2026 года» — день с ведущим нулём, как в шаблоне договора."""
    return f"{d.day:02d} {MONTHS_RU[d.month]} {d.year} {suffix}".strip() if d else ""


def fmt_quoted(d):
    """«09» июня 2026 г — как в шаблоне ходатайства (точка остаётся в шаблоне)."""
    return f"«{d.day:02d}» {MONTHS_RU[d.month]} {d.year} г" if d else ""


_UNITS_M = ["", "один", "два", "три", "четыре", "пять", "шесть", "семь", "восемь", "девять"]
_UNITS_F = ["", "одна", "две", "три", "четыре", "пять", "шесть", "семь", "восемь", "девять"]
_TEENS = ["десять", "одиннадцать", "двенадцать", "тринадцать", "четырнадцать", "пятнадцать",
          "шестнадцать", "семнадцать", "восемнадцать", "девятнадцать"]
_TENS = ["", "", "двадцать", "тридцать", "сорок", "пятьдесят", "шестьдесят", "семьдесят",
         "восемьдесят", "девяносто"]
_HUNDREDS = ["", "сто", "двести", "триста", "четыреста", "пятьсот", "шестьсот", "семьсот",
             "восемьсот", "девятьсот"]


def plural(n, one, few, many):
    n = abs(n) % 100
    if 11 <= n <= 19:
        return many
    n %= 10
    if n == 1:
        return one
    if 2 <= n <= 4:
        return few
    return many


def _triad(n, feminine=False):
    units = _UNITS_F if feminine else _UNITS_M
    words = [_HUNDREDS[n // 100]]
    rest = n % 100
    if 10 <= rest <= 19:
        words.append(_TEENS[rest - 10])
    else:
        words += [_TENS[rest // 10], units[rest % 10]]
    return [w for w in words if w]


def number_in_words(n):
    """Целое число прописью (м. р.), до миллионов: 232 → «двести тридцать два»."""
    n = int(n)
    if n == 0:
        return "ноль"
    words = []
    millions, rest = divmod(n, 1_000_000)
    thousands, units = divmod(rest, 1000)
    if millions:
        words += _triad(millions) + [plural(millions, "миллион", "миллиона", "миллионов")]
    if thousands:
        words += _triad(thousands, feminine=True) + [plural(thousands, "тысяча", "тысячи", "тысяч")]
    words += _triad(units)
    return " ".join(words)


def rubles_phrase(amount):
    """232.18 → «232,18 (двести тридцать два) рубля 18 копеек»."""
    cents = round(float(amount) * 100)
    rubles, kopecks = divmod(cents, 100)
    return (f"{rubles},{kopecks:02d} ({number_in_words(rubles)}) "
            f"{plural(rubles, 'рубль', 'рубля', 'рублей')} {kopecks:02d} "
            f"{plural(kopecks, 'копейка', 'копейки', 'копеек')}")


# ── Замена текста в абзацах ─────────────────────────────────────────────────

def _all_paragraphs(doc):
    yield from doc.paragraphs
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                yield from cell.paragraphs


def _strip_highlight(run):
    rpr = run._element.find(qn("w:rPr"))
    if rpr is not None:
        for el in rpr.findall(qn("w:shd")):
            rpr.remove(el)
        for el in rpr.findall(qn("w:highlight")):
            rpr.remove(el)


def strip_template_highlights(doc):
    """Снять подсветку шаблона (жёлтую/зелёную/голубую) — в документе остаётся
    только жёлтая пометка подставленного."""
    for para in _all_paragraphs(doc):
        for run in para.runs:
            _strip_highlight(run)


def _split_off(run, text_before, text_value, text_after):
    """Разбить run на «до | значение | после» с тем же форматированием; вернуть run значения."""
    run.text = text_value
    if text_before:
        before = copy.deepcopy(run._r)
        run._r.addprevious(before)
        Run(before, run._parent).text = text_before
    if text_after:
        after = copy.deepcopy(run._r)
        run._r.addnext(after)
        Run(after, run._parent).text = text_after
    return run


def replace_in_paragraph(para, old, new, highlight=True):
    """old → new в абзаце, даже если old разбит на несколько runs (первое
    вхождение). Значение кладётся в первый задетый run, хвост совпадения в
    остальных стирается. Если в первом run есть текст шаблона до/после
    совпадения, run разбивается — подсвечено только подставленное.
    Возвращает True, если замена была."""
    runs = para.runs
    full = "".join(r.text for r in runs)
    start = full.find(old)
    if start == -1:
        return False
    end = start + len(old)
    position, receiver, receiver_parts = 0, None, None
    for run in runs:
        text = run.text
        run_start, run_end = position, position + len(text)
        if run_end > start and run_start < end:
            prefix = text[:start - run_start] if run_start < start else ""
            suffix = text[end - run_start:] if run_end > end else ""
            if receiver is None:
                receiver, receiver_parts = run, (prefix, suffix)
            else:
                run.text = prefix + suffix
        position = run_end
    if receiver is not None:
        prefix, suffix = receiver_parts
        if highlight and new:
            _split_off(receiver, prefix, new, suffix).font.highlight_color = HIGHLIGHT
        else:
            receiver.text = prefix + new + suffix
    return True


@dataclass(frozen=True)
class Sub:
    """Подстановка: в абзаце с якорем `anchor` заменить образец `sample` значением `key`.

    count — сколько вхождений образца заменить (подпись «Отабоева Н.И.» дважды).
    optional — пустое значение не считается нехваткой и подставляется пустым.
    exact — якорь равен всему тексту абзаца (ячейки таблицы подписей, где тот же
    образец встречается и в тексте договора).
    """
    anchor: str
    sample: str
    key: str
    count: int = 1
    optional: bool = False
    exact: bool = False


def _find_paragraphs(doc, anchor, exact=False):
    if exact:
        return [para for para in _all_paragraphs(doc) if para.text.strip() == anchor]
    return [para for para in _all_paragraphs(doc) if anchor in para.text]


def render(template_path, subs, values, allow_missing=False):
    """Сгенерировать документ. Возвращает (bytes, недостающие ключи).

    Нехватка значения при allow_missing=False — ValueError со списком ключей;
    образец не найден — TemplateMismatch.
    """
    missing = sorted({s.key for s in subs if not s.optional and not str(values.get(s.key) or "").strip()})
    if missing and not allow_missing:
        raise ValueError("Не хватает данных: " + ", ".join(missing))

    doc = Document(str(template_path))
    strip_template_highlights(doc)
    for sub in subs:
        value = str(values.get(sub.key) or "").strip()
        if not value:
            value = "" if sub.optional else NO_DATA
        paragraphs = _find_paragraphs(doc, sub.anchor, sub.exact)
        if not paragraphs:
            raise TemplateMismatch(f"Абзац с «{sub.anchor}» не найден в {template_path.name}")
        done = 0
        for para in paragraphs:
            while done < sub.count and replace_in_paragraph(para, sub.sample, value):
                done += 1
        if done < sub.count:
            raise TemplateMismatch(f"Образец «{sub.sample}» (абзац «{sub.anchor}») не найден в {template_path.name}")
    buffer = BytesIO()
    doc.save(buffer)
    return buffer.getvalue(), missing


def drop_paragraphs(content, anchor):
    """Удалить абзацы с якорем (строка патента у граждан РФ)."""
    doc = Document(BytesIO(content))
    for para in _find_paragraphs(doc, anchor):
        para._element.getparent().remove(para._element)
    buffer = BytesIO()
    doc.save(buffer)
    return buffer.getvalue()


# ── Карта подстановок: трудовой договор ─────────────────────────────────────
# Образцы — текст шаблона data/templates/contract_template.docx (жёлтое — сотрудник,
# зелёное — юрлицо). Подробно — docs/contracts.md.

CONTRACT_SUBS = [
    # Шапка: город и дата
    Sub("2026 г.", "г. Санкт-Петербург", "city"),
    Sub("2026 г.", "08 октября 2026 г", "contract_date_head"),
    # Стороны
    Sub("именуемый в дальнейшем «Работодатель»", "Общество с ограниченной ответственностью «БАЛТИЙСКИЙ ДОМ»", "le_full_name"),
    Sub("именуемый в дальнейшем «Работодатель»", "ООО «БАЛТИЙСКИЙ ДОМ»", "le_short_name"),
    Sub("именуемый в дальнейшем «Работодатель»", "генерального директора", "le_director_title"),
    Sub("именуемый в дальнейшем «Работодатель»", "Хацкевич Виталия Сергеевича", "le_director_genitive"),
    Sub("именуемый в дальнейшем «Работодатель»", "гражданка Республики Узбекистана Отабоева Навбахор Исломбой Кизи",
        "employee_party"),
    # 1.1 должность, 1.3 место работы, 1.5 даты, 1.6 срок
    Sub("1.1. По настоящему Трудовому договору", "подсобный рабочий", "position"),
    Sub("1.3. Трудовая деятельность", "г. Санкт-Петербург, ул. Бабушкина д.40", "work_address"),
    Sub("1.5. Настоящий Трудовой договор вступает в силу", "08 октября 2026 года", "effective_date"),
    Sub("1.5. Настоящий Трудовой договор вступает в силу", "08 октября 2026 года", "start_date"),
    Sub("1.6. Настоящий Трудовой договор заключен",
        "на неопределенный срок./ на срок до «дата окончания патента»", "term"),
    # 5.1 ставка
    Sub("5.1. Работнику устанавливается часовая тарифная ставка",
        "232,18 (двести тридцать два) рублей 18 копейка", "rate_phrase"),
    # Реквизиты работодателя (таблица подписей, левая колонка)
    Sub("ООО «БАЛТИЙСКИЙ ДОМ»", "ООО «БАЛТИЙСКИЙ ДОМ»", "le_short_name", exact=True),
    Sub("Юридический адрес:", "195196, Г.САНКТ-ПЕТЕРБУРГ, ВН.ТЕР.Г. МУНИЦИПАЛЬНЫЙ ОКРУГ МАЛАЯ ОХТА, "
        "УЛ. ТАЛЛИНСКАЯ, Д. 7 ЛИТЕРА И, ПОМЕЩ. 4Н/6Н, ОФИС 325", "le_legal_address"),
    Sub("ИНН/КПП:", "7805595716", "le_inn"),
    Sub("ИНН/КПП:", "780601001", "le_kpp"),
    Sub("ОГРН:", "1127847392243", "le_ogrn"),
    Sub("р/с ", "40702810370110000801", "le_bank_account"),
    Sub("МОДУЛЬБАНК", 'МОСКОВСКИЙ ФИЛИАЛ АО КБ "МОДУЛЬБАНК"', "le_bank_name"),
    Sub("БИК: ", "044525092", "le_bik"),
    Sub("К/с ", "30101810645250000092", "le_corr_account"),
    Sub("В.С. Хацкевич", "В.С. Хацкевич", "le_director_short"),
    # Реквизиты работника (правая колонка)
    Sub("Отабоева Навбахор Исломбой Кизи", "Отабоева Навбахор Исломбой Кизи", "fio", exact=True),
    Sub("г.р.", "21.03.1998", "birth_date"),
    Sub("Паспорт №", "№FA9061607 выдан 25.01.2024", "passport"),
    Sub("ИНН 780114424010", "780114424010", "inn"),
    Sub("СНИЛС ", "229-798-702 37", "snils"),
    Sub("Патент серия", "Патент серия 78 №2600131320 выдан 18.08.2026 ГУ МВД России по г. Санкт-Петербургу и "
        "Ленинградской области, серия и номер бланка ПР 8408114 срок действия патента 18.08.2026- 17.08.2027",
        "patent_line"),
    Sub("Отабоева Н.И.", "Отабоева Н.И.", "initials", count=2),
    Sub("8 октября 2026 года", "8 октября 2026 года", "receipt_date"),
]
PATENT_LINE_ANCHOR = "Патент серия"

# ── Карта подстановок: ходатайство ──────────────────────────────────────────
# Голубое — юрлицо, зелёное — адресат по региону, жёлтое — сотрудник и патент.

PETITION_SUBS = [
    Sub("Общество с ограниченной ответственностью", "Общество с ограниченной ответственностью ", "le_full_name"),
    Sub("«ЦКК»", "«ЦКК»", "empty", optional=True),
    Sub("ОГРН ", "1217700138633", "le_ogrn"),
    Sub("ОГРН ", "773301001", "le_kpp"),
    Sub("ОГРН ", "9701173752", "le_inn"),
    Sub("Волоколамское", "125371, город Москва, Волоколамское ш, д. 114 к. 1, помещ. 2/1", "le_legal_address"),
    Sub("Лиговский", "191040, г. Санкт-Петербург, пр-кт. Лиговский, д. 30, литера а", "le_actual_address"),
    Sub("Начальнику УВМ", "Начальнику УВМ ГУ МВД России", "uvm_addressee_1"),
    Sub("По Санкт -Петербургу", " По Санкт -Петербургу и  Ленинградской области ", "uvm_addressee_2", optional=True),
    Sub("Полковнику полиции", "Полковнику полиции", "uvm_rank"),
    Sub("Иванову Ивану Васильевичу", "Иванову Ивану Васильевичу", "uvm_person"),
    Sub("Прошу переоформить патент", "Улугбердиев Шавкат Шомуротович", "fio"),
    Sub("Патент серия", "78    №  2500130741", "patent_series_number"),
    Sub("Бланк патента", "ПР     №   5126345", "patent_blank"),
    Sub("Срок действия:", "с 23.07.2025 по 22.07.2026", "patent_period"),
    Sub("Дата  выдачи", "23.07.2025", "patent_issue_date"),
    Sub("Кем выдан", "ГУ МВД России по Санкт-Петербургу и Ленинградской обл.", "patent_authority"),
    Sub("Территория действия патента", "г.Санкт-Петербург", "patent_territory"),
    Sub("Профессия (специальность", "Подсобный рабочий", "patent_profession"),
    Sub("2026 г.", "«09» июня 2026 г", "petition_date"),
    Sub("Генеральный директор", "Бигильдин Тимур Ривкатевич", "le_director_name"),
]


def generate_contract(values, allow_missing=False, template_path=CONTRACT_TEMPLATE, with_patent=True):
    """bytes .docx трудового договора и список недостающих ключей."""
    subs = CONTRACT_SUBS if with_patent else [s for s in CONTRACT_SUBS if s.key != "patent_line"]
    content, missing = render(Path(template_path), subs, values, allow_missing=allow_missing)
    if not with_patent:
        content = drop_paragraphs(content, PATENT_LINE_ANCHOR)
    return content, missing


def generate_petition(values, allow_missing=False, template_path=PETITION_TEMPLATE):
    return render(Path(template_path), PETITION_SUBS, values, allow_missing=allow_missing)


def today():
    return date.today()

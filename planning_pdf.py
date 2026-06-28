"""
Генерация PDF бланка планирования (БП) по магазину — по образцу БП-007.

Чистый reportlab, без системных зависимостей (работает на Windows и на Render
без pango/cairo). Шрифт — вендорный DejaVu (static/fonts), полная кириллица.

Модуль только СТРОИТ PDF-файл на диске. Запись PlanningForm, аудит и отдача на
скачивание — в роутере.
"""

import os
from datetime import date
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.pdfmetrics import registerFontFamily
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

# --- Реквизиты компании. Пока КОНСТАНТЫ; позже — из LegalEntity. ---
COMPANY_NAME = "ООО «ПРОГРЕСС»"          # как в шапке (с кавычками)
COMPANY_NAME_PLAIN = "ООО ПРОГРЕСС"      # как в подвале образца (без кавычек)
COMPANY_PHONE = "+7 (495) 150-46-13"
COMPANY_EMAIL = "spb@progress.com.ru"
COMPANY_LEGAL_ADDRESS_LINES = (
    "143360, Московская область, Наро-Фоминский р-н,",
    "Апрелевка г, Парковая ул, стр. 1Б, комн.16",
)

# Палитра таблицы — оливковая (решение владельца): зелёная шапка,
# светло-оливковое чередование строк, тёмно-оливковый текст.
HEAD_BG = colors.HexColor("#8a9a3a")
ROW_ALT = colors.HexColor("#eef1dd")
TEXT_BLUE = colors.HexColor("#41501a")
LINE_DARK = colors.HexColor("#222222")

_BASE = Path(__file__).resolve().parent
FONT_DIR = _BASE / "static" / "fonts"
IMG_DIR = _BASE / "static" / "images"
LOGO_PATH = IMG_DIR / "progress_logo.jpg"
STAMP_PATH = IMG_DIR / "progress_stamp.jpg"

FONT = "DejaVu"
FONT_BOLD = "DejaVu-Bold"

# Геометрия страницы.
PAGE_W, PAGE_H = A4
MARGIN_X = 18 * mm
HEADER_H = 34 * mm   # высота шапки сверху
FOOTER_H = 50 * mm   # высота подвала снизу

_FONTS_REGISTERED = False


def _register_fonts():
    global _FONTS_REGISTERED
    if _FONTS_REGISTERED:
        return
    pdfmetrics.registerFont(TTFont(FONT, str(FONT_DIR / "DejaVuSans.ttf")))
    pdfmetrics.registerFont(TTFont(FONT_BOLD, str(FONT_DIR / "DejaVuSans-Bold.ttf")))
    registerFontFamily(FONT, normal=FONT, bold=FONT_BOLD, italic=FONT, boldItalic=FONT_BOLD)
    _FONTS_REGISTERED = True


def _fmt(d: date) -> str:
    return d.strftime("%d.%m.%Y")


def build_filename(tk_number, date_from: date) -> str:
    """Имя файла БП — как образец «БП-007 — ПРОГРЕСС — 07-05-2026»."""
    return f"БП-{int(tk_number):03d}_ПРОГРЕСС_{date_from.strftime('%d-%m-%Y')}.pdf"


def _img_size(path, target_w=None, target_h=None):
    """Размеры картинки с сохранением пропорций под заданную ширину/высоту."""
    from reportlab.lib.utils import ImageReader

    iw, ih = ImageReader(str(path)).getSize()
    if target_w is not None:
        return target_w, target_w * ih / iw
    return target_h * iw / ih, target_h


def _draw_header_footer(canvas, doc):
    """Шапка и подвал — рисуются на каждой странице (canvas), таблица между ними."""
    canvas.saveState()

    # --- Шапка: лого слева, реквизиты справа, тонкая линия снизу ---
    if LOGO_PATH.is_file():
        lw, lh = _img_size(LOGO_PATH, target_h=14 * mm)
        canvas.drawImage(
            str(LOGO_PATH), MARGIN_X, PAGE_H - 12 * mm - lh,
            width=lw, height=lh, mask="auto", preserveAspectRatio=True,
        )

    canvas.setFillColor(colors.black)
    right = PAGE_W - MARGIN_X
    top = PAGE_H - 13 * mm
    canvas.setFont(FONT_BOLD, 12)
    canvas.drawRightString(right, top, COMPANY_NAME)
    canvas.setFont(FONT, 10)
    canvas.drawRightString(right, top - 6.0 * mm, COMPANY_PHONE)
    canvas.drawRightString(right, top - 11.2 * mm, COMPANY_EMAIL)

    line_y = PAGE_H - HEADER_H
    canvas.setStrokeColor(LINE_DARK)
    canvas.setLineWidth(1.2)
    canvas.line(MARGIN_X, line_y, PAGE_W - MARGIN_X, line_y)

    # --- Подвал: линия сверху, реквизиты слева, юр.адрес справа ---
    foot_line_y = FOOTER_H

    # Печать рисуется ПЕРВОЙ (нижний слой) — белый фон JPG сливается с белой
    # страницей, а текст идёт поверх (как в образце). Размер +50%, по центру,
    # совмещена по высоте со строками подвала.
    if STAMP_PATH.is_file():
        sw, sh = _img_size(STAMP_PATH, target_h=39 * mm)
        canvas.drawImage(
            str(STAMP_PATH), (PAGE_W - sw) / 2, foot_line_y - sh - 1 * mm,
            width=sw, height=sh, mask="auto", preserveAspectRatio=True,
        )

    canvas.setStrokeColor(LINE_DARK)
    canvas.setLineWidth(1.2)
    canvas.line(MARGIN_X, foot_line_y, PAGE_W - MARGIN_X, foot_line_y)

    canvas.setFillColor(colors.black)
    canvas.setFont(FONT, 9)
    ty = foot_line_y - 5 * mm
    for ln in (COMPANY_NAME_PLAIN, COMPANY_PHONE, COMPANY_EMAIL):
        canvas.drawString(MARGIN_X, ty, ln)
        ty -= 4.6 * mm

    # Юр.адрес справа — 2 строки (без подписи «Юридический адрес», как в образце).
    ty = foot_line_y - 5 * mm
    for ln in COMPANY_LEGAL_ADDRESS_LINES:
        canvas.drawRightString(PAGE_W - MARGIN_X, ty, ln)
        ty -= 4.6 * mm

    canvas.restoreState()


def build_planning_pdf(path, *, tk_number, object_address, city, date_from, date_to, employees):
    """
    Собрать PDF бланка планирования.

    employees — список ФИО (уже отсортированный). ТК и адрес одинаковы во всех
    строках таблицы (как образец).
    """
    _register_fonts()
    path = str(path)

    tk_label = f"{int(tk_number):03d}"   # 007 — в обращении и имени файла
    tk_cell = str(int(tk_number))        # 7 — в колонке таблицы (как образец)
    addr = object_address or "—"

    title = ParagraphStyle(
        "title", fontName=FONT_BOLD, fontSize=15, leading=20,
        alignment=TA_CENTER, spaceBefore=4, spaceAfter=12,
    )
    intro_n = ParagraphStyle(
        "intro_n", fontName=FONT, fontSize=11, leading=15, alignment=TA_CENTER,
    )
    intro_b = ParagraphStyle(
        "intro_b", fontName=FONT_BOLD, fontSize=11, leading=15, alignment=TA_CENTER,
    )
    cell = ParagraphStyle("cell", fontName=FONT, fontSize=10, leading=13, textColor=TEXT_BLUE)
    head_cell = ParagraphStyle(
        "head", fontName=FONT_BOLD, fontSize=10, leading=13, textColor=colors.white,
    )

    # Обращение — отдельными центрированными строками, как в образце.
    story = [Paragraph("БЛАНК ПЛАНИРОВАНИЯ", title)]
    for text, st in [
        ("Просим Вас обеспечить доступ сотрудникам компании", intro_n),
        (f"{COMPANY_NAME} на объект по адресу:", intro_b),
        (addr, intro_b),
        (f"ТК-{tk_label}", intro_b),
        (f"На период {_fmt(date_from)} – {_fmt(date_to)}", intro_b),
    ]:
        story.append(Paragraph(text, st))
        story.append(Spacer(1, 5))
    story.append(Spacer(1, 8))

    data = [[
        Paragraph("ТК", head_cell),
        Paragraph("РАБОТНИК", head_cell),
        Paragraph("адрес", head_cell),
    ]]
    for name in employees:
        data.append([
            Paragraph(tk_cell, cell),
            Paragraph(name, cell),
            Paragraph(addr, cell),
        ])

    # Таблица по центру страницы, оливковые полосы без сетки.
    col_w = [12 * mm, 72 * mm, 64 * mm]
    table = Table(data, colWidths=col_w, repeatRows=1, hAlign="CENTER")
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), HEAD_BG),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]
    for i in range(1, len(data)):
        if i % 2 == 1:
            style.append(("BACKGROUND", (0, i), (-1, i), ROW_ALT))
    table.setStyle(TableStyle(style))
    story.append(table)

    frame = Frame(
        MARGIN_X, FOOTER_H,
        PAGE_W - 2 * MARGIN_X, PAGE_H - HEADER_H - FOOTER_H,
        leftPadding=0, rightPadding=0, topPadding=6 * mm, bottomPadding=0,
    )
    doc = BaseDocTemplate(
        path, pagesize=A4,
        leftMargin=MARGIN_X, rightMargin=MARGIN_X,
        topMargin=HEADER_H, bottomMargin=FOOTER_H,
        title="Бланк планирования",
    )
    doc.addPageTemplates([
        PageTemplate(id="bp", frames=[frame], onPage=_draw_header_footer),
    ])
    doc.build(story)
    return path


if __name__ == "__main__":
    # Черновик для визуальной проверки вёрстки под образец.
    sample = os.path.join(
        os.path.dirname(__file__) if "__file__" in globals() else ".",
        "bp_draft_sample.pdf",
    )
    build_planning_pdf(
        sample,
        tk_number=7,
        object_address="г. Москва, Кутузовский проспект, д. 57",
        city="Москва",
        date_from=date(2026, 6, 29),
        date_to=date(2026, 6, 30),
        employees=[
            "Ахметов Руслан Маратович",
            "Колесников Иван Петрович",
            "Петров Сергей Александрович",
            "Сидорова Анна Викторовна",
        ],
    )
    print("written", sample)

# Как перевести страницу на base.html

Паттерн отработан на пилоте (login / rates / cabinet) и на эталоне admin_dashboard.
Дальше волнами: админка -> кабинет -> отчёты. Роуты, контекст, имена полей и JS не трогаем.

## 5 шагов

1. **Шапка файла целиком удаляется.** `<!DOCTYPE>`, `<head>`, фавиконы, meta, `<style>`,
   `<body>`, `</html>` — всё это теперь в base.html. Вместо них первая строка файла:
   `{% extends "base.html" %}`.
2. **Заголовки — в блоки:**
   ```
   {% block title %}ЧТС{% endblock %}
   {% block brand_title %}ЧТС{% endblock %}
   {% block brand_subtitle %}<p class="brand-subtitle">…</p>{% endblock %}
   {% block topbar_actions %}<a href="/admin" class="back-link">Назад в админку</a>{% endblock %}
   ```
   `topbar_actions` по умолчанию = «Выйти». Страница без шапки (логин): `{% block topbar %}{% endblock %}`.
3. **Содержимое — в `{% block content %}`**, начиная с `<div class="page">`
   (`page-narrow` = 1040px, `page-wide` = 1600px). Скрипты — в `{% block scripts %}` как есть.
4. **Локальный CSS выбросить, классы заменить на системные** (таблица ниже).
   Всё, что осталось и реально уникально для страницы — в `{% block head %}<style>…</style>{% endblock %}`.
   Это только ширины колонок, min-width таблицы, единичные оффсеты. Если правило пригодится
   второй странице — его место в app.css, а не в block head.
5. **Проверить:** форма постится, фильтры держат query-параметры, модалки открываются,
   печать/экспорт (`.no-print`) целы, на 720px ничего не разъезжается.

## Замена классов (что было -> что стало)

| Старое | Новое |
|---|---|
| локальный `:root` | удалить, токены в app.css |
| `.card` как карточка-ссылка раздела | `.nav-card` |
| `.card` как панель | `.card` (padding 20, radius 13), узкая — `.card.card-tight` |
| `.btn` + локальный градиент | `.btn.btn-primary` (плоский `--brand-blue`) |
| `.btn-danger` с градиентом | `.btn.btn-danger` |
| `.logout`, `.back-link` | оставить как есть — в app.css они алиасы `.btn-secondary` |
| `.msg` / `.err` / `.error` | `.alert.alert-success` / `.alert.alert-error` / `.alert.alert-warn` (старые имена работают) |
| инлайновые ссылки-фильтры | `.tabs` + `.tab` + `.tab.is-active` |
| `.summary-pill`, `.docs-chip` | `.pill.pill-peach`, `.chip` |
| `.filter-form` | `.form-grid.cols-3.align-end` |
| `table` + локальные `th/td` | `.table-wrap` > `table` (sticky-шапка уже в системе) |
| `style="…"` для отступов | `.mt-*` / `.mb-*` / `.row` / `.stack` / `.muted` / `.field-hint` |
| `.page { padding-top: 20px }` в block head | класс `.page-pad-top` (страница без `.hero`) |
| `.module` / `.module-grid` (старый `employees.css`) | `.nav-card` / `.grid` |
| `.panel`, `.btn.light`, `.btn.good` / `.btn.warn` | `.card`, `.btn-secondary`, `.btn-primary` / `.btn-danger` |

## Типовые грабли

- **Имя класса, собранное внутри Jinja, переименовывать НЕЛЬЗЯ.** Если в разметке
  `class="pill {{ row.status_class }}"` или `{{ 'active' if view == 'registry' }}`, то менять
  выражение запрещено правилами — значит, менять нечего. Оформление задавайте **алиасом**
  в `{% block head %}` поверх системных токенов: `.pill.ok { background: var(--success-bg); … }`.
  Так сделано в `documents`, `referral`, `citizenship_*`, `admin_email_test`.
  Осторожно с коллизиями: класс `error` из выражения столкнётся с системным `.alert`-подобным
  `.error` — в `admin_email_test` это решено префиксом `status-`.
- **Повторил правило на второй странице — вынеси в app.css.** Это не пожелание, а то, ради чего
  всё затевалось. На волнах 1–3 всплыли три дубля: кнопки экспорта в 4 файлах, блоки писем в 3,
  `padding-top` в 12. Все сведены в app.css. Проверяйте себя: `grep -l "ваш-класс" templates/*.html`.
- **`.card` двусмысленный.** В эталоне так называлась карточка-ссылка. В системе `.card` — панель,
  ссылка — `.nav-card`. При переводе смотреть, что за элемент, а не только на имя класса.
- **Ширины таблиц.** `min-width` у `table` — свойство конкретной страницы, оно уезжает в block head
  (`.rates-table table { min-width: 1450px; }`), а не в app.css.
- **`.inline-form`.** Сетка колонок у каждой страницы своя — только в block head.
- **Липкие шапки.** `.topbar-sticky` и `.quicknav-sticky` не включены по умолчанию:
  добавляются через `{% block topbar_class %}`. Если обе липкие — проверить `top` у quicknav.
- **Печать.** `.no-print` / `.print-only` в app.css; не заводить локальные `@media print`.
- **data-атрибуты.** Модалки, `return_to`, html2canvas-экспорт читают `data-*` — при перекраске
  разметки атрибуты и `id` переносить дословно.
- **Ширина страницы — только на `.page`.** `page-narrow` (1040) / `page-wide` (1600) / без класса
  (1240) ставятся на сам `.page`. Топбар и quicknav лежат рядом, а не внутри, поэтому app.css
  дублирует модификатор через `body:has(.page-wide)` — так шапка, quicknav и контент выравниваются
  по одной левой границе. Заводите новый модификатор ширины — добавьте и парное `body:has(...)`,
  иначе лого уедет от края контента. Это проверяет `tests/test_templates_base.py`.
- **Кодировка.** Python 3.11, файлы CRLF без BOM.
- **Кэш.** app.css подключён как `/static/app.css?v=3` — при правках системы поднимать `v`.

## Сверка: правка обязана остаться представленческой

```
PYTHONIOENCODING=utf-8 python tools/check_migration.py ИМЯ.html   # одна страница
PYTHONIOENCODING=utf-8 python tools/check_migration.py            # всё изменённое
```

Скрипт сравнивает мультимножества Jinja-выражений и значимых атрибутов (`name`, `id`, `action`,
`formaction`, `method`, `data-*`, `value`, `href`, `enctype`, инлайновые `on*`, `required`/`min`/
`max`/`pattern`, `colspan`, `placeholder`) с версией из git. Должно быть `ok`. Прогоняйте после
**каждого** файла, а не в конце волны.

Чего скрипт НЕ видит — проверяйте глазами: атрибут `style=`, имена CSS-классов, текст, порядок
элементов. Расхождение в мультимножестве не всегда ошибка (переверстать `div`-строки в таблицу
допустимо), но каждое обязано быть разобрано и названо вслух, а не молча принято.

## Границы

Правки только представленческие: класс, обёртка, порядок блоков. Имена полей, `action`, `method`,
Jinja-выражения, JS-обработчики и `id` остаются байт-в-байт.

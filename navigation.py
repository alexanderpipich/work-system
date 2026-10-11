"""Реестр навигации: группы и карточки дашборда как данные (П2).

Один дашборд для всех ролей. Карточка видна всегда; доступна, если у пользователя
есть хотя бы один вариант перехода. Недоступная рисуется приглушённой, а клик
объясняет, каким ролям раздел доступен (static/ui.js, `data-locked`).

Вариант перехода — `(href, permission, roles)`. У разделов, которые роли открывают
под своим префиксом (`/hr/...`, `/economist/...` — это разные режимы: просмотр,
своя область, свои фильтры), вариантов несколько; берётся первый подходящий.
`roles=None` — достаточно права. Первым всегда идёт канонический `/admin/...`
(его `href` и считается адресом карточки).

Права — строки из `rbac.PERMISSIONS`; суперадмин проходит любое право. `None` у
`permission` вместе с `coming_soon=True` — заглушка будущего модуля.
"""

from rbac import (
    ROLE_BRIGADIER,
    ROLE_ECONOMIST,
    ROLE_HR_CLERK,
    ROLE_HR_LEAD,
    ROLE_LABELS,
    ROLE_SUPERADMIN,
    ROLE_TM,
    ROLES,
    canonical_role,
    has_permission,
)

SA = {ROLE_SUPERADMIN}
ECON = {ROLE_ECONOMIST}
HR_VIEW = {ROLE_HR_LEAD, ROLE_TM}  # /hr-разделы выплат, ставок, ЛМК, отчётов, графиков
HR_CAB = {ROLE_HR_LEAD, ROLE_TM, ROLE_HR_CLERK}  # /hr-разделы сотрудников и документов

# Порядок ролей в подписях «доступно ролям».
ROLE_ORDER = ["superadmin", "hr_lead", "tm", "hr_clerk", "economist", "brigadier", "headhunter", "employee"]

ICONS = {
    "employees": ("indigo", '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M16 19v-1.5a3 3 0 0 0-3-3H7a3 3 0 0 0-3 3V19"/><circle cx="10" cy="7.5" r="3"/><path d="M17 5.5a3 3 0 0 1 0 5.8"/><path d="M20 19v-1.5a3 3 0 0 0-2.2-2.9"/></svg>'),
    "users": ("indigo", '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="8" r="3.5"/><path d="M5 20a7 7 0 0 1 14 0"/></svg>'),
    "upload_users": ("indigo", '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 15V4"/><path d="M8 8l4-4 4 4"/><path d="M4 15v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"/></svg>'),
    "upload": ("sky", '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8h8M8 12h8M8 16h5"/></svg>'),
    "rates": ("amber", '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 20V5h4.5a3.5 3.5 0 0 1 0 7H9"/><path d="M7 14h7"/></svg>'),
    "payroll": ("amber", '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="6" width="18" height="13" rx="2.5"/><path d="M3 10h18"/><circle cx="16.5" cy="14.5" r="1.4"/></svg>'),
    "schedules": ("violet", '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3.5" y="5" width="17" height="15" rx="2.5"/><path d="M3.5 10h17M8 3.5v3M16 3.5v3"/></svg>'),
    "requisites": ("teal", '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3.5 10L12 5l8.5 5"/><path d="M5 10v8M19 10v8M9.5 10v8M14.5 10v8"/><path d="M3.5 20h17"/></svg>'),
    "lmk": ("rose", '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="3" width="16" height="18" rx="2.5"/><path d="M12 8v8M8 12h8"/></svg>'),
    "adjustments": ("coral", '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4.5 21 19.5H3z"/><path d="M12 10v4"/><circle cx="12" cy="17" r=".6" fill="currentColor" stroke="none"/></svg>'),
    "referral": ("rose", '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 12.5a5.5 5.5 0 0 1 5.5-5.5h4a5.5 5.5 0 0 1 5.5 5.5v1a4.5 4.5 0 0 1-4.5 4.5h-6A4.5 4.5 0 0 1 4 13.5z"/><path d="M19 11.5l1.8-.9a.6.6 0 0 1 .85.55v2.7a.6.6 0 0 1-.85.55L19 13.5"/><path d="M7 18v2M15.5 18v2"/><path d="M8.5 6.8 7.6 4.2a.6.6 0 0 1 .8-.74l3.1 1.3"/><path d="M10.5 11.5h4"/><circle cx="7.6" cy="11.8" r=".9" fill="currentColor" stroke="none"/></svg>'),
    "documents": ("coral", '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M16.5 7.5 9 15a3 3 0 0 0 4.2 4.2l6.4-6.4a5 5 0 0 0-7-7L5.6 12.7a7 7 0 0 0 9.9 9.9"/></svg>'),
    "citizenship": ("sky", '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17"/><path d="M12 3.5c2.5 2.4 2.5 14.2 0 17"/></svg>'),
    "document_types": ("violet", '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 4h6l3.5 3.5V18a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z"/><path d="M14 4v4h3.5"/><path d="M9.5 13h5M9.5 16h3"/></svg>'),
    "legal_entities": ("teal", '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 20V7l7-3 7 3v13"/><path d="M9 20v-5h4v5"/><path d="M8 11h1.5M14 11h1.5"/></svg>'),
    "stores": ("lime", '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 9l1-4h14l1 4"/><path d="M5 9v11h14V9"/><path d="M9 20v-6h6v6"/></svg>'),
    "planning_bp": ("violet", '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="3" width="14" height="18" rx="2"/><path d="M8.5 8h7M8.5 11.5h7M8.5 15h4"/><path d="M15 18.5l1.6 1.6 3-3.4"/></svg>'),
    "email": ("sky", '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="5.5" width="18" height="13" rx="2.5"/><path d="M3.6 7l8.4 6 8.4-6"/></svg>'),
    "email_unplanned": ("coral", '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="5.5" width="14" height="11" rx="2"/><path d="M3.6 7l6.4 4.6L15 8.6"/><circle cx="18.5" cy="16.5" r="3.5"/><path d="M18.5 14.8v1.9"/></svg>'),
    "email_planning": ("indigo", '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="5.5" width="14" height="11" rx="2"/><path d="M3.6 7l6.4 4.6L15 8.6"/><path d="M15 14h5v6h-5z"/></svg>'),
    "email_reconciliation": ("teal", '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="5.5" width="14" height="11" rx="2"/><path d="M3.6 7l6.4 4.6L15 8.6"/><path d="M15.5 20v-3M18 20v-5M20.5 20v-2"/></svg>'),
    "messages": ("slate", '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 14.5a2.5 2.5 0 0 1-2.5 2.5H9l-4 3.5V6.5A2.5 2.5 0 0 1 7.5 4h10A2.5 2.5 0 0 1 20 6.5z"/><path d="M9 9h8M9 12.5h5"/></svg>'),
    "reports": ("lime", '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="3.5" width="16" height="17" rx="2"/><path d="M8 15v-3M12 15v-6M16 15v-4"/></svg>'),
    "analytics": ("amber", '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 19h16"/><path d="M5 15l4.5-5 3.5 3.5L19 6"/><circle cx="19" cy="6" r="1.4"/></svg>'),
    "audit": ("slate", '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 4h12v16H6z"/><path d="M9 8.5h6M9 12h6M9 15.5h4"/><path d="M6 4v16" stroke-width="2.4"/></svg>'),
    "hr_team": ("violet", '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="9" cy="8" r="3.5"/><path d="M3 20a6 6 0 0 1 12 0"/><path d="M16 11.5l2 2 4-4"/></svg>'),
    "services": ("violet", '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h10"/></svg>'),
    "payroll_runs": ("slate", '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 4h12v16H6z"/><path d="M9 8.5h6M9 12h6M9 15.5h4"/><path d="M6 4v16" stroke-width="2.4"/></svg>'),
    "access": ("sky", '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4.5" y="10.5" width="15" height="9.5" rx="2.5"/><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"/><circle cx="12" cy="15.2" r="1.3"/></svg>'),
    "stores_directory": ("lime", '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 9l1-4h14l1 4"/><path d="M5 9v11h14V9"/><path d="M9 20v-6h6v6"/></svg>'),
}
# Иконки разделов, появившихся в П2 (стиль тот же: 24×24, линия).
ICONS.update({
    "dismissals": ("coral", '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="10" cy="8" r="3.5"/><path d="M3 20a7 7 0 0 1 14 0"/><path d="M16 11h6"/></svg>'),
    "monitoring": ("sky", '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 12h4l2-5 4 10 2-5h6"/></svg>'),
    "contracts": ("violet", '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 3.5h7l4 4v13H7z"/><path d="M14 3.5v4h4"/><path d="M9.5 16c1.5-2 2.5-2 3 0s1.5 2 3 0"/></svg>'),
    "payouts": ICONS["payroll"],
    "advances": ("amber", '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3.5" y="5" width="17" height="15" rx="2.5"/><path d="M3.5 10h17M8 3.5v3M16 3.5v3"/><path d="M9 14.5h6"/></svg>'),
    "reconciliations": ("teal", '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 12l3 3 6-7"/><path d="M14 18h6M15 13h5"/></svg>'),
    "employee_list": ("indigo", ICONS["users"][1]),
    "regions": ("teal", '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 21s-7-6.2-7-11.5A7 7 0 0 1 19 9.5C19 14.8 12 21 12 21z"/><circle cx="12" cy="9.5" r="2.5"/></svg>'),
    "upload_auto": ("sky", ICONS["upload"][1]),
})


def card(key, title, desc, variants=(), icon=None, coming_soon=False, hidden_for=()):
    """Карточка. `variants` — [(href, permission, roles|None)], канонический первым.
    hidden_for — роли, которым карточка не показывается вовсе (дубль другого раздела)."""
    variants = [tuple(v) for v in variants]
    return {
        "key": key,
        "title": title,
        "desc": desc,
        "href": variants[0][0] if variants else "#",
        "permission": variants[0][1] if variants else None,
        "variants": variants,
        "icon": icon or key,
        "coming_soon": coming_soon,
        "hidden_for": frozenset(hidden_for),
    }


NAV_GROUPS = [
    {"key": "people", "title": "Сотрудники и доступ", "cards": [
        card("employees", "Сотрудники",
             "Линейный персонал: список сотрудников и сверки часов по магазинам.",
             [("/admin/employees", "employees.view", SA),
              ("/hr/employees", "employees.view", HR_CAB),
              ("/economist/employees", "employees.view", ECON)]),
        card("users", "Пользователи",
             "Фильтры, роли, магазины бригадиров, гражданство, юрлица, пароли и удаление сотрудников.",
             [("/admin/users", "users.view", None)]),
        card("upload_users", "Импорт пользователей",
             "Массовая загрузка сотрудников из Excel с телефонами, ФИО и паролями.",
             [("/admin/upload-users", "users.manage", None)]),
        card("upload", "Загрузка смен",
             "Загрузка Excel со сменами. Учитываются магазин, город, формат, услуга, сотрудник и часы.",
             [("/admin/upload", "shifts.upload", None)]),
        card("hr_team", "Команда ТМ",
             "Назначение регионов территориальным менеджерам.",
             [("/hr/team", "hr_team.manage", None)]),
        # У суперадмина сброс паролей — в «Пользователях»; дубль ему не показываем (П4.2).
        card("access", "Доступ сотрудников",
             "Безопасный сброс паролей сотрудников и бригадиров.",
             [("/hr/access", "password.reset_limited", HR_VIEW)],
             hidden_for={ROLE_SUPERADMIN}),
    ]},
    {"key": "money", "title": "Время, ставки и выплаты", "cards": [
        card("rates", "ЧТС",
             "Ставки по услугам, форматам, магазинам и индивидуальным сотрудникам.",
             [("/admin/rates", "rates.manage", SA),
              ("/economist/rates", "rates.view", ECON),
              ("/hr/rates", "rates.view", HR_VIEW)]),
        card("payouts", "Выплаты",
             "Еженедельные авансы, выплатной табель за полмесяца и история выплат.",
             [("/admin/payouts", "payroll.view", None)]),
        card("schedules", "Графики выходов",
             "Просмотр выходов сотрудников по магазинам и периодам в формате календарной таблицы.",
             [("/admin/schedules", "schedules.admin_view", None),
              ("/economist/schedules", "schedules.view", ECON),
              ("/hr/schedules", "schedules.view", HR_VIEW),
              ("/brigadier", "schedules.view", {ROLE_BRIGADIER})]),
        card("requisites", "Реквизиты",
             "Реквизиты сотрудников: карта, телефон для выплаты, банк, ИНН, счёт и БИК.",
             [("/admin/requisites", "requisites.manage", SA),
              ("/hr/requisites", "requisites.view", HR_VIEW),
              ("/economist/requisites", "requisites.view", ECON)]),
        card("lmk", "ЛМК",
             "Удержания за личные медицинские книжки: сумма, период списания, остаток и статус.",
             [("/admin/lmk", "lmk.manage", SA),
              ("/economist/lmk", "lmk.manage", ECON),
              ("/hr/lmk", "lmk.view", HR_VIEW)]),
        card("adjustments", "МОНИТОРИНГ ИЗМЕНЕНИЙ",
             "Контроль и подтверждение автоматических корректировок по табелям.",
             [("/admin/adjustments", "adjustments.manage", SA),
              ("/economist/adjustments", "adjustments.manage", ECON)]),
        card("referral", "Акции",
             "Реферальная программа: приглашения сотрудников, начисления и выплаты бонусов за приведённых кандидатов.",
             [("/admin/referral", "payroll.manage", SA),
              ("/economist/referral", "payroll.manage", ECON)]),
    ]},
    {"key": "documents", "title": "Документы, Кадры и комплаенс", "cards": [
        card("documents", "Документы",
             "Реестр документов сотрудников: загрузка, проверка, отклонение, архив и контроль отсутствующих документов.",
             [("/admin/documents", "documents.manage", SA),
              ("/hr/documents", "documents.manage", HR_CAB),
              ("/economist/documents", "documents.verify", ECON)]),
        card("citizenship", "Гражданства и режимы",
             "Правовые режимы, справочник стран и матрица обязательных документов по режимам.",
             [("/admin/citizenship/regimes", "citizenship.manage", None)]),
        card("document_types", "Типы документов",
             "Настройка обязательных документов, подсказок, гражданства, сроков действия и образцов фото.",
             [("/admin/document-types", "documents.manage", SA),
              ("/hr/document-types", "documents.manage", HR_CAB),
              ("/economist/document-types", "documents.verify", ECON)]),
        card("dismissals", "Мониторинг увольнений",
             "Пропавшие со смен — кандидаты на увольнение (кадровое).",
             [("/admin/employees/dismissals", "employees.view", SA),
              ("/hr/employees/dismissals", "employees.view", HR_CAB),
              ("/economist/employees/dismissals", "employees.view", ECON)]),
        card("contracts", "Договоры",
             "Договоры с сотрудниками. Раздел появится в П4.",
             [("/admin/contracts", "contracts.view", None)]),
    ]},
    {"key": "directories", "title": "Справочники", "cards": [
        card("legal_entities", "Юрлица",
             "Единый список юридических лиц для сотрудников и фиксации выплатных табелей.",
             [("/admin/legal-entities", "legal_entities.manage", SA),
              ("/economist/legal-entities", "legal_entities.manage", ECON)]),
        card("stores", "Классификатор магазинов",
             "Торговые точки, адреса объектов, контакты по сценариям (планирование, сверки, уведомления).",
             [("/admin/stores", "stores.view", None)]),
        card("stores_directory", "Справочник магазинов",
             "Адреса и контакты магазинов.",
             [("/stores", "stores.directory.view", None)]),
        card("regions", "Регионы",
             "Адресат ходатайства в УВМ, орган выдачи и территория патента по региону работы.",
             [("/admin/regions", "regions.manage", None)]),
        card("services", "Услуги",
             "Справочник услуг и уровней: матрица по городам и форматам.",
             [("/admin/services", "services.view", None)]),
    ]},
    {"key": "planning", "title": "Планирование и рассылки", "cards": [
        card("planning_bp", "Бланк планирования",
             "Формирование PDF-бланка планирования по магазину (по образцу БП-007) и скачивание.",
             [("/admin/planning-bp", "planning.manage", None)]),
        card("monitoring", "Мониторинг сотрудников",
             "Рекомендации для бланка планирования: кого убрать из планирования, кого добавить — по фактическим сменам.",
             [("/admin/employees/monitoring", "employees.view", SA),
              ("/hr/employees/monitoring", "employees.view", HR_CAB),
              ("/economist/employees/monitoring", "employees.view", ECON)]),
        card("email", "Email / Рассылки",
             "Движок отправки писем через SMTP. Тест подключения, история отправок.",
             [("/admin/email/test", "email.manage", None)]),
        card("email_unplanned", "Рассылка: смены без плана",
             "Предпросмотр и ручная отправка писем директорам магазинов о сменах без плана.",
             [("/admin/email/unplanned", "email.manage", None)]),
        card("email_planning", "Рассылка: бланк планирования",
             "Предпросмотр и ручная отправка писем с PDF-бланком планирования на период.",
             [("/admin/email/planning-bp", "email.manage", None)]),
        card("email_reconciliation", "Рассылка: сверки",
             "Предпросмотр и ручная отправка XLS-сверки отработанных часов (тип A 01-15 / тип B весь месяц).",
             [("/admin/email/reconciliation", "email.manage", None)]),
        card("messages", "Сообщения",
             "Будущий модуль обмена сообщениями между администрацией, бригадирами и сотрудниками.",
             coming_soon=True),
    ]},
    {"key": "reports", "title": "Отчётность", "cards": [
        card("reports", "Отчеты",
             "Управленческие таблицы по часам, выплатам, корректировкам, ЛМК и документам.",
             [("/admin/reports", "reports.view", SA),
              ("/economist/reports", "reports.view", ECON),
              ("/hr/reports", "reports.view", HR_VIEW)]),
        card("analytics", "Аналитика",
             "KPI, предупреждения, динамика часов, выплат, документов, корректировок и ЛМК.",
             [("/admin/analytics", "reports.view", SA),
              ("/economist/analytics", "reports.view", ECON)]),
        card("audit", "Audit Log",
             "История действий пользователей: табели, корректировки, документы, ставки, реквизиты и справочники.",
             [("/admin/audit-log", "audit.view", None)]),
    ]},
]

# Поддашборд «Выплаты» (/admin/payouts).
PAYOUTS_GROUPS = [
    {"key": "payouts", "title": "Выплаты", "cards": [
        card("payroll", "Выплатной табель",
             "Расчёт недельных выплат по сменам и ЧТС с фильтрами по сотрудникам и магазинам.",
             [("/admin/payroll", "payroll.manage", SA),
              ("/economist/payroll", "payroll.view", ECON),
              ("/hr/payroll", "payroll.view", HR_VIEW)]),
        card("advances", "Еженедельные авансы",
             "Отметки ТМ, вычеты, фиксация недели и реестр выплат на карты.",
             [("/admin/payouts/advances", "payouts.advances.select_any", None),
              ("/admin/payouts/advances", "payouts.advances.fix", None),
              ("/admin/payouts/advances", "payouts.advances.select_own", None)]),
        card("payroll_runs", "История выплат",
             "Просмотр и экспорт зафиксированных табелей.",
             [("/admin/payroll/runs", "payroll.manage", SA),
              ("/economist/payroll/runs", "payroll.view", ECON),
              ("/hr/payroll/runs", "payroll.view", HR_VIEW)]),
    ]},
]


def employees_groups(base_path):
    """Поддашборд «Сотрудники» (/admin|/hr|/economist/employees).

    Сверки ведут под тот же префикс, с которого открыт поддашборд: обработчик один,
    а префикс задаёт область и обратные ссылки.
    """
    return [
        {"key": "employees", "title": "Сотрудники", "cards": [
            card("employee_list", "Список сотрудников",
                 "Линейный персонал: карточки, гражданство, реквизиты и закреплённый ТМ.",
                 [("/admin/users?role=employee", "users.view", None)]),
            card("reconciliations", "Сверки",
                 "Сверки часов по магазинам за фиксированные периоды.",
                 [("/admin/employees/reconciliations", "employees.view", SA),
                  ("/hr/employees/reconciliations", "employees.view", HR_CAB),
                  ("/economist/employees/reconciliations", "employees.view", ECON)]
                 if base_path == "/admin/employees" else
                 [(base_path + "/reconciliations", "employees.view", None)]),
        ]},
    ]


def _variant_ok(role, user, variant):
    _href, permission, roles = variant
    if roles is not None and role not in roles:
        return False
    return has_permission(user, permission)


class _RoleProbe:
    """Пользователь-заглушка для вопроса «доступно ли роли»."""

    def __init__(self, role):
        self.role = role
        self.is_admin = role == ROLE_SUPERADMIN


def role_href(user, entry):
    """Адрес карточки для пользователя или None, если доступа нет."""
    role = canonical_role(user)
    for variant in entry["variants"]:
        if _variant_ok(role, user, variant):
            return variant[0]
    return None


def allowed_roles(entry):
    """Роли (в порядке ROLE_ORDER), которым карточка доступна; суперадмин — всегда."""
    result = []
    for role in ROLE_ORDER:
        if role not in ROLES:
            continue
        if role == ROLE_SUPERADMIN or role_href(_RoleProbe(role), entry):
            result.append(role)
    return result


def build_navigation(user, groups=None):
    """Группы с карточками для пользователя: каждая карточка получает
    `available`, `url` (куда вести этого пользователя), `allowed_roles`
    и их подписи `roles_label`."""
    result = []
    role = canonical_role(user)
    for group in NAV_GROUPS if groups is None else groups:
        cards = []
        for entry in group["cards"]:
            if role in entry["hidden_for"]:
                continue
            url = None if entry["coming_soon"] else role_href(user, entry)
            roles = [] if entry["coming_soon"] else allowed_roles(entry)
            cards.append({
                **entry,
                "available": url is not None,
                "url": url or entry["href"],
                "allowed_roles": roles,
                "roles_label": ", ".join(ROLE_LABELS[r] for r in roles),
                "icon_color": ICONS[entry["icon"]][0],
                "icon_svg": ICONS[entry["icon"]][1],
            })
        result.append({"key": group["key"], "title": group["title"], "cards": cards})
    return result


def all_cards(groups=None):
    for group in NAV_GROUPS if groups is None else groups:
        yield from group["cards"]

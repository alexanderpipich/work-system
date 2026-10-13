from sqlalchemy import Column, Integer, String, Float, Date, Boolean, UniqueConstraint, ForeignKey, DateTime, Text, event
from sqlalchemy.orm import relationship
from database import Base
from time_helpers import now_utc


class Shift(Base):
    __tablename__ = "shifts"

    id = Column(Integer, primary_key=True, index=True)
    store = Column(String, nullable=False)
    format = Column(String, nullable=False)
    city = Column(String, nullable=True)
    shift_date = Column(Date, nullable=False)
    service = Column(String, nullable=False)
    employee = Column(String, nullable=False)
    hours = Column(Float, nullable=False)
    request_type = Column(
        String,
        nullable=False,
        default="Основные заказы",
        server_default="Основные заказы",
    )

    __table_args__ = (
        UniqueConstraint(
            "store",
            "format",
            "shift_date",
            "service",
            "employee",
            "request_type",
            name="uq_shift_row",
        ),
    )


class TimebookEmployee(Base):
    """Стейджинг контактов из timebook (ФИО→телефон/ИНН/табельный).

    Смены (Shift) не хранят телефон/ИНН — эти поля тянутся из timebook и оседают
    здесь, чтобы экран «несозданные» мог предзаполнить данные при создании User.
    Ключ — нормализованное ФИО; при каждой загрузке непустые значения обновляются.
    """
    __tablename__ = "timebook_employees"

    id = Column(Integer, primary_key=True, index=True)
    employee_name = Column(String, unique=True, nullable=False, index=True)
    phone = Column(String, nullable=True)
    inn = Column(String, nullable=True)
    tab_number = Column(String, nullable=True)
    updated_at = Column(DateTime, default=now_utc)


# Фиксированный справочник должностей (4.54). Пустое значение допустимо.
JOB_TITLES = ["ОПРР", "РТЗ", "ПЕКАРНЯ", "ГАСТРОНОМ", "ПУ"]


class User(Base):
    __tablename__ = "users"

    __table_args__ = (
        UniqueConstraint("employee_name_norm", name="uq_users_employee_name_norm"),
    )

    id = Column(Integer, primary_key=True, index=True)
    # Сотрудник без кабинета: phone и password_hash оба NULL, войти нельзя.
    # Выдача пароля заполняет оба поля. Несколько NULL в unique-колонке допустимы.
    phone = Column(String(50), unique=True, nullable=True)
    password_hash = Column(String, nullable=True)
    employee_name = Column(String(255), nullable=False)
    # Ключ уникальности ФИО (utils.normalize_person_name). Заполняется ТОЛЬКО
    # событием ORM ниже — вручную не присваивать. Bulk-update/сырой SQL событие
    # обходят: при правке employee_name так — пересчитать и это поле.
    employee_name_norm = Column(String(255), nullable=False)

    is_admin = Column(Boolean, default=False)

    role = Column(String(50), default="employee")
    brigadier_store = Column(String, nullable=True)

    economist_stores = Column(Text, nullable=True)

    citizenship_country = Column(String, nullable=True)
    citizenship_country_id = Column(Integer, ForeignKey("countries.id"), nullable=True)
    is_student = Column(Boolean, default=False)
    legal_entity = Column(String, nullable=True)
    inn = Column(String, nullable=True)  # ИНН сотрудника (Блок 2 нормализации, canonical). НЕ путать с LegalEntity.inn.
    qr_image_path = Column(String, nullable=True)  # Загруженная QR-картинка-пропуск сотрудника (не генерируется).
    job_title = Column(String, nullable=True)  # Должность (JOB_TITLES). Бизнес-поле, НЕ путать с системной role.
    # Временный пароль (задан админом/при массовом создании) — сотруднику предлагается сменить.
    # Снимается в False, когда сотрудник сменил пароль сам.
    password_is_temporary = Column(Boolean, default=False)
    birth_date = Column(Date, nullable=True)
    # П4: m | f | NULL — для «гражданин/гражданка» и «получил/получила»; если пусто,
    # генератор угадывает по отчеству и предлагает сохранить.
    gender = Column(String(1), nullable=True)
    # П4: почта для уведомлений (сроки документов); у большинства сотрудников пусто.
    email = Column(String, nullable=True)
    # Закреплённый ТМ (User с ролью tm); может быть пустым.
    tm_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    # Загруженные QR-пропуска (до 3, с подписью специальности). qr_image_path выше — legacy,
    # deprecated после переноса в employee_qr (см. scripts/migrate_qr_codes.py).
    qr_codes = relationship(
        "EmployeeQr",
        back_populates="user",
        order_by="EmployeeQr.sort_order",
        cascade="all, delete-orphan",
    )


@event.listens_for(User, "before_insert")
@event.listens_for(User, "before_update")
def _fill_employee_name_norm(mapper, connection, target):
    from utils import normalize_person_name  # utils импортирует models — только лениво
    target.employee_name_norm = normalize_person_name(target.employee_name)


class EmployeeQr(Base):
    __tablename__ = "employee_qr"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    image_path = Column(String, nullable=False)
    label = Column(String, nullable=True)  # подпись специальности (свободный текст)
    sort_order = Column(Integer, default=0)  # порядок в карусели кабинета
    created_at = Column(DateTime, default=now_utc)

    user = relationship("User", back_populates="qr_codes")


class LegalEntity(Base):
    __tablename__ = "legal_entities"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    short_name = Column(String, nullable=True)
    inn = Column(String, nullable=True)
    comment = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, nullable=True)
    # П4: реквизиты для договора и ходатайства (зелёные/голубые подстановки шаблонов).
    full_name = Column(String, nullable=True)  # «Общество с ограниченной ответственностью «…»»
    ogrn = Column(String, nullable=True)
    kpp = Column(String, nullable=True)
    legal_address = Column(Text, nullable=True)
    actual_address = Column(Text, nullable=True)  # шапка ходатайства
    work_address = Column(Text, nullable=True)  # п. 1.3 договора — место работы
    bank_name = Column(String, nullable=True)
    bank_account = Column(String, nullable=True)
    bik = Column(String, nullable=True)
    corr_account = Column(String, nullable=True)
    director_name = Column(String, nullable=True)  # им. падеж: Хацкевич Виталий Сергеевич
    director_name_genitive = Column(String, nullable=True)  # род. падеж: Хацкевича Виталия Сергеевича
    director_short = Column(String, nullable=True)  # В.С. Хацкевич
    director_title = Column(String, nullable=True, default="генерального директора")


class Service(Base):
    """Справочник услуг (переделка услуг, этап 1).

    Плоский текст `Nур_услуга` в Rate/Shift — источник дублей и опечаток. Service
    выносит услугу в самостоятельную сущность (канон + алиасы, как Country).
    Уровень (1..5) хранится отдельным полем на Rate, не склеен в имя.
    """
    __tablename__ = "services"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, unique=True)  # каноничное имя услуги
    aliases = Column(String, nullable=True)  # CSV вариантов написания (как Country.aliases)
    is_active = Column(Boolean, default=True)
    # Не оплачивается из timebook (комплектация считается по другому отчёту): смены
    # с этой услугой не входят в аванс и табель и не блокируют фиксацию «нет ЧТС».
    excluded_from_payroll = Column(Boolean, default=False, server_default="false", nullable=False)
    created_at = Column(DateTime, nullable=True, default=now_utc)


class Rate(Base):
    __tablename__ = "rates"

    id = Column(Integer, primary_key=True, index=True)
    service = Column(String, nullable=False)  # deprecated (этап 1): оставлен для отката/сверки
    service_id = Column(Integer, ForeignKey("services.id"), nullable=True)
    level = Column(Integer, nullable=True)  # уровень услуги 1..5; NULL — услуга без уровня (легитимно)
    format = Column(String, nullable=True)
    city = Column(String, nullable=True, index=True)
    store = Column(String, nullable=True)
    employee_name = Column(String, nullable=True)
    hourly_rate = Column(Float, nullable=False)
    active_from = Column(Date, nullable=True)
    active_to = Column(Date, nullable=True)
    comment = Column(String, nullable=True)


class Requisite(Base):
    __tablename__ = "requisites"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    employee_name = Column(String, index=True)

    inn = Column(String)
    account_number = Column(String)
    bik = Column(String)
    bank_name = Column(String)
    # Гражданство развязано (нормализация атрибутов, Блок 1): источник истины —
    # User.citizenship_country_id. Колонка requisites.citizenship удалена миграцией
    # scripts/migrate_drop_requisite_citizenship.py.

    is_third_party = Column(Boolean, default=False)
    recipient_name = Column(String, nullable=True)

    # Выплата на карту (П1-Г). Номер карты — сплошные цифры; телефон — 11 цифр с 7;
    # срок — MM/YY. Способ: card | card_phone | cash (utils.PAYOUT_METHODS).
    # ИНН/счёт/БИК выше — запасной путь: годен хотя бы один способ.
    card_number = Column(String, nullable=True)
    card_phone = Column(String, nullable=True)
    card_expiry = Column(String(5), nullable=True)
    payout_method = Column(String, nullable=False, default="card_phone", server_default="card_phone")

    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)

    created_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True)
    verified_at = Column(DateTime, nullable=True)

    comment = Column(Text, nullable=True)


class PayrollRun(Base):
    __tablename__ = "payroll_runs"

    id = Column(Integer, primary_key=True, index=True)

    date_from = Column(Date, nullable=False)
    date_to = Column(Date, nullable=False)
    legal_entity = Column(String, nullable=True)

    status = Column(String, default="draft")
    # П3: advance — еженедельный аванс (Пн–Вс, только отмеченные сотрудники);
    # period — выплатной табель за полмесяца (1–15 / 16–конец). Старые прогоны — period.
    kind = Column(String, nullable=False, default="period", server_default="period")

    created_by = Column(Integer, nullable=True)
    fixed_by = Column(Integer, nullable=True)
    sent_by = Column(Integer, nullable=True)
    closed_by = Column(Integer, nullable=True)

    created_at = Column(DateTime, nullable=True)
    fixed_at = Column(DateTime, nullable=True)
    sent_at = Column(DateTime, nullable=True)
    closed_at = Column(DateTime, nullable=True)

    comment = Column(Text, nullable=True)


class PayrollRunItem(Base):
    __tablename__ = "payroll_run_items"

    id = Column(Integer, primary_key=True, index=True)

    run_id = Column(Integer, nullable=False)

    employee_name = Column(String, nullable=False)
    store = Column(String, nullable=True)
    service = Column(String, nullable=True)
    shift_date = Column(Date, nullable=True)

    hours = Column(Float, default=0)
    rate = Column(Float, default=0)
    amount = Column(Float, default=0)
    other_amount = Column(Float, default=0)
    auto_adjustments_amount = Column(Float, default=0)
    manual_adjustments_amount = Column(Float, default=0)
    lmk_amount = Column(Float, default=0)
    # П3: смена уже оплачена другим зафиксированным прогоном (обычно авансом) —
    # его id и сколько по ней выплачено (amount + manual_adjustments_amount двойника).
    # total_amount = amount + bonus_amount + other_amount + auto_adjustments_amount − lmk_amount − advanced_amount.
    paid_by_run_id = Column(Integer, nullable=True)
    advanced_amount = Column(Float, default=0, server_default="0")
    # П4.4: надбавка к часу («Акция») — часы × Σ надбавок HourlyBonus на дату смены.
    bonus_amount = Column(Float, default=0, server_default="0")
    total_amount = Column(Float, default=0)

    comment = Column(Text, nullable=True)


class HourlyBonus(Base):
    """Надбавка к часу (П4.4): «Акция» 5 ₽/ч сверх ЧТС Ленты. Действует на смены
    с ненулевой ставкой с active_from по active_to (пусто — бессрочно); несколько
    действующих суммируются. Закрытие датой не пересчитывает старые прогоны."""
    __tablename__ = "hourly_bonuses"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    amount_per_hour = Column(Float, nullable=False)
    active_from = Column(Date, nullable=False)
    active_to = Column(Date, nullable=True)
    is_active = Column(Boolean, default=True)
    comment = Column(Text, nullable=True)
    created_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=now_utc)


class AdvanceSelection(Base):
    """Отметка «платить аванс» на неделю (П3). Живёт отдельно от прогона: ТМ
    отмечает своих до того, как экономист зафиксирует аванс."""
    __tablename__ = "advance_selections"
    __table_args__ = (
        UniqueConstraint("week_start", "employee_name", name="uq_advance_selection_week_employee"),
    )

    id = Column(Integer, primary_key=True, index=True)
    week_start = Column(Date, nullable=False, index=True)  # понедельник
    employee_name = Column(String, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    selected_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=now_utc)
    # П4.6: частичный аванс — NULL = весь ФОТ недели; сумма действует на одну неделю
    # (carry-over копирует отметку без суммы).
    amount = Column(Float, nullable=True)
    comment = Column(Text, nullable=True)


class WeeklyReview(Base):
    """Неделя еженедельного отчёта закрыта для коррекций ТМ (П4.6). Нет строки — открыта."""
    __tablename__ = "weekly_reviews"

    id = Column(Integer, primary_key=True, index=True)
    week_start = Column(Date, nullable=False, unique=True)
    closed_by = Column(Integer, nullable=True)
    closed_at = Column(DateTime, nullable=True)


class WeeklyTmCheck(Base):
    """Отметки ТМ за неделю (П4.6): «ЧТС проверено» и «Зафиксировать авансы» (подал своих)."""
    __tablename__ = "weekly_tm_checks"
    __table_args__ = (UniqueConstraint("week_start", "tm_id", name="uq_weekly_tm_check_week_tm"),)

    id = Column(Integer, primary_key=True, index=True)
    week_start = Column(Date, nullable=False, index=True)
    tm_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    checked_at = Column(DateTime, nullable=True)
    advances_submitted_at = Column(DateTime, nullable=True)


class TmChangeRequest(Base):
    """Запрос ТМ «это мой сотрудник» на сотрудника другого ТМ (П4.6): решает экономист/HR-руководитель."""
    __tablename__ = "tm_change_requests"

    id = Column(Integer, primary_key=True, index=True)
    employee_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    from_tm_id = Column(Integer, nullable=True)
    to_tm_id = Column(Integer, nullable=False)
    requested_by = Column(Integer, nullable=True)
    week_start = Column(Date, nullable=True)
    status = Column(String, nullable=False, default="pending")  # pending / accepted / rejected
    decided_by = Column(Integer, nullable=True)
    decided_at = Column(DateTime, nullable=True)
    comment = Column(Text, nullable=True)
    created_at = Column(DateTime, default=now_utc)


class MedicalBookCharge(Base):
    __tablename__ = "medical_book_charges"

    id = Column(Integer, primary_key=True, index=True)

    employee_name = Column(String, nullable=False)
    exam_date = Column(Date, nullable=False)

    total_amount = Column(Float, default=0)
    months_count = Column(Integer, default=1)
    monthly_amount = Column(Float, default=0)
    start_month = Column(Date, nullable=False)
    remaining_amount = Column(Float, default=0)

    status = Column(String, default="active")
    comment = Column(Text, nullable=True)

    created_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, nullable=True)

    cancelled_by = Column(Integer, nullable=True)
    cancelled_at = Column(DateTime, nullable=True)


class MedicalBookPayment(Base):
    __tablename__ = "medical_book_payments"

    id = Column(Integer, primary_key=True, index=True)
    charge_id = Column(Integer, nullable=True)
    run_id = Column(Integer, nullable=True)
    employee_name = Column(String, nullable=True)
    amount = Column(Float, default=0)
    created_at = Column(DateTime, default=now_utc)



class PayrollAdjustment(Base):
    __tablename__ = "payroll_adjustments"

    id = Column(Integer, primary_key=True, index=True)

    employee_name = Column(String, nullable=False)
    store = Column(String, nullable=True)
    service = Column(String, nullable=True)
    shift_date = Column(Date, nullable=True)

    old_hours = Column(Float, default=0)
    new_hours = Column(Float, default=0)
    diff_hours = Column(Float, default=0)

    rate = Column(Float, default=0)
    diff_amount = Column(Float, default=0)

    source_run_id = Column(Integer, nullable=True)
    target_run_id = Column(Integer, nullable=True)

    status = Column(String, default="pending")

    comment = Column(Text, nullable=True)

    created_at = Column(DateTime, nullable=True)
    approved_at = Column(DateTime, nullable=True)
    approved_by = Column(Integer, nullable=True)
    rejected_at = Column(DateTime, nullable=True)
    rejected_by = Column(Integer, nullable=True)


class ManualPayrollAdjustment(Base):
    __tablename__ = "manual_payroll_adjustments"

    id = Column(Integer, primary_key=True, index=True)

    employee_name = Column(String, nullable=False)
    store = Column(String, nullable=False)
    date_from = Column(Date, nullable=False)
    date_to = Column(Date, nullable=False)

    amount = Column(Float, default=0)
    comment = Column(Text, nullable=True)
    status = Column(String, default="active")

    created_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, nullable=True)

    deleted_by = Column(Integer, nullable=True)
    deleted_at = Column(DateTime, nullable=True)

    applied_run_id = Column(Integer, nullable=True)


class DocumentType(Base):
    __tablename__ = "document_types"

    id = Column(Integer, primary_key=True, index=True)

    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    help_text = Column(Text, nullable=True)
    sample_image_path = Column(String, nullable=True)
    citizenship_filter = Column(String, nullable=True)

    requires_number = Column(Boolean, default=True)
    requires_issue_date = Column(Boolean, default=True)
    requires_expiry_date = Column(Boolean, default=True)
    allow_permanent = Column(Boolean, default=True)

    extra_field_1_label = Column(String, nullable=True)
    extra_field_2_label = Column(String, nullable=True)

    is_required = Column(Boolean, default=True)
    is_active = Column(Boolean, default=True)
    sort_order = Column(Integer, default=0)
    is_student_doc = Column(Boolean, default=False)
    # П4: уровни напоминаний до окончания срока, «30,14,7,0»; NULL — из настроек
    # (env DOCUMENT_ALERT_DAYS). Первый уровень — порог статуса «скоро истекает».
    alert_days = Column(String, nullable=True)

    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, nullable=True)


class DocumentTypeSample(Base):
    __tablename__ = "document_type_samples"

    id = Column(Integer, primary_key=True, index=True)
    document_type_id = Column(Integer, nullable=False, index=True)
    file_path = Column(String, nullable=False)
    original_filename = Column(String, nullable=True)
    sort_order = Column(Integer, default=0)
    uploaded_at = Column(DateTime, default=now_utc)


class EmployeeDocument(Base):
    __tablename__ = "employee_documents"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, nullable=True)
    employee_name = Column(String, nullable=False)
    document_type_id = Column(Integer, nullable=False)

    document_number = Column(String, nullable=True)
    issue_date = Column(Date, nullable=True)
    expiry_date = Column(Date, nullable=True)
    is_permanent = Column(Boolean, default=False)

    extra_field_1_value = Column(String, nullable=True)
    extra_field_2_value = Column(String, nullable=True)

    file_path = Column(String, nullable=True)
    original_filename = Column(String, nullable=True)

    status = Column(String, default="uploaded")
    comment = Column(Text, nullable=True)

    uploaded_by = Column(Integer, nullable=True)
    verified_by = Column(Integer, nullable=True)

    uploaded_at = Column(DateTime, default=now_utc)
    verified_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True)


class UploadLog(Base):
    __tablename__ = "upload_logs"

    id = Column(Integer, primary_key=True, index=True)

    filename = Column(String, nullable=True)
    uploaded_by = Column(Integer, nullable=True)

    added = Column(Integer, default=0)
    updated = Column(Integer, default=0)
    skipped_duplicates = Column(Integer, default=0)
    skipped_locked_months = Column(Integer, default=0)
    adjustments_created = Column(Integer, default=0)

    status = Column(String, default="success")
    error = Column(Text, nullable=True)

    created_at = Column(DateTime, default=now_utc)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, nullable=True)
    user_role = Column(String, nullable=True)

    action = Column(String, nullable=False)

    entity_type = Column(String, nullable=False)
    entity_id = Column(String, nullable=True)
    entity_name = Column(String, nullable=True)

    old_value = Column(Text, nullable=True)
    new_value = Column(Text, nullable=True)

    comment = Column(Text, nullable=True)

    ip_address = Column(String, nullable=True)
    user_agent = Column(Text, nullable=True)

    created_at = Column(DateTime, default=now_utc)

class EmployeeStoreAssignment(Base):
    __tablename__ = "employee_store_assignments"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)
    employee_name = Column(String, nullable=False)
    store = Column(String, nullable=False)
    city = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    created_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=now_utc)
    comment = Column(Text, nullable=True)


class PlanningScenario(Base):
    __tablename__ = "planning_scenarios"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    template_type = Column(String, default="standard")
    email_subject_template = Column(String, nullable=True)
    email_body_template = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, nullable=True)


class PlanningForm(Base):
    __tablename__ = "planning_forms"

    id = Column(Integer, primary_key=True, index=True)
    scenario_id = Column(Integer, nullable=True)
    employee_name = Column(String, nullable=False)
    user_id = Column(Integer, nullable=True)
    store = Column(String, nullable=False)
    city = Column(String, nullable=True)
    date_from = Column(Date, nullable=True)
    date_to = Column(Date, nullable=True)
    file_path = Column(String, nullable=True)
    file_name = Column(String, nullable=True)
    status = Column(String, default="created")
    created_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=now_utc)
    sent_by = Column(Integer, nullable=True)
    sent_at = Column(DateTime, nullable=True)
    email_to = Column(String, nullable=True)
    email_subject = Column(String, nullable=True)
    comment = Column(Text, nullable=True)


class EmployeeMonitoringSettings(Base):
    __tablename__ = "employee_monitoring_settings"

    id = Column(Integer, primary_key=True, index=True)
    inactive_days = Column(Integer, default=14)
    minimum_shifts = Column(Integer, default=3)
    analysis_days = Column(Integer, default=14)
    updated_by = Column(Integer, nullable=True)
    updated_at = Column(DateTime, nullable=True)


class EmployeeMonitoringRecommendation(Base):
    __tablename__ = "employee_monitoring_recommendations"

    id = Column(Integer, primary_key=True, index=True)
    employee_name = Column(String, nullable=False)
    store = Column(String, nullable=False)
    city = Column(String, nullable=True)
    recommendation_type = Column(String, nullable=False)
    remove_from_planning = Column(Boolean, default=False)
    add_to_planning = Column(Boolean, default=False)
    recommendation_text = Column(Text, nullable=True)
    status = Column(String, default="new")
    created_at = Column(DateTime, default=now_utc)
    processed_at = Column(DateTime, nullable=True)
    processed_by = Column(Integer, nullable=True)


class EmployeeDismissalDecision(Base):
    """Кадровое решение по пропавшему со смен сотруднику (мониторинг увольнений).

    Один сотрудник — одно текущее решение (dismiss «к увольнению» / keep «оставить»).
    Список кандидатов вычисляется на лету (последняя смена старше порога); здесь —
    только зафиксированное человеком решение.
    """
    __tablename__ = "employee_dismissal_decisions"

    id = Column(Integer, primary_key=True, index=True)
    employee_name = Column(String, nullable=False, unique=True)
    decision = Column(String, nullable=False)  # dismiss | keep
    comment = Column(Text, nullable=True)
    decided_by = Column(Integer, nullable=True)
    decided_at = Column(DateTime, nullable=True)


class ReferralPromo(Base):
    """Акция «Приведи друга» (АПД). Привязана к приведённому сотруднику (по ФИО,
    уникально за всю историю). Выгодоприобретатель — пользователь, который привёл.
    Строится по образцу MedicalBookCharge (статусы + привязка к табелю)."""
    __tablename__ = "referral_promos"

    id = Column(Integer, primary_key=True, index=True)
    referred_employee_name = Column(String, nullable=False, unique=True)  # приведённый — один раз в истории
    beneficiary_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    beneficiary_name = Column(String, nullable=True)  # снимок ФИО выгодоприобретателя
    status = Column(String, default="active")  # active | threshold_reached | paid | cancelled
    threshold_reached_at = Column(Date, nullable=True)  # дата набора порога (фиксируется хуком)
    created_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=now_utc)
    cancelled_by = Column(Integer, nullable=True)
    cancelled_at = Column(DateTime, nullable=True)
    comment = Column(Text, nullable=True)


class ReferralSettings(Base):
    """Глобальные настройки АПД (синглтон — одна строка)."""
    __tablename__ = "referral_settings"

    id = Column(Integer, primary_key=True, index=True)
    hours_threshold = Column(Float, default=150)
    bonus_amount = Column(Float, default=5000)
    updated_by = Column(Integer, nullable=True)
    updated_at = Column(DateTime, nullable=True)


class ReferralPayout(Base):
    """Премия АПД в табель — pending-корректировка, требует подтверждения человека.
    pending блокирует формирование/фиксацию табеля."""
    __tablename__ = "referral_payouts"

    id = Column(Integer, primary_key=True, index=True)
    promo_id = Column(Integer, ForeignKey("referral_promos.id"), nullable=False)
    beneficiary_user_id = Column(Integer, nullable=True)
    beneficiary_name = Column(String, nullable=True)
    amount = Column(Float, default=0)  # = bonus_amount на момент достижения порога
    status = Column(String, default="pending")  # pending | confirmed | cancelled
    run_id = Column(Integer, nullable=True)  # в какой табель попала
    created_at = Column(DateTime, default=now_utc)
    confirmed_by = Column(Integer, nullable=True)
    confirmed_at = Column(DateTime, nullable=True)
    cancelled_by = Column(Integer, nullable=True)
    cancelled_at = Column(DateTime, nullable=True)


class StoreReconciliationSettings(Base):
    __tablename__ = "store_reconciliation_settings"

    id = Column(Integer, primary_key=True, index=True)
    store = Column(String, nullable=False, unique=True)
    city = Column(String, nullable=True)
    email = Column(String, nullable=True)
    enabled = Column(Boolean, default=True)
    comment = Column(Text, nullable=True)


class StoreReconciliation(Base):
    __tablename__ = "store_reconciliations"

    id = Column(Integer, primary_key=True, index=True)
    store = Column(String, nullable=False)
    city = Column(String, nullable=True)
    period_from = Column(Date, nullable=False)
    period_to = Column(Date, nullable=False)
    status = Column(String, default="generated")
    file_path = Column(String, nullable=True)
    created_at = Column(DateTime, default=now_utc)
    sent_at = Column(DateTime, nullable=True)


class StoreNotificationSettings(Base):
    __tablename__ = "store_notification_settings"

    id = Column(Integer, primary_key=True, index=True)
    store = Column(String, nullable=False, unique=True)
    city = Column(String, nullable=True)
    email = Column(String, nullable=True)
    enabled = Column(Boolean, default=True)
    comment = Column(Text, nullable=True)


STORE_CONTACT_ROLES = {
    "security": "Охрана",
    "hr_dept": "Отдел персонала",
    "director": "Директор",
    "other": "Прочее",
}


class Store(Base):
    __tablename__ = "stores"

    id = Column(Integer, primary_key=True, index=True)
    tk_number = Column(Integer, unique=True, nullable=False)
    display_name = Column(String, nullable=True)
    city = Column(String, nullable=True)
    # П4.4: тарифный регион — по нему подбирается ЧТС (Rate.city). У подмосковных
    # ТК «Московская область», хотя «Город» timebook даёт «Москва». Пусто → город смены.
    rate_region = Column(String, nullable=True)
    format = Column(String, nullable=True)
    object_address = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, nullable=True)
    comment = Column(Text, nullable=True)


class StoreContact(Base):
    __tablename__ = "store_contacts"

    id = Column(Integer, primary_key=True, index=True)
    store_id = Column(Integer, ForeignKey("stores.id"), nullable=False, index=True)
    email = Column(String, nullable=False)
    role = Column(String, nullable=False)
    name = Column(String, nullable=True)
    for_planning = Column(Boolean, default=False)
    for_reconciliation = Column(Boolean, default=False)
    for_unplanned = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)


class CitizenshipRegime(Base):
    __tablename__ = "citizenship_regimes"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(50), unique=True, nullable=False)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    sort_order = Column(Integer, default=0)


class Country(Base):
    __tablename__ = "countries"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    regime_id = Column(Integer, ForeignKey("citizenship_regimes.id"), nullable=False)
    is_active = Column(Boolean, default=True)
    aliases = Column(String, nullable=True)  # CSV сокращений для матчинга («РФ»→«Россия»)
    # П4: «гражданин(ка) Республики Узбекистан» в договоре.
    name_genitive = Column(String, nullable=True)


class DocumentExpiryAlert(Base):
    """Напоминание о сроке документа (П4): документ × уровень × адресат — один раз."""
    __tablename__ = "document_expiry_alerts"
    __table_args__ = (
        UniqueConstraint("document_id", "level", "recipient_user_id", name="uq_document_expiry_alert"),
    )

    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey("employee_documents.id"), nullable=False, index=True)
    level = Column(Integer, nullable=False)  # дней до окончания: 30 / 14 / 7 / 0
    recipient_user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    email_status = Column(String, nullable=True)  # sent | disabled | failed | NULL (нет почты)
    created_at = Column(DateTime, default=now_utc)
    read_at = Column(DateTime, nullable=True)


class Region(Base):
    """Регион работы (П4): адресат ходатайства в УВМ и орган выдачи патента.

    Регион сотрудника подбирается по городу его последних смен (cities — CSV
    городов из выгрузки смен), в форме документа его можно выбрать вручную.
    """
    __tablename__ = "regions"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, unique=True)
    cities = Column(Text, nullable=True)
    uvm_addressee = Column(Text, nullable=True)  # дат. падеж: «Начальнику УВМ ГУ МВД России по …»
    uvm_rank = Column(String, nullable=True)  # «Полковнику полиции»
    uvm_person = Column(String, nullable=True)  # ФИО в дат. падеже
    patent_authority = Column(Text, nullable=True)  # «ГУ МВД России по г. Санкт-Петербургу и …»
    patent_territory = Column(String, nullable=True)  # «г. Санкт-Петербург»
    is_active = Column(Boolean, default=True)


class RegimeDocumentRule(Base):
    __tablename__ = "regime_document_rules"

    id = Column(Integer, primary_key=True, index=True)
    regime_id = Column(Integer, ForeignKey("citizenship_regimes.id"), nullable=False)
    document_type_id = Column(Integer, ForeignKey("document_types.id"), nullable=False)
    is_required = Column(Boolean, default=True)

    __table_args__ = (
        UniqueConstraint("regime_id", "document_type_id", name="uq_regime_doc_rule"),
    )


class UserAccessScope(Base):
    __tablename__ = "user_access_scopes"
    __table_args__ = (
        UniqueConstraint("user_id", "scope_type", "scope_value", name="uq_user_access_scope"),
    )

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    scope_type = Column(String(20), nullable=False)
    scope_value = Column(String, nullable=False)
    created_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=now_utc)
    is_active = Column(Boolean, default=True)


class EmailLog(Base):
    __tablename__ = "email_logs"

    id = Column(Integer, primary_key=True, index=True)
    to_addresses = Column(Text, nullable=False)
    subject = Column(String, nullable=True)
    status = Column(String, nullable=False)
    error = Column(Text, nullable=True)
    scenario = Column(String, nullable=True)
    created_at = Column(DateTime, default=now_utc)
    created_by = Column(Integer, nullable=True)


class UnplannedNotification(Base):
    __tablename__ = "unplanned_notifications"

    id = Column(Integer, primary_key=True, index=True)
    shift_id = Column(Integer, ForeignKey("shifts.id"), nullable=False, index=True)
    email_log_id = Column(Integer, ForeignKey("email_logs.id"), nullable=True)
    status = Column(String, nullable=False)
    sent_at = Column(DateTime, default=now_utc)


class BPNotification(Base):
    __tablename__ = "bp_notifications"

    id = Column(Integer, primary_key=True, index=True)
    store_tk = Column(Integer, nullable=False, index=True)
    period_from = Column(Date, nullable=False)
    period_to = Column(Date, nullable=False)
    email_log_id = Column(Integer, ForeignKey("email_logs.id"), nullable=True)
    to_addresses = Column(Text, nullable=True)
    status = Column(String, nullable=False)
    sent_at = Column(DateTime, default=now_utc)

    __table_args__ = (
        UniqueConstraint("store_tk", "period_from", "period_to", name="uq_bp_notification"),
    )


class ReconciliationNotification(Base):
    """Идемпотентность рассылки сверок (калька BPNotification).

    Ключ включает recon_type (A/B): сверки 01-15 и 01-31 одного месяца — разные
    отправки и не должны блокировать друг друга. Запись создаётся ТОЛЬКО при
    успешной отправке.
    """
    __tablename__ = "reconciliation_notifications"

    id = Column(Integer, primary_key=True, index=True)
    store_tk = Column(Integer, nullable=False, index=True)
    period_from = Column(Date, nullable=False)
    period_to = Column(Date, nullable=False)
    recon_type = Column(String, nullable=False)  # "A" (01-15) | "B" (01-31)
    email_log_id = Column(Integer, ForeignKey("email_logs.id"), nullable=True)
    to_addresses = Column(Text, nullable=True)
    status = Column(String, nullable=False)
    sent_at = Column(DateTime, default=now_utc)

    __table_args__ = (
        UniqueConstraint(
            "store_tk", "period_from", "period_to", "recon_type",
            name="uq_reconciliation_notification",
        ),
    )

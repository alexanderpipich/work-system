from sqlalchemy import Column, Integer, String, Float, Date, Boolean, UniqueConstraint, ForeignKey, DateTime, Text
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


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    phone = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    employee_name = Column(String(255), nullable=False)

    is_admin = Column(Boolean, default=False)

    role = Column(String(50), default="employee")
    brigadier_store = Column(String, nullable=True)

    economist_stores = Column(Text, nullable=True)

    citizenship_country = Column(String, nullable=True)
    citizenship_country_id = Column(Integer, ForeignKey("countries.id"), nullable=True)
    is_student = Column(Boolean, default=False)
    legal_entity = Column(String, nullable=True)


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


class Rate(Base):
    __tablename__ = "rates"

    id = Column(Integer, primary_key=True, index=True)
    service = Column(String, nullable=False)
    format = Column(String, nullable=True)
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
    citizenship = Column(String)

    is_third_party = Column(Boolean, default=False)
    recipient_name = Column(String, nullable=True)

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
    total_amount = Column(Float, default=0)

    comment = Column(Text, nullable=True)


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


class UnplannedShiftNotification(Base):
    __tablename__ = "unplanned_shift_notifications"

    id = Column(Integer, primary_key=True, index=True)
    shift_id = Column(Integer, nullable=True, unique=True)
    store = Column(String, nullable=False)
    city = Column(String, nullable=True)
    shift_date = Column(Date, nullable=False)
    employee_name = Column(String, nullable=False)
    service = Column(String, nullable=True)
    hours = Column(Float, default=0)
    status = Column(String, default="generated")
    created_at = Column(DateTime, default=now_utc)
    sent_at = Column(DateTime, nullable=True)

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

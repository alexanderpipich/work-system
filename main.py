import logging
import os
import sys

from env_loader import load_project_env

load_project_env()

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from audit_helpers import ensure_audit_log_table
from citizenship_schema import ensure_citizenship_columns
from database import Base, SessionLocal, engine
from dependencies import RedirectException, redirect_exception_response
from menu_context import install_menu_globals
from tours import install_tour_globals
from document_helpers import ensure_document_tables
from legal_entity_helpers import ensure_legal_entities_table
from payroll_run_helpers import ensure_payroll_run_closing_columns
from requisite_schema import ensure_requisite_profile_columns
from service_schema import ensure_service_columns
from shift_schema import ensure_shift_request_type_unique_key
from user_schema import ensure_user_profile_columns
from routers.citizenship import router as citizenship_router
from routers.adjustments import router as adjustments_router
from routers.analytics import router as analytics_router
from routers.audit_logs import router as audit_logs_router
from routers.auth import router as auth_router
from routers.dashboards import router as dashboards_router
from routers.documents import router as documents_router
from routers.employee import router as employee_router
from routers.employees import router as employees_router
from routers.legal_entities import router as legal_entities_router
from routers.hr import router as hr_router
from routers.lmk import router as lmk_router
from routers.maintenance import router as maintenance_router
from routers.payroll import router as payroll_router
from routers.payroll_runs import router as payroll_runs_router
from routers.payouts import router as payouts_router
from routers.weekly import router as weekly_router
from routers.regions import router as regions_router
from routers.contracts import router as contracts_router
from routers.document_alerts import router as document_alerts_router
from routers.rates import router as rates_router
from routers.referral import router as referral_router
from routers.requisites import router as requisites_router
from routers.email_test import router as email_test_router
from routers.email_unplanned import router as email_unplanned_router
from routers.email_planning_bp import router as email_planning_bp_router
from routers.email_reconciliation import router as email_reconciliation_router
from routers.planning_bp import router as planning_bp_router
from routers.qr import router as qr_router
from routers.stores import router as stores_router
from routers.tour import router as tour_router
from routers.reports import router as reports_router
from routers.schedules import router as schedules_router
from routers.services import router as services_router
from routers.system import router as system_router
from routers.upload import router as upload_router
from routers.users import router as users_router


SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is not set")


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


# П4: счётчик непрочитанных напоминаний о сроках документов в шапке (кадровик, ТМ).
# Регистрируется ДО SessionMiddleware: middleware, добавленный позже, оборачивает
# ранние — так сессия к этому моменту уже разобрана.
@app.middleware("http")
async def document_expiry_counter(request: Request, call_next):
    request.state.expiry_alerts = 0
    user_id = request.session.get("user_id") if "session" in request.scope else None
    if user_id and request.method == "GET":
        from document_alerts import unread_count
        from models import User
        from rbac import ROLE_HR_CLERK, ROLE_TM, canonical_role

        db = SessionLocal()
        try:
            user = db.get(User, user_id)
            if user and canonical_role(user) in {ROLE_HR_CLERK, ROLE_TM}:
                request.state.expiry_alerts = unread_count(db, user.id)
        except Exception:  # счётчик не должен ронять страницу
            logging.getLogger(__name__).exception("document expiry counter failed")
        finally:
            db.close()
    return await call_next(request)


app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.exception_handler(RedirectException)
async def redirect_exception_handler(request: Request, exc: RedirectException):
    return redirect_exception_response(exc)


app.include_router(citizenship_router)
app.include_router(adjustments_router)
app.include_router(analytics_router)
app.include_router(audit_logs_router)
app.include_router(auth_router)
app.include_router(dashboards_router)
app.include_router(documents_router)
app.include_router(employee_router)
app.include_router(employees_router)
app.include_router(legal_entities_router)
app.include_router(hr_router)
app.include_router(lmk_router)
app.include_router(maintenance_router)
app.include_router(planning_bp_router)
app.include_router(qr_router)
app.include_router(tour_router)
app.include_router(payroll_router)
app.include_router(payroll_runs_router)
app.include_router(payouts_router)
app.include_router(weekly_router)
app.include_router(regions_router)
app.include_router(contracts_router)
app.include_router(document_alerts_router)
app.include_router(rates_router)
app.include_router(referral_router)
app.include_router(requisites_router)
app.include_router(email_test_router)
app.include_router(email_unplanned_router)
app.include_router(email_planning_bp_router)
app.include_router(email_reconciliation_router)
app.include_router(stores_router)
app.include_router(reports_router)
app.include_router(schedules_router)
app.include_router(services_router)
app.include_router(system_router)
app.include_router(upload_router)
app.include_router(users_router)

# П4.10: боковое меню на всех страницах — глобал menu_context в окружении Jinja каждого роутера.
install_menu_globals(module for name, module in list(sys.modules.items()) if name.startswith("routers."))
# П5: демо-туры — глобал tour_context в тех же окружениях (templates/_tour.html).
install_tour_globals(module for name, module in list(sys.modules.items()) if name.startswith("routers."))

Base.metadata.create_all(bind=engine)
# Догоняющие миграции старых баз — Postgres-специфичный SQL (ADD COLUMN IF NOT
# EXISTS, BTRIM, ALTER ... DROP NOT NULL). На свежей базе create_all уже создал
# всё по моделям; на SQLite тестов этот SQL не выполняется.
if engine.dialect.name == "postgresql":
    ensure_shift_request_type_unique_key()
    ensure_user_profile_columns()
    ensure_requisite_profile_columns()
    ensure_document_tables()
    ensure_citizenship_columns()
    ensure_legal_entities_table()
    ensure_payroll_run_closing_columns()
    ensure_audit_log_table()
    ensure_service_columns()
from referral_helpers import ensure_referral_settings
ensure_referral_settings()

# П4: проверка сроков документов раз в сутки при старте (планировщик — П6).
if engine.dialect.name == "postgresql":
    from document_alerts import maybe_run_daily

    _startup_session = SessionLocal()
    try:
        maybe_run_daily(_startup_session)
    except Exception:
        logging.getLogger(__name__).exception("daily document expiry check failed")
    finally:
        _startup_session.close()




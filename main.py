import os

from env_loader import load_project_env

load_project_env()

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from audit_helpers import ensure_audit_log_table
from database import Base, engine
from dependencies import RedirectException, redirect_exception_response
from document_helpers import ensure_document_tables
from legal_entity_helpers import ensure_legal_entities_table
from payroll_run_helpers import ensure_payroll_run_closing_columns
from requisite_schema import ensure_requisite_profile_columns
from shift_schema import ensure_shift_request_type_unique_key
from user_schema import ensure_user_profile_columns
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
from routers.rates import router as rates_router
from routers.requisites import router as requisites_router
from routers.email_test import router as email_test_router
from routers.stores import router as stores_router
from routers.reports import router as reports_router
from routers.schedules import router as schedules_router
from routers.system import router as system_router
from routers.upload import router as upload_router
from routers.users import router as users_router


SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is not set")


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.exception_handler(RedirectException)
async def redirect_exception_handler(request: Request, exc: RedirectException):
    return redirect_exception_response(exc)


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
app.include_router(payroll_router)
app.include_router(payroll_runs_router)
app.include_router(rates_router)
app.include_router(requisites_router)
app.include_router(email_test_router)
app.include_router(stores_router)
app.include_router(reports_router)
app.include_router(schedules_router)
app.include_router(system_router)
app.include_router(upload_router)
app.include_router(users_router)

Base.metadata.create_all(bind=engine)
ensure_shift_request_type_unique_key()
ensure_user_profile_columns()
ensure_requisite_profile_columns()
ensure_document_tables()
ensure_legal_entities_table()
ensure_payroll_run_closing_columns()
ensure_audit_log_table()




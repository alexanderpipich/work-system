"""П1-В: кадровик — документы, гражданства, справочники; выплаты и ставки — нет."""

import os
import unittest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base
from dependencies import RedirectException, current_user, get_db, redirect_exception_response
from models import User
from routers.citizenship import router as citizenship_router
from routers.dashboards import router as dashboards_router
from routers.documents import router as documents_router
from routers.payroll import router as payroll_router
from routers.rates import router as rates_router
from routers.services import router as services_router


def _client(role):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    session.add(User(employee_name="Кадровик Тест", phone="79990000001", password_hash="x", role=role))
    session.commit()
    session.close()

    app = FastAPI()
    for router in (citizenship_router, dashboards_router, documents_router,
                   payroll_router, rates_router, services_router):
        app.include_router(router)

    @app.exception_handler(RedirectException)
    async def _redirect(request: Request, exc: RedirectException):
        return redirect_exception_response(exc)

    def override_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    def override_user():
        db = Session()
        user = db.query(User).first()
        db.close()
        return user

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[current_user] = override_user
    return TestClient(app)


class HrClerkRoutesTests(unittest.TestCase):
    def setUp(self):
        self.client = _client("hr_clerk")

    def _status(self, path):
        return self.client.get(path, follow_redirects=False).status_code

    def test_allowed_pages_open(self):
        for path in ("/hr", "/hr/documents", "/hr/document-types",
                     "/admin/citizenship/countries", "/admin/citizenship/regimes", "/admin/services"):
            self.assertEqual(self._status(path), 200, path)

    def test_payroll_and_rates_closed(self):
        for path in ("/hr/payroll", "/hr/rates", "/economist/payroll"):
            self.assertEqual(self._status(path), 302, path)


class TmRoutesTests(unittest.TestCase):
    def test_tm_opens_hr_cabinet_but_not_citizenship(self):
        client = _client("tm")
        self.assertEqual(client.get("/hr", follow_redirects=False).status_code, 200)
        self.assertEqual(client.get("/admin/citizenship/countries", follow_redirects=False).status_code, 302)

    def test_legacy_hr_manager_still_works(self):
        client = _client("hr_manager")
        self.assertEqual(client.get("/hr", follow_redirects=False).status_code, 200)


if __name__ == "__main__":
    unittest.main()

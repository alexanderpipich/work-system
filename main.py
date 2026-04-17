import os
from datetime import datetime
from fastapi import FastAPI, UploadFile, File, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import pandas as pd
from sqlalchemy import create_engine, Column, Integer, String, Float, Date, Boolean, UniqueConstraint
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.exc import IntegrityError
from passlib.context import CryptContext

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://postgres:123456@localhost:5432/work_db"
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

templates = Jinja2Templates(directory="templates")
app = FastAPI()


class Shift(Base):
    __tablename__ = "shifts"

    id = Column(Integer, primary_key=True, index=True)
    store = Column(String, nullable=False)
    shift_date = Column(Date, nullable=False)
    employee = Column(String, nullable=False)
    hours = Column(Float, nullable=False)

    __table_args__ = (
        UniqueConstraint("store", "shift_date", "employee", name="uq_shift_row"),
    )


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    phone = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    employee_name = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=False)


Base.metadata.create_all(bind=engine)


def normalize_phone(phone: str) -> str:
    return str(phone).strip().replace(" ", "").replace("+", "")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(str(plain_password).strip(), hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(str(password).strip())


@app.get("/")
def root():
    return RedirectResponse(url="/login", status_code=302)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(
        request,
        "login.html",
        {"error": None}
    )


@app.post("/login", response_class=HTMLResponse)
def login_submit(request: Request, phone: str = Form(...), password: str = Form(...)):
    session = SessionLocal()
    try:
        phone_clean = normalize_phone(phone)
        password_clean = str(password).strip()

        user = session.query(User).filter(User.phone == phone_clean).first()

        if not user or not verify_password(password_clean, user.password_hash):
            return templates.TemplateResponse(
                request,
                "login.html",
                {"error": "Неверный телефон или пароль"}
            )

        return RedirectResponse(url=f"/cabinet?phone={user.phone}", status_code=302)

    finally:
        session.close()


@app.get("/cabinet", response_class=HTMLResponse)
def cabinet(request: Request, phone: str, date_from: str = "", date_to: str = ""):
    session = SessionLocal()
    try:
        phone_clean = normalize_phone(phone)
        user = session.query(User).filter(User.phone == phone_clean).first()

        if not user:
            return RedirectResponse(url="/login", status_code=302)

        query = session.query(Shift).filter(Shift.employee == user.employee_name)

        try:
            if date_from:
                query = query.filter(
                    Shift.shift_date >= datetime.strptime(date_from, "%Y-%m-%d").date()
                )
            if date_to:
                query = query.filter(
                    Shift.shift_date <= datetime.strptime(date_to, "%Y-%m-%d").date()
                )
        except ValueError:
            return templates.TemplateResponse(
                request,
                "cabinet.html",
                {
                    "user": user,
                    "shifts": [],
                    "total_hours": 0,
                    "date_from": date_from,
                    "date_to": date_to,
                    "error": "Некорректный формат даты"
                }
            )

        shifts = query.order_by(Shift.shift_date).all()
        total = sum(s.hours for s in shifts)

        return templates.TemplateResponse(
            request,
            "cabinet.html",
            {
                "user": user,
                "shifts": shifts,
                "total_hours": total,
                "date_from": date_from,
                "date_to": date_to,
                "error": None
            }
        )
    finally:
        session.close()


@app.get("/admin/create-user", response_class=HTMLResponse)
def create_user_page(request: Request):
    return templates.TemplateResponse(
        request,
        "create_user.html",
        {"message": None, "error": None}
    )


@app.post("/admin/create-user", response_class=HTMLResponse)
def create_user_submit(
    request: Request,
    phone: str = Form(...),
    password: str = Form(...),
    employee_name: str = Form(...)
):
    session = SessionLocal()
    try:
        phone_clean = normalize_phone(phone)
        password_clean = str(password).strip()
        employee_name_clean = str(employee_name).strip()

        if session.query(User).filter(User.phone == phone_clean).first():
            return templates.TemplateResponse(
                request,
                "create_user.html",
                {"error": "Пользователь уже существует", "message": None}
            )

        user = User(
            phone=phone_clean,
            password_hash=get_password_hash(password_clean),
            employee_name=employee_name_clean
        )

        session.add(user)
        session.commit()

        return templates.TemplateResponse(
            request,
            "create_user.html",
            {"message": "Пользователь создан", "error": None}
        )
    finally:
        session.close()


@app.get("/admin/upload-users", response_class=HTMLResponse)
def upload_users_page(request: Request):
    return templates.TemplateResponse(
        request,
        "upload_users.html",
        {"message": None, "error": None, "created": None, "skipped": None, "bad_rows": None}
    )


@app.post("/admin/upload-users", response_class=HTMLResponse)
async def upload_users_submit(request: Request, file: UploadFile = File(...)):
    session = SessionLocal()
    try:
        df = pd.read_excel(file.file)
        df.columns = [str(c).strip() for c in df.columns]

        required = ["phone", "employee_name", "password"]
        missing = [c for c in required if c not in df.columns]

        if missing:
            return templates.TemplateResponse(
                request,
                "upload_users.html",
                {
                    "error": f"В файле нет обязательных колонок: {', '.join(missing)}",
                    "message": None,
                    "created": None,
                    "skipped": None,
                    "bad_rows": None
                }
            )

        created = 0
        skipped = 0
        bad = 0

        for _, row in df.iterrows():
            try:
                phone_raw = row["phone"]
                name_raw = row["employee_name"]
                password_raw = row["password"]

                if pd.isna(phone_raw) or pd.isna(name_raw) or pd.isna(password_raw):
                    bad += 1
                    continue

                phone = normalize_phone(phone_raw)
                name = str(name_raw).strip()

                if isinstance(password_raw, float) and password_raw.is_integer():
                    password = str(int(password_raw))
                else:
                    password = str(password_raw).strip()

                if not phone or not name or not password:
                    bad += 1
                    continue

                if session.query(User).filter(User.phone == phone).first():
                    skipped += 1
                    continue

                user = User(
                    phone=phone,
                    password_hash=get_password_hash(password),
                    employee_name=name
                )

                session.add(user)

                try:
                    session.commit()
                    created += 1
                except IntegrityError:
                    session.rollback()
                    skipped += 1

            except Exception:
                session.rollback()
                bad += 1

        return templates.TemplateResponse(
            request,
            "upload_users.html",
            {
                "message": "Готово",
                "created": created,
                "skipped": skipped,
                "bad_rows": bad,
                "error": None
            }
        )

    finally:
        session.close()


@app.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request):
    session = SessionLocal()
    try:
        users = session.query(User).order_by(User.employee_name.asc()).all()
        return templates.TemplateResponse(
            request,
            "admin_users.html",
            {"users": users}
        )
    finally:
        session.close()


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    df = pd.read_excel(file.file, header=1)

    df = df.iloc[:, [0, 6, 12, 25]]
    df.columns = ["store", "date", "employee", "hours"]

    df = df.dropna()
    df["store"] = df["store"].astype(str).str.strip()
    df["employee"] = df["employee"].astype(str).str.strip()
    df["date"] = pd.to_datetime(df["date"], dayfirst=True, errors="coerce")
    df["hours"] = pd.to_numeric(df["hours"], errors="coerce")

    df = df.dropna()
    df = df.drop_duplicates(subset=["store", "date", "employee"])

    session = SessionLocal()
    added = 0
    skipped = 0

    try:
        for _, row in df.iterrows():
            exists = session.query(Shift).filter_by(
                store=row["store"],
                shift_date=row["date"].date(),
                employee=row["employee"]
            ).first()

            if exists:
                skipped += 1
                continue

            item = Shift(
                store=row["store"],
                shift_date=row["date"].date(),
                employee=row["employee"],
                hours=float(row["hours"])
            )

            session.add(item)

            try:
                session.commit()
                added += 1
            except IntegrityError:
                session.rollback()
                skipped += 1

    finally:
        session.close()

    return {"added": added, "skipped": skipped}


@app.get("/debug/shifts-count")
def debug():
    session = SessionLocal()
    try:
        return {"count": session.query(Shift).count()}
    finally:
        session.close()
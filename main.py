from datetime import datetime
from fastapi import FastAPI, UploadFile, File, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import pandas as pd
from sqlalchemy import create_engine, Column, Integer, String, Float, Date, Boolean, UniqueConstraint
from sqlalchemy.orm import declarative_base, sessionmaker
from passlib.context import CryptContext

# ВПИШИ СВОЙ ПАРОЛЬ ОТ POSTGRESQL
import os
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg2://postgres:123456@localhost:5432/work_db")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ВАЖНО:
# bcrypt у тебя уже конфликтовал с passlib,
# поэтому используем более стабильную схему для текущего проекта
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


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password.strip(), hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password.strip())


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
def login_submit(
    request: Request,
    phone: str = Form(...),
    password: str = Form(...)
):
    session = SessionLocal()
    try:
        phone_clean = phone.strip()
        password_clean = password.strip()

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
def cabinet(
    request: Request,
    phone: str,
    date_from: str = "",
    date_to: str = ""
):
    session = SessionLocal()
    try:
        phone_clean = phone.strip()
        user = session.query(User).filter(User.phone == phone_clean).first()

        if not user:
            return RedirectResponse(url="/login", status_code=302)

        query = session.query(Shift).filter(Shift.employee == user.employee_name)

        try:
            if date_from:
                parsed_date_from = datetime.strptime(date_from, "%Y-%m-%d").date()
                query = query.filter(Shift.shift_date >= parsed_date_from)

            if date_to:
                parsed_date_to = datetime.strptime(date_to, "%Y-%m-%d").date()
                query = query.filter(Shift.shift_date <= parsed_date_to)
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

        shifts = query.order_by(Shift.shift_date.asc()).all()
        total_hours = sum(item.hours for item in shifts)

        return templates.TemplateResponse(
            request,
            "cabinet.html",
            {
                "user": user,
                "shifts": shifts,
                "total_hours": total_hours,
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
    employee_name: str = Form(...),
    is_admin: str = Form(default="")
):
    session = SessionLocal()
    try:
        phone_clean = phone.strip()
        password_clean = password.strip()
        employee_name_clean = employee_name.strip()

        if not phone_clean:
            return templates.TemplateResponse(
                request,
                "create_user.html",
                {"message": None, "error": "Телефон не может быть пустым"}
            )

        if not password_clean:
            return templates.TemplateResponse(
                request,
                "create_user.html",
                {"message": None, "error": "Пароль не может быть пустым"}
            )

        if not employee_name_clean:
            return templates.TemplateResponse(
                request,
                "create_user.html",
                {"message": None, "error": "ФИО не может быть пустым"}
            )

        existing = session.query(User).filter(User.phone == phone_clean).first()
        if existing:
            return templates.TemplateResponse(
                request,
                "create_user.html",
                {"message": None, "error": "Пользователь с таким телефоном уже существует"}
            )

        user = User(
            phone=phone_clean,
            password_hash=get_password_hash(password_clean),
            employee_name=employee_name_clean,
            is_admin=(is_admin == "true" or is_admin == "on")
        )
        session.add(user)
        session.commit()

        return templates.TemplateResponse(
            request,
            "create_user.html",
            {"message": "Пользователь создан", "error": None}
        )

    except Exception as e:
        session.rollback()
        return templates.TemplateResponse(
            request,
            "create_user.html",
            {"message": None, "error": f"Ошибка создания пользователя: {str(e)}"}
        )

    finally:
        session.close()


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    try:
        df = pd.read_excel(file.file, header=1)

        # Берем только нужные столбцы:
        # A -> 0
        # G -> 6
        # M -> 12
        # Z -> 25
        df = df.iloc[:, [0, 6, 12, 25]]
        df.columns = ["store", "date", "employee", "hours"]

        df = df.dropna(subset=["store", "date", "employee", "hours"])

        # дата в исходном файле может быть как датой, так и строкой
        df["date"] = pd.to_datetime(df["date"], dayfirst=True, errors="coerce")
        df = df.dropna(subset=["date"])

        session = SessionLocal()
        added = 0
        skipped = 0

        try:
            for _, row in df.iterrows():
                store = str(row["store"]).strip()
                employee = str(row["employee"]).strip()
                shift_date = row["date"].date()
                hours = float(row["hours"])

                exists = session.query(Shift).filter_by(
                    store=store,
                    shift_date=shift_date,
                    employee=employee
                ).first()

                if exists:
                    skipped += 1
                    continue

                item = Shift(
                    store=store,
                    shift_date=shift_date,
                    employee=employee,
                    hours=hours
                )
                session.add(item)
                added += 1

            session.commit()

        except Exception:
            session.rollback()
            raise

        finally:
            session.close()

        return {
            "rows_in_file": len(df),
            "added_to_db": added,
            "skipped_duplicates": skipped
        }

    except Exception as e:
        return {"error": str(e)}
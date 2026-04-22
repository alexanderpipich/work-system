import os
from datetime import datetime, timedelta
from fastapi import FastAPI, UploadFile, File, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
import pandas as pd
from sqlalchemy import create_engine, Column, Integer, String, Float, Date, Boolean, UniqueConstraint
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.exc import IntegrityError
from passlib.context import CryptContext
from sqlalchemy import text

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://postgres:123456@localhost:5432/work_db"
)

SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret-key-please")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

templates = Jinja2Templates(directory="templates")
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
app.mount("/static", StaticFiles(directory="static"), name="static")


class Shift(Base):
    __tablename__ = "shifts"

    id = Column(Integer, primary_key=True, index=True)
    store = Column(String, nullable=False)
    format = Column(String, nullable=False)
    shift_date = Column(Date, nullable=False)
    service = Column(String, nullable=False)
    employee = Column(String, nullable=False)
    hours = Column(Float, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "store",
            "format",
            "shift_date",
            "service",
            "employee",
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


class Rate(Base):
    __tablename__ = "rates"

    id = Column(Integer, primary_key=True, index=True)
    service = Column(String, nullable=False)
    format = Column(String, nullable=False)
    store = Column(String, nullable=True)
    employee_name = Column(String, nullable=True)
    hourly_rate = Column(Float, nullable=False)
    active_from = Column(Date, nullable=True)
    active_to = Column(Date, nullable=True)
    comment = Column(String, nullable=True)

Base.metadata.create_all(bind=engine)


def normalize_phone(phone) -> str:
    if phone is None:
        return ""

    if isinstance(phone, float) and phone.is_integer():
        phone = int(phone)

    phone_str = str(phone).strip().replace(" ", "").replace("+", "")

    if phone_str.endswith(".0"):
        phone_str = phone_str[:-2]

    return phone_str


def normalize_format(value) -> str:
    if value is None:
        return ""

    text = str(value).strip().upper()

    # Нормализация под ключевые форматы
    replacements = {
        "ГМ ": "ГМ",
        " СМ": "СМ",
        "СМ ": "СМ",
        " ГМ": "ГМ",
    }
    text = replacements.get(text, text)
    return text


def normalize_text(value) -> str:
    if value is None:
        return ""
    return str(value).strip()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(str(plain_password).strip(), hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(str(password).strip())


def get_current_user(request: Request, session):
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return session.query(User).filter(User.id == user_id).first()


def require_login(request: Request, session):
    user = get_current_user(request, session)
    if not user:
        return None
    return user


def require_admin(request: Request, session):
    user = get_current_user(request, session)
    if not user or not user.is_admin:
        return None
    return user

def get_rate_for_shift(session, shift):
    candidates = session.query(Rate).filter(
        Rate.service == shift.service,
        Rate.format == shift.format
    ).all()

    # Фильтрация по датам действия
    valid_candidates = []
    for rate in candidates:
        if rate.active_from and shift.shift_date < rate.active_from:
            continue
        if rate.active_to and shift.shift_date > rate.active_to:
            continue
        valid_candidates.append(rate)

    # Приоритет:
    # 1. employee + store
    for rate in valid_candidates:
        if rate.employee_name == shift.employee and rate.store == shift.store:
            return rate

    # 2. employee only
    for rate in valid_candidates:
        if rate.employee_name == shift.employee and not rate.store:
            return rate

    # 3. store only
    for rate in valid_candidates:
        if rate.store == shift.store and not rate.employee_name:
            return rate

    # 4. base rate
    for rate in valid_candidates:
        if not rate.store and not rate.employee_name:
            return rate

    return None

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

        request.session["user_id"] = user.id

        if user.is_admin:
            return RedirectResponse(url="/admin", status_code=302)

        return RedirectResponse(url="/cabinet", status_code=302)

    finally:
        session.close()


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)


@app.get("/cabinet", response_class=HTMLResponse)
def cabinet(request: Request, date_from: str = "", date_to: str = ""):
    session = SessionLocal()
    try:
        user = require_login(request, session)
        if not user:
            return RedirectResponse(url="/login", status_code=302)

        today = datetime.today().date()

        if not date_from and not date_to:
            current_week_monday = today - timedelta(days=today.weekday())
            default_date_to = current_week_monday - timedelta(days=1)
            default_date_from = default_date_to - timedelta(days=6)

            date_from = default_date_from.strftime("%Y-%m-%d")
            date_to = default_date_to.strftime("%Y-%m-%d")

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
    session = SessionLocal()
    try:
        admin = require_admin(request, session)
        if not admin:
            return RedirectResponse(url="/login", status_code=302)

        return templates.TemplateResponse(
            request,
            "create_user.html",
            {"message": None, "error": None}
        )
    finally:
        session.close()


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
        admin = require_admin(request, session)
        if not admin:
            return RedirectResponse(url="/login", status_code=302)

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
    finally:
        session.close()


@app.get("/admin/upload-users", response_class=HTMLResponse)
def upload_users_page(request: Request):
    session = SessionLocal()
    try:
        admin = require_admin(request, session)
        if not admin:
            return RedirectResponse(url="/login", status_code=302)

        return templates.TemplateResponse(
            request,
            "upload_users.html",
            {"message": None, "error": None, "created": None, "skipped": None, "bad_rows": None}
        )
    finally:
        session.close()


@app.post("/admin/upload-users", response_class=HTMLResponse)
async def upload_users_submit(request: Request, file: UploadFile = File(...)):
    session = SessionLocal()
    try:
        admin = require_admin(request, session)
        if not admin:
            return RedirectResponse(url="/login", status_code=302)

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
                name = normalize_text(name_raw)

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
        admin = require_admin(request, session)
        if not admin:
            return RedirectResponse(url="/login", status_code=302)

        users = session.query(User).order_by(User.employee_name.asc()).all()
        return templates.TemplateResponse(
            request,
            "admin_users.html",
            {
                "users": users,
                "message": None,
                "error": None
            }
        )
    finally:
        session.close()


@app.post("/admin/delete-user", response_class=HTMLResponse)
def delete_user(request: Request, user_id: int = Form(...)):
    session = SessionLocal()
    try:
        admin = require_admin(request, session)
        if not admin:
            return RedirectResponse(url="/login", status_code=302)

        user = session.query(User).filter(User.id == user_id).first()

        if not user:
            users = session.query(User).order_by(User.employee_name.asc()).all()
            return templates.TemplateResponse(
                request,
                "admin_users.html",
                {
                    "users": users,
                    "message": None,
                    "error": "Пользователь не найден"
                }
            )

        session.delete(user)
        session.commit()

        users = session.query(User).order_by(User.employee_name.asc()).all()
        return templates.TemplateResponse(
            request,
            "admin_users.html",
            {
                "users": users,
                "message": "Пользователь удалён",
                "error": None
            }
        )

    finally:
        session.close()


@app.post("/admin/change-password", response_class=HTMLResponse)
def change_password(
    request: Request,
    user_id: int = Form(...),
    new_password: str = Form(...)
):
    session = SessionLocal()
    try:
        admin = require_admin(request, session)
        if not admin:
            return RedirectResponse(url="/login", status_code=302)

        user = session.query(User).filter(User.id == user_id).first()

        if not user:
            users = session.query(User).order_by(User.employee_name.asc()).all()
            return templates.TemplateResponse(
                request,
                "admin_users.html",
                {
                    "users": users,
                    "message": None,
                    "error": "Пользователь не найден"
                }
            )

        new_password_clean = str(new_password).strip()
        if not new_password_clean:
            users = session.query(User).order_by(User.employee_name.asc()).all()
            return templates.TemplateResponse(
                request,
                "admin_users.html",
                {
                    "users": users,
                    "message": None,
                    "error": "Новый пароль не может быть пустым"
                }
            )

        user.password_hash = get_password_hash(new_password_clean)
        session.commit()

        users = session.query(User).order_by(User.employee_name.asc()).all()
        return templates.TemplateResponse(
            request,
            "admin_users.html",
            {
                "users": users,
                "message": "Пароль изменён",
                "error": None
            }
        )

    finally:
        session.close()


@app.get("/admin/fix-phones")
def fix_phones(request: Request):
    session = SessionLocal()
    try:
        admin = require_admin(request, session)
        if not admin:
            return RedirectResponse(url="/login", status_code=302)

        users = session.query(User).all()
        fixed = 0
        skipped = 0

        for user in users:
            old_phone = user.phone
            new_phone = normalize_phone(user.phone)

            if old_phone == new_phone:
                continue

            existing = session.query(User).filter(User.phone == new_phone).first()
            if existing and existing.id != user.id:
                skipped += 1
                continue

            user.phone = new_phone
            fixed += 1

        session.commit()
        return {"fixed": fixed, "skipped": skipped}

    except Exception as e:
        session.rollback()
        return {"error": str(e)}

    finally:
        session.close()


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    def get_previous_month(today_date):
        if today_date.month == 1:
            return 12, today_date.year - 1
        return today_date.month - 1, today_date.year

    def is_editable_month(shift_date, today_date):
        if shift_date.year == today_date.year and shift_date.month == today_date.month:
            return True

        prev_month, prev_year = get_previous_month(today_date)
        if shift_date.year == prev_year and shift_date.month == prev_month and today_date.day <= 7:
            return True

        return False

    try:
        df = pd.read_excel(file.file, header=1)

        # A=0 store, C=2 format, G=6 date, L=11 service, M=12 employee, Z=25 hours
        df = df.iloc[:, [0, 2, 6, 11, 12, 25]]
        df.columns = ["store", "format", "date", "service", "employee", "hours"]

        df = df.dropna(subset=["store", "format", "date", "service", "employee", "hours"])

        df["store"] = df["store"].apply(normalize_text)
        df["format"] = df["format"].apply(normalize_format)
        df["service"] = df["service"].apply(normalize_text)
        df["employee"] = df["employee"].apply(normalize_text)
        df["date"] = pd.to_datetime(df["date"], dayfirst=True, errors="coerce")
        df["hours"] = pd.to_numeric(df["hours"], errors="coerce")

        df = df.dropna(subset=["date", "hours"])
        df = df.drop_duplicates(
            subset=["store", "format", "date", "service", "employee"],
            keep="last"
        )

        session = SessionLocal()

        added = 0
        updated = 0
        skipped_duplicates = 0
        skipped_locked_months = 0

        today_date = datetime.today().date()

        try:
            for _, row in df.iterrows():
                store = row["store"]
                format_value = row["format"]
                shift_date = row["date"].date()
                service = row["service"]
                employee = row["employee"]
                hours = float(row["hours"])

                if not is_editable_month(shift_date, today_date):
                    skipped_locked_months += 1
                    continue

                existing = session.query(Shift).filter_by(
                    store=store,
                    format=format_value,
                    shift_date=shift_date,
                    service=service,
                    employee=employee
                ).first()

                if existing:
                    if float(existing.hours) != hours:
                        existing.hours = hours
                        try:
                            session.commit()
                            updated += 1
                        except Exception:
                            session.rollback()
                            skipped_duplicates += 1
                    else:
                        skipped_duplicates += 1
                    continue

                item = Shift(
                    store=store,
                    format=format_value,
                    shift_date=shift_date,
                    service=service,
                    employee=employee,
                    hours=hours
                )

                session.add(item)

                try:
                    session.commit()
                    added += 1
                except IntegrityError:
                    session.rollback()
                    skipped_duplicates += 1

        finally:
            session.close()

        return {
            "added": added,
            "updated": updated,
            "skipped_duplicates": skipped_duplicates,
            "skipped_locked_months": skipped_locked_months
        }

    except Exception as e:
        return {"error": str(e)}


@app.get("/admin/rates", response_class=HTMLResponse)
def admin_rates(request: Request):
    session = SessionLocal()
    try:
        admin = require_admin(request, session)
        if not admin:
            return RedirectResponse(url="/login", status_code=302)

        rates = session.query(Rate).order_by(Rate.service.asc(), Rate.format.asc(), Rate.store.asc().nullsfirst()).all()

        return templates.TemplateResponse(
            request,
            "rates.html",
            {
                "rates": rates,
                "message": None,
                "error": None
            }
        )
    finally:
        session.close()


@app.post("/admin/rates", response_class=HTMLResponse)
def create_rate(
    request: Request,
    service: str = Form(...),
    format: str = Form(...),
    store: str = Form(default=""),
    employee_name: str = Form(default=""),
    hourly_rate: float = Form(...),
    active_from: str = Form(default=""),
    active_to: str = Form(default=""),
    comment: str = Form(default="")
):
    session = SessionLocal()
    try:
        admin = require_admin(request, session)
        if not admin:
            return RedirectResponse(url="/login", status_code=302)

        service_clean = normalize_text(service)
        format_clean = normalize_format(format)
        store_clean = normalize_text(store) or None
        employee_name_clean = normalize_text(employee_name) or None
        comment_clean = normalize_text(comment) or None

        active_from_date = None
        active_to_date = None

        try:
            if active_from:
                active_from_date = datetime.strptime(active_from, "%Y-%m-%d").date()
            if active_to:
                active_to_date = datetime.strptime(active_to, "%Y-%m-%d").date()
        except ValueError:
            rates = session.query(Rate).order_by(Rate.service.asc(), Rate.format.asc(), Rate.store.asc().nullsfirst()).all()
            return templates.TemplateResponse(
                request,
                "rates.html",
                {
                    "rates": rates,
                    "message": None,
                    "error": "Некорректный формат даты"
                }
            )

        if hourly_rate <= 0:
            rates = session.query(Rate).order_by(Rate.service.asc(), Rate.format.asc(), Rate.store.asc().nullsfirst()).all()
            return templates.TemplateResponse(
                request,
                "rates.html",
                {
                    "rates": rates,
                    "message": None,
                    "error": "ЧТС должна быть больше нуля"
                }
            )

        rate = Rate(
            service=service_clean,
            format=format_clean,
            store=store_clean,
            employee_name=employee_name_clean,
            hourly_rate=hourly_rate,
            active_from=active_from_date,
            active_to=active_to_date,
            comment=comment_clean
        )

        session.add(rate)
        session.commit()

        rates = session.query(Rate).order_by(Rate.service.asc(), Rate.format.asc(), Rate.store.asc().nullsfirst()).all()
        return templates.TemplateResponse(
            request,
            "rates.html",
            {
                "rates": rates,
                "message": "Ставка добавлена",
                "error": None
            }
        )

    finally:
        session.close()

@app.get("/admin/payroll", response_class=HTMLResponse)
def admin_payroll(
    request: Request,
    date_from: str = "",
    date_to: str = "",
    employee_name: str = ""
):
    session = SessionLocal()
    try:
        admin = require_admin(request, session)
        if not admin:
            return RedirectResponse(url="/login", status_code=302)

        today = datetime.today().date()

        # По умолчанию — последняя завершенная неделя
        if not date_from and not date_to:
            current_week_monday = today - timedelta(days=today.weekday())
            default_date_to = current_week_monday - timedelta(days=1)
            default_date_from = default_date_to - timedelta(days=6)

            date_from = default_date_from.strftime("%Y-%m-%d")
            date_to = default_date_to.strftime("%Y-%m-%d")

        shifts_query = session.query(Shift)

        try:
            if date_from:
                shifts_query = shifts_query.filter(
                    Shift.shift_date >= datetime.strptime(date_from, "%Y-%m-%d").date()
                )
            if date_to:
                shifts_query = shifts_query.filter(
                    Shift.shift_date <= datetime.strptime(date_to, "%Y-%m-%d").date()
                )
        except ValueError:
            return templates.TemplateResponse(
                request,
                "payroll.html",
                {
                    "rows": [],
                    "date_from": date_from,
                    "date_to": date_to,
                    "employee_name": employee_name,
                    "employees": [],
                    "total_hours": 0,
                    "total_amount": 0,
                    "error": "Некорректный формат даты",
                    "message": None
                }
            )

        if employee_name.strip():
            shifts_query = shifts_query.filter(Shift.employee == employee_name.strip())

        shifts = shifts_query.order_by(Shift.employee.asc(), Shift.shift_date.asc()).all()

        employees = session.query(Shift.employee).distinct().order_by(Shift.employee.asc()).all()
        employee_list = [e[0] for e in employees]

        payroll_map = {}

        for shift in shifts:
            rate = get_rate_for_shift(session, shift)
            rate_value = rate.hourly_rate if rate else 0
            amount = shift.hours * rate_value if rate else 0

            key = shift.employee
            if key not in payroll_map:
                payroll_map[key] = {
                    "employee_name": shift.employee,
                    "hours": 0,
                    "amount": 0,
                    "missing_rates": 0
                }

            payroll_map[key]["hours"] += shift.hours
            payroll_map[key]["amount"] += amount

            if not rate:
                payroll_map[key]["missing_rates"] += 1

        rows = list(payroll_map.values())
        rows.sort(key=lambda x: x["employee_name"])

        total_hours = sum(row["hours"] for row in rows)
        total_amount = sum(row["amount"] for row in rows)

        return templates.TemplateResponse(
            request,
            "payroll.html",
            {
                "rows": rows,
                "date_from": date_from,
                "date_to": date_to,
                "employee_name": employee_name,
                "employees": employee_list,
                "total_hours": total_hours,
                "total_amount": total_amount,
                "error": None,
                "message": None
            }
        )

    finally:
        session.close()

@app.get("/debug/shifts-count")
def debug(request: Request):
    session = SessionLocal()
    try:
        admin = require_admin(request, session)
        if not admin:
            return RedirectResponse(url="/login", status_code=302)

        return {"count": session.query(Shift).count()}
    finally:
        session.close()

@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request):
    session = SessionLocal()
    try:
        admin = require_admin(request, session)
        if not admin:
            return RedirectResponse(url="/login", status_code=302)

        return templates.TemplateResponse(
            request,
            "admin_dashboard.html",
            {"admin": admin}
        )
    finally:
        session.close()


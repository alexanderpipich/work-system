from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from dependencies import get_db
from models import Rate, Shift
from rbac import require_permission
from service_matrix import build_service_matrix, normalize_service_base
from utils import normalize_text


router = APIRouter()
templates = Jinja2Templates(directory="templates")
_rates_manage = require_permission("rates.manage")


def _distinct_values(session, *columns):
    values = set()
    for column in columns:
        for row in session.query(column).distinct().all():
            value = normalize_text(row[0])
            if value:
                values.add(value)
    return sorted(values)


@router.get("/admin/services", response_class=HTMLResponse)
def admin_services(
    request: Request,
    city: str = "",
    fmt: str = "",
    q: str = "",
    session: Session = Depends(get_db),
    user=Depends(_rates_manage),
):
    """Диагностическая матрица услуг: строка = базовая услуга, колонки = уровни
    1..5 + «без уровня». Только чтение — правка ставок на /admin/rates."""
    city = normalize_text(city)
    fmt = normalize_text(fmt)
    q = normalize_text(q)

    cities = _distinct_values(session, Rate.city, Shift.city)
    formats = _distinct_values(session, Rate.format, Shift.format)

    rate_query = session.query(Rate)
    shift_query = session.query(Shift.service).distinct()

    if city:
        rate_query = rate_query.filter(Rate.city == city)
        shift_query = shift_query.filter(Shift.city == city)
    if fmt:
        rate_query = rate_query.filter(Rate.format == fmt)
        shift_query = shift_query.filter(Shift.format == fmt)

    rate_rows = [
        {
            "service": rate.service,
            "city": rate.city,
            "format": rate.format,
            "store": rate.store,
            "employee_name": rate.employee_name,
            "hourly_rate": rate.hourly_rate,
        }
        for rate in rate_query.all()
    ]
    shift_rows = [{"service": row[0]} for row in shift_query.all()]

    matrix = build_service_matrix(rate_rows, shift_rows)

    rows = matrix["rows"]
    if q:
        needle = normalize_service_base(q)
        rows = [
            row
            for row in rows
            if needle in row["base_key"]
            or any(needle in normalize_service_base(name) for name in row["original_services"])
        ]

    return templates.TemplateResponse(
        request,
        "service_matrix.html",
        {
            "rows": rows,
            "levels": matrix["levels"],
            "counters": matrix["counters"],
            "no_rate_services": matrix["no_rate_services"],
            "rate_no_shift_services": matrix["rate_no_shift_services"],
            "cities": cities,
            "formats": formats,
            "selected_city": city,
            "selected_format": fmt,
            "search": q,
            "total_bases": len(matrix["rows"]),
            "shown_bases": len(rows),
        },
    )

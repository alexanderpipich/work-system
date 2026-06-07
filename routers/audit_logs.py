from datetime import datetime, timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from dependencies import get_db, require_admin_user
from models import AuditLog, User
from utils import normalize_text


router = APIRouter()
templates = Jinja2Templates(directory="templates")


def _parse_date(value):
    value = normalize_text(value)
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return None


def _query_string(**params):
    clean = {key: value for key, value in params.items() if value not in ("", None)}
    return urlencode(clean)


@router.get("/admin/audit-log", response_class=HTMLResponse)
def admin_audit_log(
    request: Request,
    user: str = "",
    role: str = "",
    action: str = "",
    entity_type: str = "",
    date_from: str = "",
    date_to: str = "",
    page: int = 1,
    limit: int = 100,
    session: Session = Depends(get_db),
    admin=Depends(require_admin_user),
):
    page = max(page, 1)
    limit = min(max(limit, 20), 300)

    query = session.query(AuditLog)

    user_clean = normalize_text(user)
    if user_clean:
        matching_users = session.query(User.id).filter(
            User.employee_name.ilike(f"%{user_clean}%")
        ).all()
        user_ids = [row[0] for row in matching_users]
        query = query.filter(AuditLog.user_id.in_(user_ids or [-1]))

    role_clean = normalize_text(role)
    if role_clean:
        query = query.filter(AuditLog.user_role == role_clean)

    action_clean = normalize_text(action)
    if action_clean:
        query = query.filter(AuditLog.action == action_clean)

    entity_type_clean = normalize_text(entity_type)
    if entity_type_clean:
        query = query.filter(AuditLog.entity_type == entity_type_clean)

    start_date = _parse_date(date_from)
    if start_date:
        query = query.filter(AuditLog.created_at >= start_date)

    end_date = _parse_date(date_to)
    if end_date:
        query = query.filter(AuditLog.created_at < end_date + timedelta(days=1))

    total_count = query.count()
    logs = query.order_by(
        AuditLog.created_at.desc(),
        AuditLog.id.desc(),
    ).offset((page - 1) * limit).limit(limit).all()

    user_ids = [log.user_id for log in logs if log.user_id]
    users = {
        item.id: item.employee_name
        for item in session.query(User).filter(User.id.in_(user_ids or [-1])).all()
    }

    actions = [
        row[0]
        for row in session.query(AuditLog.action)
        .filter(AuditLog.action != None)
        .distinct()
        .order_by(AuditLog.action.asc())
        .all()
    ]
    entity_types = [
        row[0]
        for row in session.query(AuditLog.entity_type)
        .filter(AuditLog.entity_type != None)
        .distinct()
        .order_by(AuditLog.entity_type.asc())
        .all()
    ]
    roles = [
        row[0]
        for row in session.query(AuditLog.user_role)
        .filter(AuditLog.user_role != None)
        .distinct()
        .order_by(AuditLog.user_role.asc())
        .all()
    ]

    base_params = {
        "user": user_clean,
        "role": role_clean,
        "action": action_clean,
        "entity_type": entity_type_clean,
        "date_from": date_from,
        "date_to": date_to,
        "limit": limit,
    }
    previous_url = None
    if page > 1:
        previous_url = f"/admin/audit-log?{_query_string(**base_params, page=page - 1)}"
    next_url = None
    if page * limit < total_count:
        next_url = f"/admin/audit-log?{_query_string(**base_params, page=page + 1)}"

    return templates.TemplateResponse(
        request,
        "audit_log.html",
        {
            "admin": admin,
            "logs": logs,
            "users": users,
            "filters": {
                "user": user_clean,
                "role": role_clean,
                "action": action_clean,
                "entity_type": entity_type_clean,
                "date_from": date_from,
                "date_to": date_to,
                "limit": limit,
            },
            "actions": actions,
            "entity_types": entity_types,
            "roles": roles,
            "page": page,
            "limit": limit,
            "total_count": total_count,
            "previous_url": previous_url,
            "next_url": next_url,
        },
    )

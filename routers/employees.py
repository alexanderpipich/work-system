import calendar
from collections import defaultdict
from datetime import date, datetime, timedelta
from io import BytesIO
from pathlib import Path
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from openpyxl import Workbook
from openpyxl.styles import Font
from sqlalchemy import func
from sqlalchemy.orm import Session

from access import apply_shift_scope, get_user_cities, get_user_stores, scope_allows_store
from audit_helpers import create_audit_log
from dependencies import RedirectException, current_user, get_db
from document_helpers import citizenship_display
from file_storage import storage_response, storage_save
from models import (
    DocumentType,
    EmployeeDismissalDecision,
    EmployeeDocument,
    EmployeeMonitoringRecommendation,
    EmployeeMonitoringSettings,
    Shift,
    StoreReconciliation,
    StoreReconciliationSettings,
    User,
)
from monitoring_helpers import (
    create_recommendation,
    get_monitoring_settings,
    recompute_recommendations,
)
from navigation import build_navigation, employees_groups
from store_helpers import allows_bp, store_formats
from rbac import HR_CABINET_ROLES, canonical_role, has_permission, is_superadmin, require_permission
from time_helpers import business_today, now_utc
from utils import normalize_person_name, normalize_text


router = APIRouter()
templates = Jinja2Templates(directory="templates")
_admin_settings = require_permission("admin.settings")
# Префиксы ключей в хранилище (в локальном режиме ложатся под GENERATED_FILES_ROOT).
RECONCILIATION_PREFIX = "generated_files/reconciliations"
XLSX_CONTENT_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def _is_admin(user):
    return is_superadmin(user)


def require_employee_manager(request: Request, user=Depends(current_user)):
    if not has_permission(user, "employees.view"):
        raise RedirectException("/")
    if request.url.path.startswith("/admin") and not _is_admin(user):
        raise RedirectException("/")
    if request.url.path.startswith("/hr") and canonical_role(user) not in HR_CABINET_ROLES:
        raise RedirectException("/")
    return user


def _context(request, user, section="dashboard", **extra):
    economist = request.url.path.startswith("/economist")
    hr_view = request.url.path.startswith("/hr")
    context = {
        "user": user,
        "section": section,
        "base_path": "/hr/employees" if hr_view else ("/economist/employees" if economist else "/admin/employees"),
        "back_url": "/hr" if hr_view else ("/economist" if economist else "/admin"),
        "is_admin": _is_admin(user),
    }
    context.update(extra)
    return context


def _scope(query, model, user):
    return apply_shift_scope(query, query.session, user, model)


def _scope_allowed(session, user, city, store):
    return scope_allows_store(session, user, city, store)


def _redirect(request, suffix="", **params):
    root = "/hr/employees" if request.url.path.startswith("/hr") else ("/economist/employees" if request.url.path.startswith("/economist") else "/admin/employees")
    url = f"{root}{suffix}"
    clean = {key: value for key, value in params.items() if value not in (None, "")}
    return RedirectResponse(f"{url}?{urlencode(clean)}" if clean else url, status_code=302)


def _parse_date(value):
    return datetime.strptime(value, "%Y-%m-%d").date()


def reconciliation_ready_date(period_to):
    current = period_to
    added = 0
    while added < 3:
        current += timedelta(days=1)
        if current.weekday() < 5:
            added += 1
    return current


def is_fixed_reconciliation_period(date_from, date_to):
    last_day = calendar.monthrange(date_from.year, date_from.month)[1]
    return (
        date_from.year == date_to.year
        and date_from.month == date_to.month
        and ((date_from.day == 1 and date_to.day == 15) or (date_from.day == 16 and date_to.day == last_day))
    )


def _stores(session, user):
    query = session.query(Shift.store, Shift.city).filter(Shift.store != None).distinct()
    query = _scope(query, Shift, user)
    return sorted({(row.store, row.city or "") for row in query.all()})


def _store_city(session, store):
    row = session.query(Shift.city).filter(Shift.store == normalize_text(store), Shift.city != None).first()
    return normalize_text(row[0]) if row else ""


def _filename_part(value, fallback):
    encoded = quote(normalize_text(value), safe="")
    return encoded[:120] or fallback


def _save_workbook(workbook, key):
    """Собрать книгу в памяти и положить в хранилище; вернуть ключ для БД."""
    buffer = BytesIO()
    workbook.save(buffer)
    return storage_save(key, buffer.getvalue(), content_type=XLSX_CONTENT_TYPE)


def _build_reconciliation_file(reconciliation, rows):
    safe_store = _filename_part(reconciliation.store, "store")
    filename = f"reconciliation_{safe_store}_{reconciliation.period_from}_{reconciliation.period_to}.xlsx"
    wb = Workbook()
    ws = wb.active
    ws.title = "Сверка"
    ws.append(["Магазин", reconciliation.store])
    ws.append(["Период", f"{reconciliation.period_from:%d.%m.%Y} - {reconciliation.period_to:%d.%m.%Y}"])
    ws.append([])
    ws.append(["ФИО", "Услуга", "Часы"])
    for cell in ws[4]:
        cell.font = Font(bold=True)
    service_totals = defaultdict(float)
    total = 0.0
    for employee, service, hours in rows:
        value = float(hours or 0)
        ws.append([employee, service, value])
        service_totals[service] += value
        total += value
    ws.append([])
    ws.append(["Итоги по услугам"])
    for service, hours in sorted(service_totals.items()):
        ws.append([service, None, hours])
    ws.append(["Общий итог", None, total])
    ws.column_dimensions["A"].width = 38
    ws.column_dimensions["B"].width = 48
    ws.column_dimensions["C"].width = 16
    reconciliation.file_path = _save_workbook(wb, f"{RECONCILIATION_PREFIX}/{filename}")


_monitoring_settings = get_monitoring_settings
_create_recommendation = create_recommendation


@router.get("/admin/employees", response_class=HTMLResponse)
@router.get("/economist/employees", response_class=HTMLResponse)
@router.get("/hr/employees", response_class=HTMLResponse)
def employees_dashboard(request: Request, user=Depends(require_employee_manager)):
    context = _context(request, user)
    context["groups"] = build_navigation(user, employees_groups(context["base_path"]))
    return templates.TemplateResponse(request, "employees_dashboard.html", context)


@router.get("/admin/employees/planning")
@router.get("/economist/employees/planning")
@router.get("/hr/employees/planning")
def planning_page_redirect():
    """Старый XLSX-бланк снят (П4.2): адреса ведут на новый БП, чтобы старые
    ссылки не давали 404."""
    return RedirectResponse("/admin/planning-bp", status_code=301)


@router.get("/admin/employees/monitoring", response_class=HTMLResponse)
@router.get("/economist/employees/monitoring", response_class=HTMLResponse)
@router.get("/hr/employees/monitoring", response_class=HTMLResponse)
def monitoring_page(request: Request, tab: str = "new", message: str = "", session: Session = Depends(get_db), user=Depends(require_employee_manager)):
    query = _scope(session.query(EmployeeMonitoringRecommendation), EmployeeMonitoringRecommendation, user)
    if tab == "inactive": query = query.filter(EmployeeMonitoringRecommendation.recommendation_type == "remove_from_planning")
    elif tab == "missing": query = query.filter(EmployeeMonitoringRecommendation.recommendation_type == "add_to_planning")
    elif tab != "all": query = query.filter(EmployeeMonitoringRecommendation.status == "new")
    rows = query.order_by(EmployeeMonitoringRecommendation.id.desc()).all()
    return templates.TemplateResponse(request, "employees_monitoring.html", _context(request, user, "monitoring", rows=rows, tab=tab, settings=_monitoring_settings(session), message=message))


@router.get("/admin/employees/monitoring/settings", response_class=HTMLResponse)
def monitoring_settings_page(request: Request, session: Session = Depends(get_db), user=Depends(_admin_settings)):
    return templates.TemplateResponse(request, "employees_monitoring.html", _context(request, user, "monitoring", rows=[], tab="settings", settings=_monitoring_settings(session), message=""))

@router.post("/admin/employees/monitoring/settings")
def monitoring_settings_save(request: Request, inactive_days: int = Form(...), minimum_shifts: int = Form(...), analysis_days: int = Form(...), session: Session = Depends(get_db), user=Depends(_admin_settings)):
    row = _monitoring_settings(session); row.inactive_days=max(inactive_days,1); row.minimum_shifts=max(minimum_shifts,1); row.analysis_days=max(analysis_days,1); row.updated_by=user.id; row.updated_at=now_utc(); session.commit()
    return _redirect(request, "/monitoring", message="Настройки сохранены")


@router.post("/admin/employees/monitoring/generate")
@router.post("/economist/employees/monitoring/generate")
@router.post("/hr/employees/monitoring/generate")
def monitoring_generate(request: Request, session: Session = Depends(get_db), user=Depends(require_employee_manager)):
    created = recompute_recommendations(session, request, user)
    return _redirect(request, "/monitoring", message=f"Создано рекомендаций: {created}")


@router.post("/admin/employees/monitoring/process")
@router.post("/economist/employees/monitoring/process")
@router.post("/hr/employees/monitoring/process")
def monitoring_process(request: Request, recommendation_id: int = Form(...), status: str = Form(...), session: Session = Depends(get_db), user=Depends(require_employee_manager)):
    row = session.query(EmployeeMonitoringRecommendation).filter(EmployeeMonitoringRecommendation.id == recommendation_id).first()
    if row and _scope_allowed(session, user, row.city, row.store) and status in {"accepted", "dismissed"}: row.status=status; row.processed_by=user.id; row.processed_at=now_utc(); session.commit()
    return _redirect(request, "/monitoring", message="Рекомендация обработана")


def _dismissal_candidates(session, user):
    """Пропавшие со смен: последняя смена старше порога inactive_days. Кадровое,
    показываем ВСЕХ (в БП или нет), с последней сменой, магазином и гражданством."""
    settings = _monitoring_settings(session)
    today = business_today()
    cutoff = today - timedelta(days=settings.inactive_days)

    query = _scope(session.query(Shift.employee, Shift.shift_date, Shift.store, Shift.city), Shift, user)
    last = {}
    for employee, day, store, city in query.all():
        if not employee or not day:
            continue
        current = last.get(employee)
        if current is None or day > current[0]:
            last[employee] = (day, store, city)

    disappeared = [(emp, d, store, city) for emp, (d, store, city) in last.items() if d <= cutoff]
    disappeared.sort(key=lambda item: item[1])  # раньше пропавшие — выше

    names = {normalize_text(emp) for emp, *_ in disappeared}
    users = {
        normalize_text(u.employee_name): u
        for u in session.query(User).all() if normalize_text(u.employee_name) in names
    }
    decisions = {normalize_text(d.employee_name): d for d in session.query(EmployeeDismissalDecision).all()}

    contracts = _active_contracts(session, today)

    rows = []
    for employee, day, store, city in disappeared:
        key = normalize_text(employee)
        person = users.get(key)
        decision = decisions.get(key)
        rows.append({
            "employee_name": employee, "last_date": day, "store": store, "city": city,
            "days_ago": (today - day).days,
            "citizenship": citizenship_display(session, person) if person else "",
            "decision": decision.decision if decision else None,
            "decision_comment": decision.comment if decision else "",
            "contract": contracts.get(normalize_person_name(employee)),
        })

    # П4: «есть действующий договор, нет смен inactive_days дней» — в том числе
    # никогда не выходившие на смены после договора.
    listed = {normalize_person_name(row["employee_name"]) for row in rows}
    last_by_key = {normalize_person_name(emp): data for emp, data in last.items()}
    for key, contract in contracts.items():
        if key in listed:
            continue
        last_shift = last_by_key.get(key)
        if last_shift and last_shift[0] > cutoff:
            continue
        person = session.get(User, contract.user_id) if contract.user_id else None
        decision = decisions.get(normalize_text(contract.employee_name))
        rows.append({
            "employee_name": contract.employee_name,
            "last_date": last_shift[0] if last_shift else None,
            "store": last_shift[1] if last_shift else None,
            "city": last_shift[2] if last_shift else None,
            "days_ago": (today - last_shift[0]).days if last_shift else None,
            "citizenship": citizenship_display(session, person) if person else "",
            "decision": decision.decision if decision else None,
            "decision_comment": decision.comment if decision else "",
            "contract": contract,
        })
    return rows, settings


def _active_contracts(session, today):
    """{ФИО: последний действующий ТРУДОВОЙ ДОГОВОР} — не в архиве, не отклонён, не истёк."""
    from employee_profile import DOC_CONTRACT

    doc_type = session.query(DocumentType).filter(DocumentType.name == DOC_CONTRACT).first()
    if doc_type is None:
        return {}
    result = {}
    for doc in session.query(EmployeeDocument).filter(
        EmployeeDocument.document_type_id == doc_type.id,
        EmployeeDocument.status.notin_(["archived", "rejected"]),
    ).order_by(EmployeeDocument.issue_date.asc(), EmployeeDocument.id.asc()).all():
        if doc.expiry_date and not doc.is_permanent and doc.expiry_date < today:
            continue
        result[normalize_person_name(doc.employee_name)] = doc
    return result


@router.get("/admin/employees/dismissals", response_class=HTMLResponse)
@router.get("/economist/employees/dismissals", response_class=HTMLResponse)
@router.get("/hr/employees/dismissals", response_class=HTMLResponse)
def dismissals_page(request: Request, message: str = "", session: Session = Depends(get_db), user=Depends(require_employee_manager)):
    rows, settings = _dismissal_candidates(session, user)
    return templates.TemplateResponse(request, "employees_dismissals.html", _context(request, user, "dismissals", rows=rows, settings=settings, message=message))


@router.post("/admin/employees/dismissals/decide")
@router.post("/economist/employees/dismissals/decide")
@router.post("/hr/employees/dismissals/decide")
def dismissals_decide(request: Request, employee_name: str = Form(...), decision: str = Form(...), comment: str = Form(default=""), session: Session = Depends(get_db), user=Depends(require_employee_manager)):
    if decision not in {"dismiss", "keep"}:
        return _redirect(request, "/dismissals")
    key = normalize_text(employee_name)
    row = session.query(EmployeeDismissalDecision).filter(EmployeeDismissalDecision.employee_name == key).first()
    if not row:
        row = EmployeeDismissalDecision(employee_name=key)
        session.add(row)
    row.decision = decision
    row.comment = normalize_text(comment) or None
    row.decided_by = user.id
    row.decided_at = now_utc()
    session.flush()
    create_audit_log(session, request, user, "dismissal_decision", "employee_dismissal_decision", row.id, key, new_value={"decision": decision})
    session.commit()
    message = "Решение сохранено"
    if decision == "dismiss" and _active_contracts(session, business_today()).get(normalize_person_name(key)):
        message += " — у сотрудника действующий договор: архивируйте его с датой увольнения"
    return _redirect(request, "/dismissals", message=message)


@router.post("/admin/employees/dismissals/archive-contract")
@router.post("/economist/employees/dismissals/archive-contract")
@router.post("/hr/employees/dismissals/archive-contract")
def dismissals_archive_contract(request: Request, document_id: int = Form(...), dismissed_on: str = Form(default=""), session: Session = Depends(get_db), user=Depends(require_employee_manager)):
    """П4: при увольнении — договор в архив с датой."""
    document = session.get(EmployeeDocument, document_id)
    if document is None or document.status == "archived":
        return _redirect(request, "/dismissals", message="Договор не найден или уже в архиве")
    try:
        day = _parse_date(dismissed_on)
    except ValueError:
        day = business_today()
    old_value = {"status": document.status, "comment": document.comment}
    document.status = "archived"
    document.comment = f"Уволен {day:%d.%m.%Y}" + (f". {document.comment}" if document.comment else "")
    document.updated_at = now_utc()
    create_audit_log(session, request, user, "document_archived", "employee_document", document.id, document.employee_name,
                     old_value=old_value, new_value={"status": "archived", "dismissed_on": day.isoformat()},
                     comment="увольнение")
    session.commit()
    return _redirect(request, "/dismissals", message=f"Договор архивирован ({day:%d.%m.%Y})")


@router.get("/admin/employees/reconciliations", response_class=HTMLResponse)
@router.get("/economist/employees/reconciliations", response_class=HTMLResponse)
@router.get("/hr/employees/reconciliations", response_class=HTMLResponse)
def reconciliations_page(request: Request, message: str = "", session: Session = Depends(get_db), user=Depends(require_employee_manager)):
    rows = _scope(session.query(StoreReconciliation), StoreReconciliation, user).order_by(StoreReconciliation.id.desc()).all()
    settings = _scope(session.query(StoreReconciliationSettings), StoreReconciliationSettings, user).order_by(StoreReconciliationSettings.store).all()
    formats = store_formats(session)
    # П4.2: сверки — только для ГМ; СМ в списке магазинов не предлагаем.
    stores = [item for item in _stores(session, user) if allows_bp(formats.get(item[0]))]
    return templates.TemplateResponse(request, "employees_reconciliations.html", _context(request, user, "reconciliations", rows=rows, settings=settings, stores=stores, message=message))


@router.post("/admin/employees/reconciliations/settings")
@router.post("/economist/employees/reconciliations/settings")
@router.post("/hr/employees/reconciliations/settings")
def reconciliation_settings(request: Request, store: str = Form(...), email: str = Form(default=""), enabled: str = Form(default=""), comment: str = Form(default=""), session: Session = Depends(get_db), user=Depends(require_employee_manager)):
    if not allows_bp(store_formats(session).get(normalize_text(store))): return _redirect(request,"/reconciliations",message="Сверки ведутся только для формата ГМ")
    city=_store_city(session,store)
    if not _scope_allowed(session,user,city,store): return _redirect(request,"/reconciliations",message="Нет доступа к городу")
    row=session.query(StoreReconciliationSettings).filter(StoreReconciliationSettings.store==normalize_text(store)).first() or StoreReconciliationSettings(store=normalize_text(store)); session.add(row); row.city=city; row.email=normalize_text(email) or None; row.enabled=enabled=="1"; row.comment=normalize_text(comment) or None; session.commit()
    return _redirect(request,"/reconciliations",message="Настройки сохранены")


@router.post("/admin/employees/reconciliations/generate")
@router.post("/economist/employees/reconciliations/generate")
@router.post("/hr/employees/reconciliations/generate")
def reconciliation_generate(request: Request, store: str = Form(...), date_from: str = Form(...), date_to: str = Form(...), session: Session = Depends(get_db), user=Depends(require_employee_manager)):
    if not allows_bp(store_formats(session).get(normalize_text(store))): return _redirect(request,"/reconciliations",message="Сверки ведутся только для формата ГМ")
    city=_store_city(session,store)
    if not _scope_allowed(session,user,city,store): return _redirect(request,"/reconciliations",message="Нет доступа к городу")
    start,end=_parse_date(date_from),_parse_date(date_to)
    if not is_fixed_reconciliation_period(start,end):return _redirect(request,"/reconciliations",message="Допустимы только периоды 01–15 или 16–конец месяца")
    if business_today() < reconciliation_ready_date(end):return _redirect(request,"/reconciliations",message=f"Сверку можно сформировать с {reconciliation_ready_date(end):%d.%m.%Y}")
    existing=session.query(StoreReconciliation).filter(StoreReconciliation.store==normalize_text(store),StoreReconciliation.period_from==start,StoreReconciliation.period_to==end).first()
    if existing:return _redirect(request,"/reconciliations",message="Сверка за период уже существует")
    data=session.query(Shift.employee,Shift.service,func.sum(Shift.hours)).filter(Shift.store==normalize_text(store),Shift.shift_date>=start,Shift.shift_date<=end).group_by(Shift.employee,Shift.service).order_by(Shift.employee,Shift.service).all()
    row=StoreReconciliation(store=normalize_text(store),city=city,period_from=start,period_to=end,status="generated",created_at=now_utc()); session.add(row);session.flush();_build_reconciliation_file(row,data);create_audit_log(session,request,user,"reconciliation_generated","store_reconciliation",row.id,row.store);session.commit()
    return _redirect(request,"/reconciliations",message="Сверка сформирована")


def _reconciliation(session,user,row_id):
    row=session.query(StoreReconciliation).filter(StoreReconciliation.id==row_id).first(); return row if row and _scope_allowed(session,user,row.city,row.store) else None


@router.get("/admin/employees/reconciliations/{row_id}/download")
@router.get("/economist/employees/reconciliations/{row_id}/download")
@router.get("/hr/employees/reconciliations/{row_id}/download")
def reconciliation_download(row_id:int,session:Session=Depends(get_db),user=Depends(require_employee_manager)):
    row=_reconciliation(session,user,row_id)
    if not row:return RedirectResponse("/",status_code=302)
    return storage_response(row.file_path,filename=Path(row.file_path or "").name) or RedirectResponse("/",status_code=302)


@router.post("/admin/employees/reconciliations/{row_id}/{action}")
@router.post("/economist/employees/reconciliations/{row_id}/{action}")
@router.post("/hr/employees/reconciliations/{row_id}/{action}")
def reconciliation_action(request:Request,row_id:int,action:str,session:Session=Depends(get_db),user=Depends(require_employee_manager)):
    row=_reconciliation(session,user,row_id)
    if row and action in {"ready","sent"}: row.status="ready_to_send" if action=="ready" else "sent"; row.sent_at=now_utc() if action=="sent" else None; create_audit_log(session,request,user,"reconciliation_sent" if action=="sent" else "reconciliation_ready","store_reconciliation",row.id,row.store);session.commit()
    return _redirect(request,"/reconciliations",message="Статус сверки обновлён")


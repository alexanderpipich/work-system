"""Договоры (П4): список сотрудников с договорами и патентами, создание договора,
ходатайства и рекомендательного письма (П4.11) по шаблонам с проверкой полноты данных."""

import json
import re
from datetime import datetime

from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session

from audit_helpers import create_audit_log
from contract_data import (contract_document_type, contract_fields, default_legal_entity, document_legal_entities,
                           format_rate, needs_patent, petition_fields, recent_work, recommendation_fields, regions, save_fixes, suggest_contract_number)
from contract_generator import TemplateMismatch, generate_contract, generate_petition, generate_recommendation
from dependencies import RedirectException, current_user, get_db
from document_helpers import preview_kind
from employee_profile import (DOC_CONTRACT, DOC_PATENT, DOC_PETITION, DOC_RECOMMENDATION, employee_profile,
                              patent_expiry)
from file_storage import storage_response, storage_save
from models import Country, DocumentType, EmployeeDocument, LegalEntity, MvdAuthority, Region, Shift, User
from mvd_authorities import active_authorities, authority_for_work
from rbac import ROLE_EMPLOYEE, TM_ROLE_VALUES, has_permission
from time_helpers import business_today, now_utc
from utils import normalize_person_name, normalize_text

router = APIRouter()
templates = Jinja2Templates(directory="templates")
templates.env.globals["preview_kind"] = preview_kind

DOCX_CONTENT_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
EXPIRING_DAYS = 30
INACTIVE = {"archived", "rejected"}
KINDS = {"contract", "petition", "recommendation"}
DOC_TYPES = {"contract": DOC_CONTRACT, "petition": DOC_PETITION, "recommendation": DOC_RECOMMENDATION}
TITLES = {"contract": "Договор", "petition": "Ходатайство", "recommendation": "Рекомендация"}
DOCUMENT_TYPES_FILE = Path(__file__).resolve().parent.parent / "data" / "reference" / "document_types.json"


def require_contracts_view(user=Depends(current_user)):
    if not has_permission(user, "contracts.view"):
        raise RedirectException("/")
    return user


def require_contracts_manage(user=Depends(current_user)):
    if not has_permission(user, "contracts.manage"):
        raise RedirectException("/admin/contracts")
    return user


def _latest_docs_by_user(session, type_name):
    doc_type = session.query(DocumentType).filter(DocumentType.name == type_name).first()
    if doc_type is None:
        return {}
    docs = session.query(EmployeeDocument).filter(
        EmployeeDocument.document_type_id == doc_type.id,
        EmployeeDocument.status.notin_(INACTIVE),
    ).order_by(EmployeeDocument.uploaded_at.asc(), EmployeeDocument.id.asc()).all()
    result = {}
    for doc in docs:
        result[doc.user_id or normalize_person_name(doc.employee_name)] = doc
    return result


def contract_state(doc, today):
    """(код, подпись, дней до окончания) для договора."""
    if doc is None:
        return "none", "нет", None
    if doc.is_permanent or not doc.expiry_date:
        return "permanent", "бессрочный", None
    days = (doc.expiry_date - today).days
    if days < 0:
        return "expired", f"истёк {doc.expiry_date:%d.%m.%Y}", days
    if days <= EXPIRING_DAYS:
        return "expiring", f"истекает через {days} дн. ({doc.expiry_date:%d.%m.%Y})", days
    return "active", f"до {doc.expiry_date:%d.%m.%Y}", days


def contracts_rows(session, today):
    """Пакетно: все сотрудники, договор, патент, последняя смена (без N+1)."""
    users = session.query(User).filter(User.role == ROLE_EMPLOYEE).all()
    countries = {c.id: c.name for c in session.query(Country).all()}
    tms = {u.id: u.employee_name for u in session.query(User).filter(User.role.in_(TM_ROLE_VALUES)).all()}
    contracts = _latest_docs_by_user(session, DOC_CONTRACT)
    patents = _latest_docs_by_user(session, DOC_PATENT)
    last_shift = {
        normalize_person_name(name): day
        for name, day in session.query(Shift.employee, func.max(Shift.shift_date)).group_by(Shift.employee).all()
    }
    rows = []
    for user in users:
        key = normalize_person_name(user.employee_name)
        contract = contracts.get(user.id) or contracts.get(key)
        patent = patents.get(user.id) or patents.get(key)
        state, label, days = contract_state(contract, today)
        expiry, computed = patent_expiry(patent)
        rows.append({
            "user": user,
            "tm_name": tms.get(user.tm_id, ""),
            "country": countries.get(user.citizenship_country_id, ""),
            "contract": contract,
            "state": state,
            "state_label": label,
            "days": days,
            "patent": patent,
            "patent_expiry": expiry,
            "patent_expiry_computed": computed,
            "last_shift": last_shift.get(key),
        })

    def order(row):
        has_shifts = row["last_shift"] is not None
        if has_shifts and row["state"] == "none":
            group = 0
        elif row["state"] in {"expiring", "expired"}:
            group = 1
        else:
            group = 2
        return (group, row["days"] if row["days"] is not None else 10_000, normalize_person_name(row["user"].employee_name))

    rows.sort(key=order)
    return rows


@router.get("/admin/contracts", response_class=HTMLResponse)
def contracts_page(
    request: Request,
    q: str = "",
    has_contract: str = "",
    expiring: str = "",
    tm: int = 0,
    message: str = "",
    error: str = "",
    session: Session = Depends(get_db),
    user=Depends(require_contracts_view),
):
    today = business_today()
    rows = contracts_rows(session, today)
    names = [r["user"].employee_name for r in rows]
    if normalize_text(q):
        needle = normalize_person_name(q)
        rows = [r for r in rows if needle in normalize_person_name(r["user"].employee_name)]
    if has_contract == "1":
        rows = [r for r in rows if r["state"] != "none"]
    elif has_contract == "0":
        rows = [r for r in rows if r["state"] == "none"]
    if expiring:
        rows = [r for r in rows if r["state"] in {"expiring", "expired"}]
    if tm:
        rows = [r for r in rows if r["user"].tm_id == tm]
    return templates.TemplateResponse(request, "contracts.html", {
        "rows": rows,
        "names": sorted(names),
        "tm_options": session.query(User).filter(User.role.in_(TM_ROLE_VALUES)).order_by(User.employee_name).all(),
        "filters": {"q": q, "has_contract": has_contract, "expiring": expiring, "tm": tm},
        "can_manage": has_permission(user, "contracts.manage"),
        "can_check_expiry": has_permission(user, "documents.manage"),
        "message": message or None,
        "error": error or None,
    })


# ── Форма договора / ходатайства ─────────────────────────────────────────────

def _date(value):
    try:
        return datetime.strptime(normalize_text(value), "%Y-%m-%d").date() if normalize_text(value) else None
    except ValueError:
        return None


def _form_values(source):
    """Значения формы (ввод) из query/form."""
    get = source.get
    return {
        "contract_number": normalize_text(get("contract_number")),
        "contract_date": _date(get("contract_date")),
        "effective_date": _date(get("effective_date")),
        "start_date": _date(get("start_date")),
        "term_until": _date(get("term_until")),
        "term_indefinite": get("term_indefinite") == "1",
        "rate": normalize_text(get("rate")),
        "city": normalize_text(get("city")),
        "position": normalize_text(get("position")),
        "petition_date": _date(get("petition_date")),
        "recommendation_date": _date(get("recommendation_date")),
        "legal_entity_id": int(get("legal_entity_id") or 0),
        "region_id": int(get("region_id") or 0),
        "mvd_authority_id": int(get("mvd_authority_id") or 0),
    }


def _context(session, employee, kind, form):
    profile = employee_profile(session, employee)
    entity = session.get(LegalEntity, form["legal_entity_id"]) if form["legal_entity_id"] else default_legal_entity(session, profile)
    region = session.get(Region, form["region_id"]) if form["region_id"] else profile["region"]
    today = business_today()
    errors = []
    # Магазин (адрес в бланке) и ЧТС — по сменам за 14 дней.
    work = recent_work(session, employee, today)
    if kind != "petition" and not form["city"] and region and region.patent_territory:
        form["city"] = region.patent_territory
    authority = None
    authority_auto = authority_hint = None
    if kind == "petition":
        form["petition_date"] = form["petition_date"] or today
        # Адресат — подразделение МВД: по основному магазину за 14 дней, ручной выбор в форме главнее.
        authority_auto, authority_hint = authority_for_work(session, work, region)
        authority = session.get(MvdAuthority, form["mvd_authority_id"]) if form["mvd_authority_id"] else authority_auto
        fields, values = petition_fields(session, profile, entity, region, form, work, authority, authority_hint)
        with_patent = True
    elif kind == "recommendation":
        form["recommendation_date"] = form["recommendation_date"] or today
        fields, values = recommendation_fields(session, profile, entity, form, work)
        with_patent = needs_patent(session, profile)
    else:
        form["contract_date"] = form["contract_date"] or today
        form["contract_number"] = form["contract_number"] or suggest_contract_number(session, form["contract_date"])
        with_patent = needs_patent(session, profile)
        # При патенте договор только срочный: срок по умолчанию — окончание патента (П4.11 A1).
        if with_patent:
            form["term_until"] = form["term_until"] or profile["patent_expiry"]
        elif not form["term_until"] and not form["term_indefinite"]:
            form["term_indefinite"] = True
        # Ставка подставляется, только если поле пустое.
        if not form["rate"] and work and work["rate"]:
            form["rate"] = format_rate(work["rate"])
        fields, values, errors, with_patent = contract_fields(session, profile, entity, region, form, work)
        if with_patent:
            form["term_indefinite"] = False
    return {
        "profile": profile,
        "entity": entity,
        "region": region,
        "fields": fields,
        "values": values,
        "errors": errors,
        "missing": [f for f in fields if f["missing"]],
        "with_patent": with_patent,
        "work": work,
        "authority": authority,
        "authority_auto": authority_auto,
        "authority_hint": authority_hint,
        "authorities": active_authorities(session) if kind == "petition" else [],
        "form": form,
        "legal_entities": document_legal_entities(session),
        "regions": regions(session),
    }


def _render_form(request, session, employee, kind, form, message="", error=""):
    context = _context(session, employee, kind, form)
    return templates.TemplateResponse(request, "contract_form.html", {
        **context, "kind": kind, "employee": employee, "message": message or None, "error": error or None,
    })


@router.get("/admin/contracts/{kind}/{user_id}", response_class=HTMLResponse)
def contract_form(request: Request, kind: str, user_id: int, session: Session = Depends(get_db),
                  user=Depends(require_contracts_manage)):
    employee = session.get(User, user_id)
    if kind not in KINDS or employee is None:
        return RedirectResponse("/admin/contracts?error=" + "Сотрудник не найден", 302)
    return _render_form(request, session, employee, kind, _form_values(request.query_params))


def _document_type(session, type_name):
    """Тип документа; рекомендательное письмо (П4.11) заводится сам — из справочника
    data/reference/document_types.json, чтобы на проде не ждать прогона seed."""
    doc_type = contract_document_type(session, type_name)
    if doc_type is None and type_name == DOC_RECOMMENDATION:
        spec = next(t for t in json.loads(DOCUMENT_TYPES_FILE.read_text(encoding="utf-8")) if t["name"] == type_name)
        doc_type = DocumentType(**{key: value for key, value in spec.items() if hasattr(DocumentType, key)})
        session.add(doc_type)
        session.flush()
    return doc_type


def _safe_filename(text):
    return re.sub(r"[^\w.-]+", "_", normalize_text(text)).strip("_")[:60] or "employee"


@router.post("/admin/contracts/{kind}/{user_id}")
async def contract_submit(request: Request, kind: str, user_id: int, session: Session = Depends(get_db),
                          user=Depends(require_contracts_manage)):
    employee = session.get(User, user_id)
    if kind not in KINDS or employee is None:
        return RedirectResponse("/admin/contracts", 302)
    raw = await request.form()
    form = _form_values(raw)
    action = raw.get("action", "check")

    # Недостающее, введённое на месте, — в источник (сотрудник, документ, юрлицо, регион).
    fixes = {key[len("fix:"):]: value for key, value in raw.items() if key.startswith("fix:")}
    profile = employee_profile(session, employee)
    entity = session.get(LegalEntity, form["legal_entity_id"]) if form["legal_entity_id"] else default_legal_entity(session, profile)
    region = session.get(Region, form["region_id"]) if form["region_id"] else profile["region"]
    authority = None
    if any(key.startswith("mvd:") for key in fixes):
        # Адресат ходатайства — в карточку выбранного (или подобранного) подразделения МВД.
        authority = (session.get(MvdAuthority, form["mvd_authority_id"]) if form["mvd_authority_id"] else
                     authority_for_work(session, recent_work(session, employee, business_today()), region)[0])
    saved = save_fixes(session, request, user, employee, entity, region, fixes, authority) if fixes else 0
    session.commit()

    context = _context(session, employee, kind, form)
    if context["errors"]:
        return _render_form(request, session, employee, kind, form, error="; ".join(context["errors"]))
    if action == "check" or (context["missing"] and action != "generate_skip"):
        message = f"Сохранено полей: {saved}" if saved else ""
        error = "Не хватает данных — заполните или сгенерируйте с «НЕТ ДАННЫХ»" if context["missing"] and action != "check" else ""
        return _render_form(request, session, employee, kind, form, message=message, error=error)

    try:
        if kind == "petition":
            content, missing = generate_petition(context["values"], allow_missing=True)
        elif kind == "recommendation":
            content, missing = generate_recommendation(context["values"], allow_missing=True)
        else:
            content, missing = generate_contract(context["values"], allow_missing=True, with_patent=context["with_patent"])
    except TemplateMismatch as exc:
        return _render_form(request, session, employee, kind, form, error=f"Шаблон не совпал с картой подстановок: {exc}")

    doc_date = {"petition": form["petition_date"], "recommendation": form["recommendation_date"]}.get(kind, form["contract_date"])
    type_name = DOC_TYPES[kind]
    doc_type = _document_type(session, type_name)
    if doc_type is None:
        return _render_form(request, session, employee, kind, form,
                            error=f"Нет типа документа «{type_name}» — загрузите справочники (seed_reference_data.py)")
    title = TITLES[kind]
    filename = f"{title}_{doc_date:%Y-%m-%d}_{_safe_filename(employee.employee_name)}.docx"
    key = storage_save(f"generated_files/contracts/{employee.id}/{now_utc():%Y%m%d-%H%M%S}_{filename}",
                       content, content_type=DOCX_CONTENT_TYPE)
    document = EmployeeDocument(
        user_id=employee.id,
        employee_name=employee.employee_name,
        document_type_id=doc_type.id,
        document_number=form["contract_number"] if kind == "contract" else None,
        issue_date=doc_date,
        expiry_date=form["term_until"] if kind == "contract" and not form["term_indefinite"] else None,
        is_permanent=kind == "contract" and form["term_indefinite"],
        extra_field_1_value=context["entity"].name if kind != "petition" and context["entity"] else None,
        extra_field_2_value=context["values"].get("position") if kind == "contract" else None,
        file_path=key,
        original_filename=filename,
        status="uploaded",
        uploaded_by=user.id,
        uploaded_at=now_utc(),
        comment=("Сгенерирован; НЕТ ДАННЫХ: " + ", ".join(missing)) if missing else "Сгенерирован",
    )
    session.add(document)
    session.flush()
    create_audit_log(session, request, user, f"{kind}.generated",
                     "employee_document", document.id, employee.employee_name,
                     new_value={"type": type_name, "number": document.document_number, "missing": missing,
                                "legal_entity": document.extra_field_1_value,
                                "region": context["region"].name if context["region"] else None})
    session.commit()
    return storage_response(key, filename=filename) or RedirectResponse("/admin/contracts", 302)

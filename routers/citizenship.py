from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from audit_helpers import create_audit_log
from dependencies import get_db
from document_helpers import employee_document_status, employee_names
from models import CitizenshipRegime, Country, DocumentType, RegimeDocumentRule, User
from rbac import canonical_role, require_permission
from utils import normalize_text

router = APIRouter()
templates = Jinja2Templates(directory="templates")

_mgmt = require_permission("admin.settings")


# ── Режимы ───────────────────────────────────────────────────────────────────

@router.get("/admin/citizenship/regimes", response_class=HTMLResponse)
def regimes_list(request: Request, session: Session = Depends(get_db), user=Depends(_mgmt)):
    regimes = session.query(CitizenshipRegime).order_by(CitizenshipRegime.sort_order, CitizenshipRegime.id).all()
    return templates.TemplateResponse(request, "citizenship_regimes.html", {
        "user": user, "regimes": regimes, "message": request.query_params.get("message"),
    })


@router.get("/admin/citizenship/regimes/add", response_class=HTMLResponse)
def regime_add_form(request: Request, session: Session = Depends(get_db), user=Depends(_mgmt)):
    return templates.TemplateResponse(request, "citizenship_regime_edit.html", {
        "user": user, "regime": None, "doc_types": [], "checked_ids": set(), "error": None,
    })


@router.post("/admin/citizenship/regimes/add")
def regime_add(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_mgmt),
    code: str = Form(""),
    name: str = Form(""),
    description: str = Form(""),
    sort_order: int = Form(0),
    is_active: str = Form("1"),
    required_doc_ids: list[int] = Form(default=[]),
):
    code = normalize_text(code)
    name = normalize_text(name)
    if not code or not name:
        doc_types = session.query(DocumentType).filter(DocumentType.is_active == True).order_by(DocumentType.sort_order, DocumentType.name).all()
        return templates.TemplateResponse(request, "citizenship_regime_edit.html", {
            "user": user, "regime": None, "doc_types": doc_types,
            "checked_ids": set(required_doc_ids), "error": "Код и название обязательны",
        })

    regime = CitizenshipRegime(
        code=code, name=name,
        description=normalize_text(description) or None,
        sort_order=sort_order,
        is_active=is_active == "1",
    )
    session.add(regime)
    session.flush()
    for dt_id in required_doc_ids:
        session.add(RegimeDocumentRule(regime_id=regime.id, document_type_id=dt_id, is_required=True))
    create_audit_log(session, request, user, "create", "citizenship_regime", entity_id=regime.id, entity_name=name)
    session.commit()
    return RedirectResponse(f"/admin/citizenship/regimes?message=Режим+добавлен", status_code=303)


@router.get("/admin/citizenship/regimes/{regime_id}/edit", response_class=HTMLResponse)
def regime_edit_form(regime_id: int, request: Request, session: Session = Depends(get_db), user=Depends(_mgmt)):
    regime = session.query(CitizenshipRegime).filter(CitizenshipRegime.id == regime_id).first()
    if not regime:
        return RedirectResponse("/admin/citizenship/regimes", status_code=302)
    doc_types = session.query(DocumentType).filter(DocumentType.is_active == True).order_by(DocumentType.sort_order, DocumentType.name).all()
    checked_ids = {
        r.document_type_id
        for r in session.query(RegimeDocumentRule).filter(
            RegimeDocumentRule.regime_id == regime_id,
            RegimeDocumentRule.is_required == True,
        ).all()
    }
    return templates.TemplateResponse(request, "citizenship_regime_edit.html", {
        "user": user, "regime": regime, "doc_types": doc_types, "checked_ids": checked_ids, "error": None,
    })


@router.post("/admin/citizenship/regimes/{regime_id}/edit")
def regime_edit_save(
    regime_id: int,
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_mgmt),
    code: str = Form(""),
    name: str = Form(""),
    description: str = Form(""),
    sort_order: int = Form(0),
    is_active: str = Form("1"),
    required_doc_ids: list[int] = Form(default=[]),
):
    regime = session.query(CitizenshipRegime).filter(CitizenshipRegime.id == regime_id).first()
    if not regime:
        return RedirectResponse("/admin/citizenship/regimes", status_code=302)

    code = normalize_text(code)
    name = normalize_text(name)
    if not code or not name:
        doc_types = session.query(DocumentType).filter(DocumentType.is_active == True).order_by(DocumentType.sort_order, DocumentType.name).all()
        checked_ids = set(required_doc_ids)
        return templates.TemplateResponse(request, "citizenship_regime_edit.html", {
            "user": user, "regime": regime, "doc_types": doc_types,
            "checked_ids": checked_ids, "error": "Код и название обязательны",
        })

    regime.code = code
    regime.name = name
    regime.description = normalize_text(description) or None
    regime.sort_order = sort_order
    regime.is_active = is_active == "1"

    # Пересохранить матрицу документов
    existing = {r.document_type_id: r for r in session.query(RegimeDocumentRule).filter(RegimeDocumentRule.regime_id == regime_id).all()}
    all_type_ids = {dt.id for dt in session.query(DocumentType.id).all()}
    for dt_id in all_type_ids:
        is_req = dt_id in required_doc_ids
        if dt_id in existing:
            existing[dt_id].is_required = is_req
        elif is_req:
            session.add(RegimeDocumentRule(regime_id=regime_id, document_type_id=dt_id, is_required=True))

    create_audit_log(session, request, user, "update", "citizenship_regime", entity_id=regime_id, entity_name=name)
    session.commit()
    return RedirectResponse(f"/admin/citizenship/regimes?message=Режим+сохранён", status_code=303)


@router.post("/admin/citizenship/regimes/{regime_id}/toggle")
def regime_toggle(regime_id: int, request: Request, session: Session = Depends(get_db), user=Depends(_mgmt)):
    regime = session.query(CitizenshipRegime).filter(CitizenshipRegime.id == regime_id).first()
    if regime:
        regime.is_active = not regime.is_active
        create_audit_log(session, request, user, "toggle", "citizenship_regime", entity_id=regime_id, entity_name=regime.name)
        session.commit()
    return RedirectResponse("/admin/citizenship/regimes", status_code=303)


# ── Страны ───────────────────────────────────────────────────────────────────

@router.get("/admin/citizenship/countries", response_class=HTMLResponse)
def countries_list(request: Request, session: Session = Depends(get_db), user=Depends(_mgmt)):
    countries = session.query(Country).order_by(Country.name).all()
    regimes = {r.id: r for r in session.query(CitizenshipRegime).all()}
    return templates.TemplateResponse(request, "citizenship_countries.html", {
        "user": user, "countries": countries, "regimes": regimes,
        "message": request.query_params.get("message"),
    })


@router.get("/admin/citizenship/countries/add", response_class=HTMLResponse)
def country_add_form(request: Request, session: Session = Depends(get_db), user=Depends(_mgmt)):
    regimes = session.query(CitizenshipRegime).filter(CitizenshipRegime.is_active == True).order_by(CitizenshipRegime.sort_order).all()
    return templates.TemplateResponse(request, "citizenship_country_edit.html", {
        "user": user, "country": None, "regimes": regimes, "error": None,
    })


@router.post("/admin/citizenship/countries/add")
def country_add(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_mgmt),
    name: str = Form(""),
    regime_id: int = Form(0),
    is_active: str = Form("1"),
):
    name = normalize_text(name)
    if not name or not regime_id:
        regimes = session.query(CitizenshipRegime).filter(CitizenshipRegime.is_active == True).order_by(CitizenshipRegime.sort_order).all()
        return templates.TemplateResponse(request, "citizenship_country_edit.html", {
            "user": user, "country": None, "regimes": regimes, "error": "Название и режим обязательны",
        })
    country = Country(name=name, regime_id=regime_id, is_active=is_active == "1")
    session.add(country)
    session.flush()
    create_audit_log(session, request, user, "create", "country", entity_id=country.id, entity_name=name)
    session.commit()
    return RedirectResponse("/admin/citizenship/countries?message=Страна+добавлена", status_code=303)


@router.get("/admin/citizenship/countries/bulk-add", response_class=HTMLResponse)
def country_bulk_add_form(request: Request, session: Session = Depends(get_db), user=Depends(_mgmt)):
    regimes = session.query(CitizenshipRegime).filter(
        CitizenshipRegime.is_active == True
    ).order_by(CitizenshipRegime.sort_order).all()
    return templates.TemplateResponse(request, "citizenship_country_bulk_add.html", {
        "user": user, "regimes": regimes, "error": None, "result": None,
    })


@router.post("/admin/citizenship/countries/bulk-add")
def country_bulk_add(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_mgmt),
    names_text: str = Form(""),
    regime_id: int = Form(0),
):
    regimes = session.query(CitizenshipRegime).filter(
        CitizenshipRegime.is_active == True
    ).order_by(CitizenshipRegime.sort_order).all()

    if not regime_id:
        return templates.TemplateResponse(request, "citizenship_country_bulk_add.html", {
            "user": user, "regimes": regimes, "error": "Выберите режим", "result": None,
        })

    names = [normalize_text(line) for line in names_text.splitlines() if normalize_text(line)]
    if not names:
        return templates.TemplateResponse(request, "citizenship_country_bulk_add.html", {
            "user": user, "regimes": regimes, "error": "Список стран пуст", "result": None,
        })

    existing = {normalize_text(c.name) for c in session.query(Country).all()}
    added, skipped = [], []
    for name in names:
        if normalize_text(name) in existing:
            skipped.append(name)
        else:
            session.add(Country(name=name, regime_id=regime_id, is_active=True))
            added.append(name)

    if added:
        session.flush()
        create_audit_log(
            session, request, user, "bulk_create", "country",
            entity_name=f"{len(added)} стран → режим {regime_id}",
            new_value={"added": added, "skipped": skipped},
        )
    session.commit()

    regime_name = next((r.name for r in regimes if r.id == regime_id), str(regime_id))
    return templates.TemplateResponse(request, "citizenship_country_bulk_add.html", {
        "user": user, "regimes": regimes, "error": None,
        "result": {
            "added": added, "skipped": skipped,
            "regime_name": regime_name,
        },
    })


@router.get("/admin/citizenship/countries/{country_id}/edit", response_class=HTMLResponse)
def country_edit_form(country_id: int, request: Request, session: Session = Depends(get_db), user=Depends(_mgmt)):
    country = session.query(Country).filter(Country.id == country_id).first()
    if not country:
        return RedirectResponse("/admin/citizenship/countries", status_code=302)
    regimes = session.query(CitizenshipRegime).filter(CitizenshipRegime.is_active == True).order_by(CitizenshipRegime.sort_order).all()
    return templates.TemplateResponse(request, "citizenship_country_edit.html", {
        "user": user, "country": country, "regimes": regimes, "error": None,
    })


@router.post("/admin/citizenship/countries/{country_id}/edit")
def country_edit_save(
    country_id: int,
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_mgmt),
    name: str = Form(""),
    regime_id: int = Form(0),
    is_active: str = Form("1"),
):
    country = session.query(Country).filter(Country.id == country_id).first()
    if not country:
        return RedirectResponse("/admin/citizenship/countries", status_code=302)
    name = normalize_text(name)
    if not name or not regime_id:
        regimes = session.query(CitizenshipRegime).filter(CitizenshipRegime.is_active == True).order_by(CitizenshipRegime.sort_order).all()
        return templates.TemplateResponse(request, "citizenship_country_edit.html", {
            "user": user, "country": country, "regimes": regimes, "error": "Название и режим обязательны",
        })
    country.name = name
    country.regime_id = regime_id
    country.is_active = is_active == "1"
    create_audit_log(session, request, user, "update", "country", entity_id=country_id, entity_name=name)
    session.commit()
    return RedirectResponse("/admin/citizenship/countries?message=Страна+сохранена", status_code=303)


@router.post("/admin/citizenship/countries/{country_id}/toggle")
def country_toggle(country_id: int, request: Request, session: Session = Depends(get_db), user=Depends(_mgmt)):
    country = session.query(Country).filter(Country.id == country_id).first()
    if country:
        country.is_active = not country.is_active
        create_audit_log(session, request, user, "toggle", "country", entity_id=country_id, entity_name=country.name)
        session.commit()
    return RedirectResponse("/admin/citizenship/countries", status_code=303)


# ── Проверка комплектности ────────────────────────────────────────────────────

def _resolve_check_context(session, employee):
    """Вернуть (user_obj, context_dict) для страницы проверки."""
    target = session.query(User).filter(User.employee_name == employee).first()
    if not target:
        return None, None

    ctx = {
        "employee_name": normalize_text(target.employee_name),
        "is_student": getattr(target, "is_student", False),
        "citizenship_string": getattr(target, "citizenship_country", None) or "",
        "country": None,
        "regime": None,
        "branch": None,
    }

    if ctx["is_student"]:
        ctx["branch"] = "student"
    elif getattr(target, "citizenship_country_id", None):
        country = session.query(Country).filter(Country.id == target.citizenship_country_id).first()
        if country:
            regime = session.query(CitizenshipRegime).filter(CitizenshipRegime.id == country.regime_id).first()
            ctx["country"] = country
            ctx["regime"] = regime
            ctx["branch"] = "regime"
        else:
            ctx["branch"] = "fallback"
    else:
        ctx["branch"] = "fallback"

    return target, ctx


@router.get("/admin/citizenship/check", response_class=HTMLResponse)
def citizenship_check(
    request: Request,
    session: Session = Depends(get_db),
    user=Depends(_mgmt),
    employee: str = "",
):
    names = employee_names(session)
    rows = []
    ctx = None

    if employee:
        target, ctx = _resolve_check_context(session, employee)
        if target:
            rows = employee_document_status(session, target)

    return templates.TemplateResponse(request, "citizenship_check.html", {
        "user": user,
        "names": names,
        "selected_employee": employee,
        "rows": rows,
        "ctx": ctx,
    })

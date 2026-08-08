# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the App

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Requires PostgreSQL at `localhost:5432/work_db`. Configure connection via `DATABASE_URL` env var. No migration tool — SQLAlchemy auto-creates tables on startup via `Base.metadata.create_all()` plus several `ensure_*()` calls at the bottom of `main.py`.

## Architecture Overview

FastAPI app with Jinja2 HTML templates, SQLAlchemy ORM (PostgreSQL), and session-based auth. No SPA framework — all rendering is server-side.

**Entry point**: `main.py` — sets up the app, mounts static files, registers all routers, and handles the largest endpoints (payroll calculation, shift uploads).

**Routers**: `routers/` — one file per domain area (auth, dashboards, payroll_runs, adjustments, users, schedules, documents, requisites, rates, lmk, reports, analytics, audit_logs, etc.). Each router is included in `main.py`.

**Models**: `models.py` — all SQLAlchemy ORM models in one file. Key ones: `User`, `Shift`, `Rate`, `Requisite`, `PayrollRun`, `PayrollRunItem`, `ManualPayrollAdjustment`, `PayrollAdjustment`, `MedicalBookCharge`, `EmployeeDocument`, `LegalEntity`, `AuditLog`, `UserAccessScope`.

**Helpers**: Standalone modules in the root (not a `helpers/` package) — `utils.py`, `access.py`, `audit_helpers.py`, `shift_helpers.py`, `payroll_run_helpers.py`, `payroll_adjustments.py`, `payroll_closing.py`, `manual_adjustments.py`, `lmk_charges.py`, `document_helpers.py`, `legal_entity_helpers.py`.

## Role System

Six roles: `superadmin`, `hr_lead`, `hr_manager`, `economist`, `brigadier`, `employee`. The legacy `is_admin = True` flag maps to `superadmin` via `canonical_role()` in `rbac.py`.

**Three-layer access model:**

1. **`current_user`** (`dependencies.py`) — resolves the logged-in user from the session. Redirects to `/login` if unauthenticated.
2. **`require_permission(perm)`** (`rbac.py`) — checks whether the user's role grants a given permission string (e.g. `"rates.view"`, `"payroll.manage"`). Full permission matrix is the `PERMISSIONS` dict in `rbac.py`. Use this for all new routes.
3. **`UserAccessScope`** (model + `rbac.get_scope_values()`) — restricts which cities/stores a user can see. `superadmin` and `hr_lead` are unrestricted (scope returns `None`). For `economist` and `hr_manager`, scope is read from `UserAccessScope` rows first; falls back to `User.economist_stores` (comma-separated) via `_legacy_scope_values()`. `access.py` wraps these lookups: `get_user_cities()`, `get_user_stores()`, `apply_shift_scope()`, `accessible_employee_names()`.

**Transitional helpers** in `dependencies.py` — `require_admin_user`, `require_economist_user`, `require_brigadier_user` — do a coarse role check only and are still used in older routes. New routes must use `require_permission`. These helpers will be phased out.

## Shift Uniqueness and request_type

The unique constraint on `shifts` is `(store, format, shift_date, service, employee, request_type)` — `request_type` is intentionally part of the key.

- `"Основные заказы"` — standard paid shifts.
- `"Смена без плана"` — unplanned shifts; **not paid by default**. They enter payroll only as a correction, not as a base line item.

Do **not** remove `request_type` from the uniqueness key or treat these two types as duplicates — they are deliberately distinct.

## Payroll Pipeline

1. Shifts uploaded as Excel → parsed → stored in `shifts` table.
2. `get_rate_for_shift()` in `utils.py` applies priority-scored rate lookup: employee-specific (+100) > store-specific (+10) > format-specific (+1) > service-only (base).
3. `ManualPayrollAdjustment` records tweak amounts per (employee, store, date range).
4. `PayrollAdjustment` records handle auto-corrections with `pending → approved → applied` workflow.
5. `MedicalBookCharge` deductions (LMK) spread across months.
6. Economist creates `PayrollRun` + `PayrollRunItem` records — one run per legal entity.
7. Finance closes the run → immutable, audit-logged.

PayrollRun lifecycle: `draft` → `fixed` → `sent` → `closed`.

**One payroll run = one legal entity.** `PayrollRun.legal_entity` ties a run to a specific `LegalEntity`. Do not mix multiple legal entities within one run.

**Never change numerical results** (rates, LMK deductions, adjustment amounts) during refactoring. Calculation logic in `payroll_run_helpers.py`, `lmk_charges.py`, `payroll_adjustments.py` must produce identical outputs before and after any structural change.

## Normalization

All text inputs pass through `normalize_text()`, `normalize_phone()`, `normalize_format()` in `utils.py` before DB writes or comparisons. These handle whitespace, Cyrillic е/ё variants, format name aliases (ГМ, СМ), and float-to-int phone conversions. Apply these when writing any new ingestion or lookup logic.

## Audit Logging

Every state-changing action calls `create_audit_log()` from `audit_helpers.py`, capturing user ID, role, IP, user-agent, action string, entity type/ID/name, old/new values (JSON), and an optional comment. Always call this when adding mutations.

## Database Sessions

Use FastAPI's `Depends(get_db)` from `dependencies.py` — it yields a `SessionLocal` and closes it in a `finally` block. Helper functions receive `db` (or `session`) as a parameter — they do not open their own sessions.

## Template Conventions

Templates use CSS variables (`--brand-blue`, `--brand-peach`) and a consistent context shape: user info, data lists, error/message banners. Role-conditional rendering is done with Jinja2 `{% if user.role == ... %}` checks inside templates.

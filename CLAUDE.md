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

**Helpers**: Standalone modules in the root (not a `helpers/` package) — `utils.py`, `access.py`, `audit_helpers.py`, `shift_helpers.py`, `payroll_run_helpers.py`, `payroll_adjustments.py`, `payroll_closing.py`, `manual_adjustments.py`, `lmk_charges.py`, `document_helpers.py`, `legal_entity_helpers.py`, `file_storage.py`.

## File Storage

Production runs on Timeweb App Platform, which has **no persistent disk** — the container is rebuilt from GitHub on every commit to `main`, wiping local files. All file I/O therefore goes through `file_storage.py`: `storage_save()`, `storage_exists()`, `storage_delete()`, `storage_stream()`, and `storage_response()` (a ready `StreamingResponse` with RFC 5987 `Content-Disposition` — filenames are Cyrillic).

The backend is chosen by environment: `S3_BUCKET` + `S3_ACCESS_KEY` + `S3_SECRET_KEY` set → S3 (Timeweb Object Storage via boto3, `S3_ENDPOINT`/`S3_REGION`); otherwise local disk under `DOCUMENT_UPLOAD_ROOT` / `GENERATED_FILES_ROOT` for dev and tests. `boto3` is imported lazily, so local mode needs no S3 packages.

Object keys mirror the old on-disk layout and are stored verbatim in the existing `file_path` / `image_path` / `sample_image_path` columns — no schema change: `uploaded_documents/<folder>/<file>` (QR included), `generated_files/planning_forms/...`, `generated_files/reconciliations/...`. Pre-migration absolute paths (`/data/...`, `/app/...`) are reported as missing in S3 mode; those files were lost in the move.

Never write generated files to disk — build them in a `BytesIO` and hand the bytes to `storage_save()`. Do not reintroduce `FileResponse`, `Path(...).write_bytes()`, `.unlink()`, or `mkdir()` for user or generated files.

## Role System

Roles: `superadmin`, `hr_lead`, `tm` (территориальный менеджер; legacy DB value `hr_manager` is an alias until `scripts/migrate_role_tm.py`), `hr_clerk` (кадровик), `economist`, `brigadier`, `headhunter`, `employee`. The legacy `is_admin = True` flag maps to `superadmin` via `canonical_role()` in `rbac.py`. UI labels: `rbac.ROLE_LABELS`. Roles allowed into the `/hr` cabinet: `rbac.HR_CABINET_ROLES`.

**Three-layer access model:**

1. **`current_user`** (`dependencies.py`) — resolves the logged-in user from the session. Redirects to `/login` if unauthenticated.
2. **`require_permission(perm)`** (`rbac.py`) — checks whether the user's role grants a given permission string (e.g. `"rates.view"`, `"payroll.manage"`). Full permission matrix is the `PERMISSIONS` dict in `rbac.py`. Use this for all new routes.
3. **`UserAccessScope`** (model + `rbac.get_scope_values()`) — restricts which cities/stores a user can see. **Disabled since П1**: with `SCOPES_ENABLED` unset/false, `get_scope_values()` and `access.get_economist_cities()` return `None` (unrestricted) for every role; `None` must always be treated as "no restriction". With `SCOPES_ENABLED=true` the old logic applies: `superadmin` and `hr_lead` are unrestricted; for `economist` and `tm`, scope is read from `UserAccessScope` rows first; falls back to `User.economist_stores` (comma-separated) via `_legacy_scope_values()`. `access.py` wraps these lookups: `get_user_cities()`, `get_user_stores()`, `apply_shift_scope()`, `accessible_employee_names()`.

**Transitional helpers** in `dependencies.py` — `require_admin_user`, `require_economist_user`, `require_brigadier_user` — do a coarse role check only and are still used in older routes. New routes must use `require_permission`. These helpers will be phased out.

## Shift Uniqueness and request_type

The unique constraint on `shifts` is `(store, format, shift_date, service, employee, request_type)` — `request_type` is intentionally part of the key.

- `"Основные заказы"` — standard paid shifts.
- `"Смена без плана"` — unplanned shifts; **not paid by default**. They enter payroll only as a correction, not as a base line item.

Do **not** remove `request_type` from the uniqueness key or treat these two types as duplicates — they are deliberately distinct.

## Payroll Pipeline

1. Shifts uploaded as Excel → parsed → stored in `shifts` table.
2. `get_rate_for_shift()` in `utils.py` applies priority-scored rate lookup: employee-specific (+100) > store-specific (+10) > format-specific (+1) > service-only (base). The region filter compares `Rate.city` (labelled «Регион» in the UI) with the shift's **tariff region**: `Store.rate_region` of the shift's store (by ТК number from `Shift.store`), falling back to `Shift.city` when the store is unknown or the field is empty (П4.4). The region map rides on the resolver from `service_catalog.build_service_resolver` (`resolve.rate_region`), so every `pick_rate(..., resolve=resolve)` call gets it; without a resolver `pick_rate` uses `Shift.city` as before. Suburban stores are «Московская область» / «Ленинградская область» even though the timebook «Город» says «Москва» / «Санкт-Петербург»; `Shift.city` itself stays the timebook value.
3. `ManualPayrollAdjustment` records tweak amounts per (employee, store, date range).
4. `PayrollAdjustment` records handle auto-corrections with `pending → approved → applied` workflow.
5. `MedicalBookCharge` deductions (LMK) spread across months.
6. Economist creates `PayrollRun` + `PayrollRunItem` records — one run per legal entity.
7. Finance closes the run → immutable, audit-logged.

PayrollRun lifecycle: `draft` → `fixed` → `sent` → `closed`.

**Services not paid from the timebook.** `Service.excluded_from_payroll` (toggle on `/admin/services`) marks services paid from another report. Off for every service by default: комплектация deliberately stays «Не найдена ЧТС» until its hours are exported and rates exist (owner, 12.10.2026) — do not set the flag in `services.json`. `payroll_run_helpers.payable_shifts(shifts, resolve)` drops their shifts from advances, period runs, fix_payroll and the payroll previews, so they never block fixing with «Не найдена ЧТС»; schedules and reports still show them. **Format aliases for rates:** `utils.RATE_FORMAT_ALIASES` — ТШ/ЗМ shifts take СМ rates, ЦП takes ГМ (a rate with the exact format still wins).

**Timesheet builder (П4.6).** `timesheet.build_timesheet_rows(session, date_from, date_to, lines=None)` — one row per (employee, ТК, service) with hours by day; the «Табель» sheet of the period statement (`statement_export`, from run items) and the weekly report `/admin/payouts/weekly` (`weekly_report`, from shifts via `payroll_run_helpers.price_shift`, the same rate+bonus calc as `build_run_items`) both use it. No-plan shifts are not in either. The weekly report shows the shift's city/format, rate = ЧТС + bonus of the last rated shift (`НЕТ` without), ФОТ incl. bonus; only completed Mon–Sun weeks (`resolve_week` rounds down to Monday and clamps to the last completed week).

**Hourly bonus (П4.4).** `HourlyBonus` rows («Акция», ₽ per hour, `active_from`/`active_to`) add `PayrollRunItem.bonus_amount = hours × Σ bonuses active on the shift date` to shifts with a non-zero rate; `total_amount = amount + bonus_amount + other + auto − lmk − advanced`, and a twin's `advanced_amount` includes its bonus. With no active bonus the rows are identical to before (`tests/test_payroll_snapshot.py`). Managed on `/admin/payouts/bonuses`.

**One payroll run = one legal entity.** `PayrollRun.legal_entity` ties a run to a specific `LegalEntity`. Do not mix multiple legal entities within one run.

**Never change numerical results** (rates, LMK deductions, adjustment amounts) during refactoring. Calculation logic in `payroll_run_helpers.py`, `lmk_charges.py`, `payroll_adjustments.py` must produce identical outputs before and after any structural change.

## Store Assignments and Where a Shift Counts

An employee↔store assignment (`EmployeeStoreAssignment`, managed on `/admin/planning-bp`) is **only an input for the planning blank (БП)** — it does not restrict where the employee may work. A shift counts where the timebook export caught it, for the service stated in the export: the store, city and service of `Shift` come from the upload, never from the assignment. Monitoring therefore says «убрать из БП» / «добавить в БП», not «не работает». БП and reconciliations are for the ГМ format only (`store_helpers.allows_bp`). City from the export is normalized (`utils.normalize_city`: no «г.», empty → NULL) because rate lookup matches the region string-for-string (`Store.rate_region`, else `Shift.city`).

## Contracts and Petitions (P4)

`contract_generator.py` fills `data/templates/contract_template.docx` / `petition_template.docx` by replacing template **sample text** inside the paragraph found by an **anchor** (spans across Word runs, formatting kept, substituted text highlighted yellow, missing → «НЕТ ДАННЫХ» only on explicit request). The map is `CONTRACT_SUBS` / `PETITION_SUBS`; `tests/test_documents_contracts.py -k real_templates` fails with `TemplateMismatch` if a template edit removed a sample. Field sources live in `contract_data.py`; see `docs/contracts.md`.

**Rule: employee documents are the data source for contracts.** Passport, SNILS and patent come from `EmployeeDocument` (patent: `document_number` = «78 №… / ПР …», extra fields = issuing authority / profession), the rest from `User`, `LegalEntity`, `Region` (`employee_profile.py`). Missing data entered in the completeness form is saved back to that source, never only into the generated file.

## Normalization

All text inputs pass through `normalize_text()`, `normalize_phone()`, `normalize_format()` in `utils.py` before DB writes or comparisons. These handle whitespace, Cyrillic е/ё variants, format name aliases (ГМ, СМ), and float-to-int phone conversions. Apply these when writing any new ingestion or lookup logic.

## Audit Logging

Every state-changing action calls `create_audit_log()` from `audit_helpers.py`, capturing user ID, role, IP, user-agent, action string, entity type/ID/name, old/new values (JSON), and an optional comment. Always call this when adding mutations.

## Database Sessions

Use FastAPI's `Depends(get_db)` from `dependencies.py` — it yields a `SessionLocal` and closes it in a `finally` block. Helper functions receive `db` (or `session`) as a parameter — they do not open their own sessions.

## Template Conventions

Templates use CSS variables (`--brand-blue`, `--brand-peach`) and a consistent context shape: user info, data lists, error/message banners. Role-conditional rendering is done with Jinja2 `{% if user.role == ... %}` checks inside templates.

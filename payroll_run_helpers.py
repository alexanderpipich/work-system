from sqlalchemy import text

from database import engine


def ensure_payroll_run_closing_columns():
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                ALTER TABLE payroll_runs
                ADD COLUMN IF NOT EXISTS closed_at TIMESTAMP
                """
            )
        )
        connection.execute(
            text(
                """
                ALTER TABLE payroll_runs
                ADD COLUMN IF NOT EXISTS closed_by INTEGER
                """
            )
        )
        connection.execute(
            text(
                """
                ALTER TABLE payroll_adjustments
                ADD COLUMN IF NOT EXISTS target_run_id INTEGER
                """
            )
        )
        connection.execute(
            text(
                """
                ALTER TABLE manual_payroll_adjustments
                ADD COLUMN IF NOT EXISTS applied_run_id INTEGER
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS medical_book_payments (
                    id SERIAL PRIMARY KEY,
                    charge_id INTEGER,
                    run_id INTEGER,
                    employee_name VARCHAR,
                    amount DOUBLE PRECISION DEFAULT 0,
                    created_at TIMESTAMP DEFAULT NOW()
                )
                """
            )
        )

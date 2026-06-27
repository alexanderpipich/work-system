import os
import unittest
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from document_helpers import employee_document_status, EXPIRY_WARNING_DAYS
from time_helpers import business_today


# ── helpers ───────────────────────────────────────────────────────────────────

def _dt(id, sort_order=0, is_student_doc=False):
    return SimpleNamespace(id=id, name=f"DocType-{id}", sort_order=sort_order, is_student_doc=is_student_doc)


def _rule(doc_type_id, is_required=True):
    return SimpleNamespace(document_type_id=doc_type_id, is_required=is_required)


def _doc(status, expiry_date=None, is_permanent=False):
    return SimpleNamespace(status=status, expiry_date=expiry_date, is_permanent=is_permanent)


def _user(is_student=False, country_id=None, citizenship_country=None):
    return SimpleNamespace(
        id=1,
        employee_name="Тест Тестов",
        is_student=is_student,
        citizenship_country_id=country_id,
        citizenship_country=citizenship_country,
    )


def _regime_session(doc_types, country_regime_id=1):
    """Session mock for the regime branch: Country → rules → DocumentTypes."""
    from models import Country, DocumentType, RegimeDocumentRule

    country = SimpleNamespace(id=1, regime_id=country_regime_id)
    rules = [_rule(dt.id) for dt in doc_types]

    def _query(model):
        q = MagicMock()
        if model is Country:
            q.filter.return_value.first.return_value = country
        elif model is RegimeDocumentRule:
            q.filter.return_value.all.return_value = rules
        elif model is DocumentType:
            q.filter.return_value.order_by.return_value.all.return_value = doc_types
        return q

    session = MagicMock()
    session.query.side_effect = _query
    return session


def _student_session(base_types, student_types):
    """Session mock for the student branch: two sequential DocumentType queries."""
    from models import DocumentType

    call_count = [0]

    def _query(model):
        q = MagicMock()
        if model is DocumentType:
            call_count[0] += 1
            # First call = base types (sort_order 1–5), second = student docs
            result = base_types if call_count[0] == 1 else student_types
            q.filter.return_value.order_by.return_value.all.return_value = result
        return q

    session = MagicMock()
    session.query.side_effect = _query
    return session


# ── RegimeDocumentSetTests ────────────────────────────────────────────────────

class RegimeDocumentSetTests(unittest.TestCase):
    """Function returns exactly the types listed in RegimeDocumentRule(is_required=True)."""

    @patch("document_helpers.latest_employee_document", return_value=None)
    def test_resident_returns_5_types(self, _):
        doc_types = [_dt(i, sort_order=i) for i in range(1, 6)]
        session = _regime_session(doc_types)
        result = employee_document_status(session, _user(country_id=1))
        self.assertEqual(len(result), 5)

    @patch("document_helpers.latest_employee_document", return_value=None)
    def test_union_returns_6_types(self, _):
        doc_types = [_dt(i, sort_order=i) for i in range(1, 7)]
        session = _regime_session(doc_types)
        result = employee_document_status(session, _user(country_id=1))
        self.assertEqual(len(result), 6)

    @patch("document_helpers.latest_employee_document", return_value=None)
    def test_eaeu_returns_8_types(self, _):
        doc_types = [_dt(i, sort_order=i) for i in range(1, 9)]
        session = _regime_session(doc_types)
        result = employee_document_status(session, _user(country_id=1))
        self.assertEqual(len(result), 8)

    @patch("document_helpers.latest_employee_document", return_value=None)
    def test_patent_returns_12_types(self, _):
        doc_types = [_dt(i, sort_order=i) for i in range(1, 13)]
        session = _regime_session(doc_types)
        result = employee_document_status(session, _user(country_id=1))
        self.assertEqual(len(result), 12)

    @patch("document_helpers.latest_employee_document", return_value=None)
    def test_all_items_are_required(self, _):
        doc_types = [_dt(i) for i in range(1, 6)]
        session = _regime_session(doc_types)
        result = employee_document_status(session, _user(country_id=1))
        self.assertTrue(all(r["required"] for r in result))

    @patch("document_helpers.latest_employee_document", return_value=None)
    def test_non_relevant_types_excluded(self, _):
        # Only 3 types required; function must not include a 4th type not in rules
        doc_types = [_dt(1), _dt(2), _dt(3)]
        session = _regime_session(doc_types)
        result = employee_document_status(session, _user(country_id=1))
        self.assertEqual(len(result), 3)
        returned_ids = {r["document_type"].id for r in result}
        self.assertEqual(returned_ids, {1, 2, 3})


# ── StudentOverrideTests ──────────────────────────────────────────────────────

class StudentOverrideTests(unittest.TestCase):
    """is_student=True overrides citizenship entirely."""

    @patch("document_helpers.latest_employee_document", return_value=None)
    def test_student_gets_base_plus_student_docs(self, _):
        base = [_dt(i, sort_order=i) for i in range(1, 6)]       # 5 base types
        student_docs = [_dt(13, is_student_doc=True), _dt(14, is_student_doc=True)]
        session = _student_session(base, student_docs)
        result = employee_document_status(session, _user(is_student=True, country_id=99))
        self.assertEqual(len(result), 7)  # 5 base + 2 student

    @patch("document_helpers.latest_employee_document", return_value=None)
    def test_student_ignores_country_id(self, _):
        # Even with a country_id set, student branch takes priority
        base = [_dt(i, sort_order=i) for i in range(1, 6)]
        student_docs = [_dt(13, is_student_doc=True)]
        session = _student_session(base, student_docs)
        user = _user(is_student=True, country_id=42)
        result = employee_document_status(session, user)
        # Should NOT hit the regime branch (6 types would include patent extras)
        self.assertEqual(len(result), 6)

    @patch("document_helpers.latest_employee_document", return_value=None)
    def test_student_patent_citizen_has_no_patent_doc(self, _):
        # Student from patent-regime country: only base + student docs returned,
        # not patent/registration/migration card
        base = [_dt(i, sort_order=i) for i in range(1, 6)]
        student_docs = [_dt(13, is_student_doc=True), _dt(14, is_student_doc=True)]
        session = _student_session(base, student_docs)
        result = employee_document_status(session, _user(is_student=True, country_id=5))
        returned_ids = {r["document_type"].id for r in result}
        # IDs 7–12 are patent/registration/migration extras — must not appear
        self.assertFalse(returned_ids & {7, 8, 9, 10, 11, 12})


# ── CompletenessStatusTests ───────────────────────────────────────────────────

class CompletenessStatusTests(unittest.TestCase):
    """All four statuses + edge case: uploaded with expired date → expired."""

    def _result_for(self, doc):
        doc_types = [_dt(1)]
        session = _regime_session(doc_types)
        with patch("document_helpers.latest_employee_document", return_value=doc):
            result = employee_document_status(session, _user(country_id=1))
        return result[0]["status"]

    def test_verified_future_expiry_is_ok(self):
        future = business_today() + timedelta(days=60)
        status = self._result_for(_doc("verified", expiry_date=future))
        self.assertEqual(status, "ok")

    def test_verified_permanent_is_ok(self):
        status = self._result_for(_doc("verified", is_permanent=True))
        self.assertEqual(status, "ok")

    def test_uploaded_future_expiry_is_pending(self):
        future = business_today() + timedelta(days=30)
        status = self._result_for(_doc("uploaded", expiry_date=future))
        self.assertEqual(status, "pending")

    def test_pending_verification_no_expiry_is_pending(self):
        status = self._result_for(_doc("pending_verification"))
        self.assertEqual(status, "pending")

    def test_verified_past_expiry_is_expired(self):
        past = business_today() - timedelta(days=1)
        status = self._result_for(_doc("verified", expiry_date=past))
        self.assertEqual(status, "expired")

    def test_no_document_is_missing(self):
        status = self._result_for(None)
        self.assertEqual(status, "missing")

    def test_rejected_document_is_missing(self):
        status = self._result_for(_doc("rejected"))
        self.assertEqual(status, "missing")

    def test_archived_document_is_missing(self):
        status = self._result_for(_doc("archived"))
        self.assertEqual(status, "missing")

    def test_uploaded_with_expired_date_is_expired_not_pending(self):
        # Edge case: document uploaded but its expiry_date is in the past.
        # Must be "expired", not "pending", because the document is no longer valid.
        past = business_today() - timedelta(days=1)
        status = self._result_for(_doc("uploaded", expiry_date=past))
        self.assertEqual(status, "expired")

    def test_pending_verification_with_expired_date_is_expired_not_pending(self):
        past = business_today() - timedelta(days=10)
        status = self._result_for(_doc("pending_verification", expiry_date=past))
        self.assertEqual(status, "expired")


# ── ExpiringSoonTests ─────────────────────────────────────────────────────────

class ExpiringSoonTests(unittest.TestCase):
    """expiring_soon: verified + expiry within EXPIRY_WARNING_DAYS. Boundary at exactly 30 days."""

    def _result_for(self, doc):
        doc_types = [_dt(1)]
        session = _regime_session(doc_types)
        with patch("document_helpers.latest_employee_document", return_value=doc):
            result = employee_document_status(session, _user(country_id=1))
        return result[0]["status"]

    def test_verified_15_days_left_is_expiring_soon(self):
        expiry = business_today() + timedelta(days=15)
        self.assertEqual(self._result_for(_doc("verified", expiry_date=expiry)), "expiring_soon")

    def test_verified_40_days_left_is_ok(self):
        expiry = business_today() + timedelta(days=40)
        self.assertEqual(self._result_for(_doc("verified", expiry_date=expiry)), "ok")

    def test_verified_exactly_30_days_left_is_expiring_soon(self):
        expiry = business_today() + timedelta(days=EXPIRY_WARNING_DAYS)
        self.assertEqual(self._result_for(_doc("verified", expiry_date=expiry)), "expiring_soon")

    def test_verified_31_days_left_is_ok(self):
        expiry = business_today() + timedelta(days=EXPIRY_WARNING_DAYS + 1)
        self.assertEqual(self._result_for(_doc("verified", expiry_date=expiry)), "ok")

    def test_uploaded_30_days_left_is_pending_not_expiring_soon(self):
        # expiring_soon only applies to verified documents
        expiry = business_today() + timedelta(days=15)
        self.assertEqual(self._result_for(_doc("uploaded", expiry_date=expiry)), "pending")

    def test_verified_permanent_is_ok_not_expiring_soon(self):
        # permanent docs are never expiring_soon
        self.assertEqual(self._result_for(_doc("verified", is_permanent=True)), "ok")


# ── FallbackTests ─────────────────────────────────────────────────────────────

class FallbackTests(unittest.TestCase):
    """No citizenship_country_id → old citizenship_filter logic, no crash."""

    @patch("document_helpers.active_document_types", return_value=[])
    @patch("document_helpers.user_citizenship", return_value="")
    def test_fallback_when_no_country_id_does_not_crash(self, mock_cit, mock_types):
        session = MagicMock()
        user = _user(country_id=None, citizenship_country=None)
        result = employee_document_status(session, user)
        self.assertEqual(result, [])
        mock_cit.assert_called_once()
        mock_types.assert_called_once()

    @patch("document_helpers.latest_employee_document", return_value=None)
    @patch("document_helpers.active_document_types")
    @patch("document_helpers.user_citizenship", return_value="рф")
    def test_fallback_returns_types_from_old_logic(self, mock_cit, mock_types, _):
        doc_types = [_dt(1), _dt(2), _dt(3)]
        mock_types.return_value = doc_types
        session = MagicMock()
        user = _user(country_id=None, citizenship_country="РФ")
        result = employee_document_status(session, user)
        self.assertEqual(len(result), 3)
        self.assertTrue(all(r["status"] == "missing" for r in result))


if __name__ == "__main__":
    unittest.main()

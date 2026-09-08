from __future__ import annotations

from app.engine import evaluate_claim


def _base_claim(**overrides):
    data = {
        "id": 99,
        "provider_name": "Bay Clinic",
        "provider_npi": "1234567893",
        "facility": "Bay Clinic",
        "date_of_service": "2026-08-12",
        "diagnosis_code": "J06.9",
        "procedure_code": "99213",
        "amount": 158.0,
        "place_of_service": "office",
        "is_emergency": 0,
        "preauth_number": "",
        "notes": "",
    }
    data.update(overrides)
    return data


def _patient():
    return {"full_name": "Maya Chen", "date_of_birth": "1984-04-12", "member_id": "MBR-441890"}


def _policy():
    return {
        "policy_number": "POL-1001-MC",
        "status": "active",
        "effective_from": "2024-01-01",
        "effective_to": "2026-12-31",
        "annual_limit": 25000,
        "used_to_date": 400,
        "network": "in_network",
    }


def _docs():
    return [
        {"doc_type": "claim_form", "original_name": "cms1500.txt", "size_bytes": 400, "text": "CMS-1500 Claim Form Maya Chen $158.00"},
        {"doc_type": "itemized_bill", "original_name": "bill.txt", "size_bytes": 200, "text": "Itemized bill Maya Chen $158.00"},
        {"doc_type": "medical_record", "original_name": "note.txt", "size_bytes": 200, "text": "Progress note Maya Chen"},
        {"doc_type": "id_document", "original_name": "id.txt", "size_bytes": 120, "text": "Member ID Maya Chen"},
    ]


def test_clean_office_visit_approves():
    decision = evaluate_claim(_base_claim(), _policy(), _patient(), _docs(), [])
    assert decision.recommendation == "APPROVE"
    assert decision.fraud_probability < 0.4
    assert decision.coverage_ok is True


def test_expired_policy_denies():
    policy = _policy()
    policy["status"] = "expired"
    decision = evaluate_claim(_base_claim(), policy, _patient(), _docs(), [])
    assert decision.recommendation == "DENY"
    assert decision.coverage_ok is False


def test_pediatric_knee_replacement_is_high_fraud():
    patient = {"full_name": "James Okonkwo", "date_of_birth": "2018-01-19", "member_id": "MBR-1"}
    claim = _base_claim(procedure_code="27447", diagnosis_code="J06.9", amount=48000, is_emergency=1, provider_npi="0000000000")
    decision = evaluate_claim(claim, _policy(), patient, [], [])
    assert decision.fraud_probability >= 0.7
    assert decision.recommendation == "DENY"


def test_duplicate_claim_is_flagged():
    prior = [_base_claim(id=1)]
    decision = evaluate_claim(_base_claim(id=2), _policy(), _patient(), _docs(), prior)
    names = {f.name: f for f in decision.factors}
    assert names["Duplicate claim"].passed is False


def test_missing_documents_requests_info():
    decision = evaluate_claim(_base_claim(), _policy(), _patient(), [], [])
    assert decision.recommendation in {"REQUEST_INFO", "MANUAL_REVIEW", "DENY"}
    names = {f.name: f for f in decision.factors}
    assert names["Required documents"].passed is False

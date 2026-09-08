from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date, datetime
from math import exp
from typing import Any

from app.config import (
    ADULT_ONLY_CPT,
    CPT_ICD_HINTS,
    EXCLUDED_PROCEDURES,
    PREAUTH_REQUIRED_CPT,
    REQUIRED_DOC_TYPES,
    UCR_TABLE,
)
from app.security import npi_checksum_ok


@dataclass
class Factor:
    name: str
    category: str
    severity: str
    score_delta: float
    passed: bool
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Decision:
    recommendation: str
    fraud_probability: float
    coverage_ok: bool
    confidence: float
    rationale: str
    factors: list[Factor] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data


def _parse_date(value: str) -> date | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%d-%m-%Y"):
        try:
            return datetime.strptime(value[:10], fmt).date()
        except ValueError:
            continue
    return None


def _age(dob: str, on: date) -> int | None:
    born = _parse_date(dob)
    if not born:
        return None
    years = on.year - born.year - ((on.month, on.day) < (born.month, born.day))
    return years


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + exp(-x))


def _icd_family(code: str) -> str:
    return "".join(ch for ch in (code or "").upper() if ch.isalnum())[:3]


def _amount_from_text(text: str) -> list[float]:
    import re

    found = []
    for match in re.finditer(r"\$?\s*([0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]{2})|[0-9]+\.[0-9]{2})", text):
        try:
            found.append(float(match.group(1).replace(",", "")))
        except ValueError:
            continue
    return found


def evaluate_claim(claim: dict[str, Any], policy: dict[str, Any] | None, patient: dict[str, Any], documents: list[dict[str, Any]], prior_claims: list[dict[str, Any]]) -> Decision:
    factors: list[Factor] = []
    fraud_raw = 0.0
    coverage_ok = True
    today = date.today()
    dos = _parse_date(claim.get("date_of_service") or "") or today
    amount = float(claim.get("amount") or 0)
    cpt = str(claim.get("procedure_code") or "").strip().upper()
    icd = str(claim.get("diagnosis_code") or "").strip().upper()
    doc_types = {d.get("doc_type") for d in documents}
    combined_text = "\n".join(d.get("text") or "" for d in documents)

    def add(name: str, category: str, severity: str, delta: float, passed: bool, detail: str) -> None:
        nonlocal fraud_raw, coverage_ok
        factors.append(Factor(name, category, severity, delta, passed, detail))
        fraud_raw += delta
        if category == "eligibility" and not passed and severity == "critical":
            coverage_ok = False

    # --- Eligibility / coverage ---
    if not policy:
        add("Policy on file", "eligibility", "critical", 18, False, "No matching policy was found for this member.")
    else:
        status = (policy.get("status") or "").lower()
        start = _parse_date(policy["effective_from"])
        end = _parse_date(policy["effective_to"])
        if status != "active":
            add("Policy status", "eligibility", "critical", 22, False, f"Policy {policy['policy_number']} is {status}.")
        elif start and end and not (start <= dos <= end):
            add("Date of service in term", "eligibility", "critical", 20, False, f"Service date {dos.isoformat()} is outside {start}–{end}.")
        else:
            add("Policy status", "eligibility", "info", 0, True, f"Policy {policy['policy_number']} is active and in force on the date of service.")

        remaining = float(policy.get("annual_limit") or 0) - float(policy.get("used_to_date") or 0)
        if amount > remaining:
            add("Annual limit", "eligibility", "critical", 12, False, f"Claim ${amount:,.2f} exceeds remaining benefit ${remaining:,.2f}.")
        else:
            add("Annual limit", "eligibility", "info", 0, True, f"Remaining annual benefit is ${remaining:,.2f}.")

        if policy.get("network") == "in_network":
            add("Network", "eligibility", "info", 0, True, "Provider is billed as in-network.")
        else:
            add("Network", "eligibility", "warning", 6, False, "Out-of-network claims have a higher dispute and fraud rate.")

    if cpt in EXCLUDED_PROCEDURES:
        add("Covered benefit", "eligibility", "critical", 15, False, EXCLUDED_PROCEDURES[cpt])
    else:
        add("Covered benefit", "eligibility", "info", 0, True, f"Procedure {cpt or '—'} is not on the exclusion list.")

    if cpt in PREAUTH_REQUIRED_CPT:
        if claim.get("preauth_number"):
            add("Prior authorization", "eligibility", "info", 0, True, f"Prior auth {claim['preauth_number']} was supplied.")
        else:
            add("Prior authorization", "eligibility", "critical", 10, False, f"Procedure {cpt} requires prior authorization.")

    # --- Documentation completeness ---
    missing = [t for t in REQUIRED_DOC_TYPES if t not in doc_types]
    if missing:
        labels = ", ".join(t.replace("_", " ") for t in missing)
        add("Required documents", "documentation", "warning", 8 + 4 * len(missing), False, f"Missing: {labels}.")
    else:
        add("Required documents", "documentation", "info", 0, True, "Claim form, itemized bill, medical record, and ID are present.")

    if not documents:
        add("Document repository", "documentation", "critical", 16, False, "No files were stored in the local repository for this claim.")
    else:
        empty = [d["original_name"] for d in documents if int(d.get("size_bytes") or 0) < 24]
        if empty:
            add("Document substance", "documentation", "warning", 10, False, f"Near-empty files: {', '.join(empty)}.")
        else:
            add("Document substance", "documentation", "info", 0, True, f"{len(documents)} file(s) stored in the local encrypted repository.")

    patient_name = (patient.get("full_name") or "").strip().lower()
    if combined_text and patient_name:
        last = patient_name.split()[-1]
        if last and last not in combined_text.lower():
            add("Name consistency", "documentation", "warning", 12, False, "Patient surname does not appear in the uploaded documents.")
        else:
            add("Name consistency", "documentation", "info", 0, True, "Patient identity appears in the supporting documents.")

    bill_amounts = _amount_from_text(combined_text)
    if bill_amounts and amount:
        closest = min(bill_amounts, key=lambda x: abs(x - amount))
        if abs(closest - amount) > max(25.0, 0.08 * amount):
            add("Billed vs claimed amount", "documentation", "warning", 11, False, f"Claimed ${amount:,.2f} does not match billed amounts in documents (nearest ${closest:,.2f}).")
        else:
            add("Billed vs claimed amount", "documentation", "info", 0, True, "Claimed amount is consistent with the itemized bill.")

    # --- Clinical reasonableness ---
    years = _age(patient.get("date_of_birth") or "", dos)
    if years is not None and cpt in ADULT_ONLY_CPT and years < 16:
        add("Age vs procedure", "fraud", "critical", 28, False, f"Patient age {years} is incompatible with procedure {cpt}.")
    elif years is not None:
        add("Age vs procedure", "fraud", "info", 0, True, f"Patient age {years} is compatible with the billed procedure.")

    hints = CPT_ICD_HINTS.get(cpt)
    if hints:
        family = _icd_family(icd)
        if any(family.startswith(h[:3]) or h.startswith(family) for h in hints) or family in {h[:3] for h in hints}:
            add("Diagnosis vs procedure", "fraud", "info", 0, True, f"{icd} is a plausible indication for {cpt}.")
        else:
            add("Diagnosis vs procedure", "fraud", "warning", 18, False, f"ICD-10 {icd} is an unusual pairing for CPT {cpt}.")

    npi = str(claim.get("provider_npi") or "")
    if npi_checksum_ok(npi):
        add("Provider NPI", "fraud", "info", 0, True, "NPI passes the CMS checksum.")
    else:
        add("Provider NPI", "fraud", "warning", 14, False, "Provider NPI is missing or fails the CMS checksum.")

    # --- Fraud / abuse patterns ---
    ucr = UCR_TABLE.get(cpt)
    if ucr and amount > ucr * 1.8:
        add("Usual customary rate", "fraud", "warning", 16, False, f"${amount:,.2f} is more than 180% of the local UCR ${ucr:,.2f}.")
    elif ucr and amount > ucr * 1.35:
        add("Usual customary rate", "fraud", "warning", 8, False, f"${amount:,.2f} is above typical UCR ${ucr:,.2f}.")
    elif ucr:
        add("Usual customary rate", "fraud", "info", 0, True, f"${amount:,.2f} is within a reasonable range of UCR ${ucr:,.2f}.")

    if amount >= 100 and amount == int(amount) and amount % 100 == 0:
        add("Round-dollar billing", "fraud", "info", 5, False, "Exact hundred-dollar amounts are over-represented in abusive billing.")

    window = [p for p in prior_claims if p.get("id") != claim.get("id")]
    duplicates = [
        p
        for p in window
        if p.get("procedure_code") == cpt
        and abs(float(p.get("amount") or 0) - amount) < 1
        and p.get("date_of_service") == claim.get("date_of_service")
    ]
    if duplicates:
        add("Duplicate claim", "fraud", "critical", 30, False, f"{len(duplicates)} prior claim(s) match this date, procedure, and amount.")
    else:
        recent = 0
        for p in window:
            prior_dos = _parse_date(p.get("date_of_service") or "")
            if prior_dos and abs((dos - prior_dos).days) <= 14:
                recent += 1
        if recent >= 2:
            add("Claim frequency", "fraud", "warning", 12, False, f"{recent} other claims within 14 days of this service date.")
        else:
            add("Duplicate claim", "fraud", "info", 0, True, "No same-day duplicate of this procedure and amount.")

    lag = (today - dos).days
    if lag > 90:
        add("Timely filing", "fraud", "warning", 7, False, f"Claim was filed {lag} days after the date of service.")
    elif lag < 0:
        add("Future service date", "fraud", "critical", 20, False, "Date of service is in the future.")

    if claim.get("is_emergency") and cpt in {"27447", "27130", "66984", "43239"}:
        add("Emergency flag vs procedure", "fraud", "warning", 9, False, "Elective surgical CPTs are rarely true emergencies.")

    # Map accumulated red-flag mass to a calibrated probability.
    fraud_probability = round(min(0.97, max(0.02, _sigmoid((fraud_raw - 28) / 14))), 3)

    missing_docs = any(f.name == "Required documents" and not f.passed for f in factors)
    critical_coverage = any(f.category == "eligibility" and f.severity == "critical" and not f.passed for f in factors)
    critical_fraud = any(f.category == "fraud" and f.severity == "critical" and not f.passed for f in factors)

    if critical_coverage:
        recommendation = "DENY"
        rationale = "Coverage rules fail. The claim should not be paid from this policy."
    elif critical_fraud or fraud_probability >= 0.72:
        recommendation = "DENY"
        rationale = "Fraud and abuse indicators are high enough to refuse automated payment and route to SIU."
    elif missing_docs and fraud_probability < 0.55:
        recommendation = "REQUEST_INFO"
        rationale = "Coverage looks plausible but required documents are incomplete."
    elif fraud_probability >= 0.40 or any(f.severity == "warning" and not f.passed for f in factors):
        recommendation = "MANUAL_REVIEW"
        rationale = "Mixed signals. A human reviewer should confirm medical necessity and documentation."
    else:
        recommendation = "APPROVE"
        rationale = "Eligibility, documentation, and fraud screens are within automated payment thresholds."

    passed = sum(1 for f in factors if f.passed)
    confidence = round(min(0.95, 0.45 + 0.5 * (passed / max(len(factors), 1))), 2)

    return Decision(
        recommendation=recommendation,
        fraud_probability=fraud_probability,
        coverage_ok=coverage_ok,
        confidence=confidence,
        rationale=rationale,
        factors=factors,
    )

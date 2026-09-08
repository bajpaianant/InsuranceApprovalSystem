from __future__ import annotations

from app.config import CLAIMS_DIR
from app.database import db, init_db
from app.documents import ensure_repository, sanitize_filename
from app.engine import evaluate_claim
from app.security import get_fernet, hash_password
from app.store import now


def _doc(name: str, body: str) -> dict[str, str]:
    return {"name": name, "body": body}


def _write_encrypted(claim_id: int, original: str, body: str) -> dict:
    from uuid import uuid4
    import hashlib

    folder = CLAIMS_DIR / str(claim_id)
    folder.mkdir(parents=True, exist_ok=True)
    stored = f"{uuid4().hex}.enc"
    raw = body.encode("utf-8")
    (folder / stored).write_bytes(get_fernet().encrypt(raw))
    return {
        "original_name": sanitize_filename(original),
        "stored_name": stored,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
        "text": body,
    }


def seed() -> None:
    init_db()
    ensure_repository()
    with db() as conn:
        exists = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if exists:
            return

    created = now()
    with db() as conn:
        conn.execute(
            "INSERT INTO users (username, display_name, role, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
            ("reviewer", "Priya Nair", "reviewer", hash_password("reviewer123"), created),
        )
        conn.execute(
            "INSERT INTO users (username, display_name, role, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
            ("patient", "Maya Chen", "patient", hash_password("patient123"), created),
        )
        conn.execute(
            "INSERT INTO users (username, display_name, role, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
            ("patient2", "James Okonkwo", "patient", hash_password("patient123"), created),
        )

        patients = [
            (2, "Maya Chen", "1984-04-12", "MBR-441890", "94110"),
            (None, "Robert Hale", "1958-11-03", "MBR-552017", "10011"),
            (None, "Aisha Rahman", "1996-07-22", "MBR-663204", "60614"),
            (3, "James Okonkwo", "2018-01-19", "MBR-774318", "02115"),
            (None, "Linda Park", "1975-09-08", "MBR-885429", "98101"),
        ]
        for user_id, name, dob, member, zipc in patients:
            conn.execute(
                """INSERT INTO patients (user_id, full_name, date_of_birth, member_id, zip_code, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (user_id, name, dob, member, zipc, created),
            )

        policies = [
            (1, "POL-1001-MC", "active", "2024-01-01", "2026-12-31", 25000, 420, 500, 500, "in_network"),
            (2, "POL-1002-RH", "active", "2023-06-01", "2026-12-31", 80000, 2100, 1000, 1000, "in_network"),
            (3, "POL-1003-AR", "expired", "2022-01-01", "2024-12-31", 15000, 15000, 750, 750, "in_network"),
            (4, "POL-1004-JO", "active", "2025-01-01", "2026-12-31", 40000, 0, 250, 0, "in_network"),
            (5, "POL-1005-LP", "active", "2025-03-01", "2026-12-31", 20000, 800, 500, 500, "out_of_network"),
        ]
        for pid, number, status, start, end, limit, used, ded, met, network in policies:
            conn.execute(
                """INSERT INTO policies (patient_id, policy_number, status, effective_from, effective_to,
                    annual_limit, used_to_date, deductible, deductible_met, network, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (pid, number, status, start, end, limit, used, ded, met, network, created),
            )

    samples = _sample_claims()
    for sample in samples:
        _insert_seed_claim(sample)


def _sample_claims() -> list[dict]:
    return [
        {
            "patient_id": 1,
            "policy_id": 1,
            "provider_name": "Bay Clinic",
            "provider_npi": "1234567893",
            "facility": "Bay Clinic — Mission",
            "date_of_service": "2026-08-12",
            "diagnosis_code": "J06.9",
            "procedure_code": "99213",
            "amount": 158.00,
            "place_of_service": "office",
            "is_emergency": 0,
            "preauth_number": "",
            "notes": "Follow-up for acute upper respiratory infection.",
            "docs": [
                _doc("cms1500_chen.txt", MAYA_CLAIM_FORM),
                _doc("itemized_bill_chen.txt", MAYA_BILL),
                _doc("progress_note_chen.txt", MAYA_NOTE),
                _doc("member_id_chen.txt", MAYA_ID),
            ],
        },
        {
            "patient_id": 2,
            "policy_id": 2,
            "provider_name": "Hudson Orthopedics",
            "provider_npi": "1987654328",
            "facility": "St. Anne Surgical Center",
            "date_of_service": "2026-07-02",
            "diagnosis_code": "M17.11",
            "procedure_code": "27447",
            "amount": 27450.00,
            "place_of_service": "outpatient_hospital",
            "is_emergency": 0,
            "preauth_number": "PA-88921",
            "notes": "Right total knee arthroplasty after failed conservative care.",
            "docs": [
                _doc("cms1500_hale.txt", HALE_CLAIM_FORM),
                _doc("itemized_bill_hale.txt", HALE_BILL),
                _doc("op_note_hale.txt", HALE_NOTE),
                _doc("member_id_hale.txt", HALE_ID),
            ],
        },
        {
            "patient_id": 3,
            "policy_id": 3,
            "provider_name": "Lakeside Imaging",
            "provider_npi": "1111111112",
            "facility": "Lakeside Imaging",
            "date_of_service": "2026-06-18",
            "diagnosis_code": "R51.9",
            "procedure_code": "70553",
            "amount": 1420.00,
            "place_of_service": "imaging_center",
            "is_emergency": 0,
            "preauth_number": "",
            "notes": "MRI brain for chronic headache. Policy term already ended.",
            "docs": [
                _doc("invoice_rahman.txt", AISHA_BILL),
                _doc("order_rahman.txt", AISHA_ORDER),
            ],
        },
        {
            "patient_id": 4,
            "policy_id": 4,
            "provider_name": "North End Surgical",
            "provider_npi": "0000000000",
            "facility": "Cash-Pay Pavilion",
            "date_of_service": "2026-08-20",
            "diagnosis_code": "J06.9",
            "procedure_code": "27447",
            "amount": 48000.00,
            "place_of_service": "office",
            "is_emergency": 1,
            "preauth_number": "",
            "notes": "Submitted as emergency knee replacement.",
            "docs": [
                _doc("invoice_okonkwo.txt", JAMES_BILL),
            ],
        },
        {
            "patient_id": 5,
            "policy_id": 5,
            "provider_name": "Pacific Wellness",
            "provider_npi": "1357924681",
            "facility": "Pacific Wellness",
            "date_of_service": "2026-08-01",
            "diagnosis_code": "E11.9",
            "procedure_code": "80053",
            "amount": 85.00,
            "place_of_service": "office",
            "is_emergency": 0,
            "preauth_number": "",
            "notes": "Metabolic panel. Duplicate of an earlier filing.",
            "docs": [
                _doc("cms1500_park.txt", PARK_CLAIM_FORM),
                _doc("itemized_bill_park.txt", PARK_BILL),
                _doc("lab_park.txt", PARK_NOTE),
                _doc("member_id_park.txt", PARK_ID),
            ],
        },
        {
            "patient_id": 5,
            "policy_id": 5,
            "provider_name": "Pacific Wellness",
            "provider_npi": "1357924681",
            "facility": "Pacific Wellness",
            "date_of_service": "2026-08-01",
            "diagnosis_code": "E11.9",
            "procedure_code": "80053",
            "amount": 85.00,
            "place_of_service": "office",
            "is_emergency": 0,
            "preauth_number": "",
            "notes": "Resubmitted metabolic panel.",
            "docs": [
                _doc("cms1500_park_dup.txt", PARK_CLAIM_FORM),
                _doc("itemized_bill_park_dup.txt", PARK_BILL),
            ],
        },
    ]


def _insert_seed_claim(sample: dict) -> None:
    from uuid import uuid4

    created = now()
    public_id = f"CLM-{uuid4().hex[:8].upper()}"
    with db() as conn:
        cur = conn.execute(
            """INSERT INTO claims (
                public_id, patient_id, policy_id, submitted_by, provider_name, provider_npi, facility,
                date_of_service, diagnosis_code, procedure_code, amount, place_of_service, is_emergency,
                preauth_number, notes, status, recommendation, fraud_probability, coverage_ok, confidence,
                rationale, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'SUBMITTED', 'PENDING', 0, 0, 0, '', ?, ?)""",
            (
                public_id,
                sample["patient_id"],
                sample["policy_id"],
                1,
                sample["provider_name"],
                sample["provider_npi"],
                sample["facility"],
                sample["date_of_service"],
                sample["diagnosis_code"],
                sample["procedure_code"],
                sample["amount"],
                sample["place_of_service"],
                sample["is_emergency"],
                sample["preauth_number"] or None,
                sample["notes"],
                created,
                created,
            ),
        )
        claim_id = int(cur.lastrowid)

    stored_docs = []
    with db() as conn:
        for doc in sample["docs"]:
            meta = _write_encrypted(claim_id, doc["name"], doc["body"])
            from app.documents import guess_doc_type

            doc_type = guess_doc_type(doc["name"], doc["body"])
            conn.execute(
                """INSERT INTO documents (claim_id, original_name, stored_name, doc_type, sha256, size_bytes, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (claim_id, meta["original_name"], meta["stored_name"], doc_type, meta["sha256"], meta["size_bytes"], created),
            )
            stored_docs.append({**meta, "doc_type": doc_type})

    with db() as conn:
        patient = dict(conn.execute("SELECT * FROM patients WHERE id = ?", (sample["patient_id"],)).fetchone())
        policy = dict(conn.execute("SELECT * FROM policies WHERE id = ?", (sample["policy_id"],)).fetchone())
        priors = [dict(r) for r in conn.execute("SELECT * FROM claims WHERE patient_id = ?", (sample["patient_id"],)).fetchall()]

    claim = {
        "id": claim_id,
        **{k: sample[k] for k in (
            "provider_name", "provider_npi", "facility", "date_of_service", "diagnosis_code",
            "procedure_code", "amount", "place_of_service", "is_emergency", "preauth_number", "notes",
        )},
    }
    decision = evaluate_claim(claim, policy, patient, stored_docs, priors)
    status = {
        "APPROVE": "APPROVED",
        "DENY": "DENIED",
        "MANUAL_REVIEW": "MANUAL_REVIEW",
        "REQUEST_INFO": "REQUEST_INFO",
    }[decision.recommendation]
    with db() as conn:
        conn.execute(
            """UPDATE claims SET status = ?, recommendation = ?, fraud_probability = ?, coverage_ok = ?,
               confidence = ?, rationale = ?, updated_at = ? WHERE id = ?""",
            (
                status,
                decision.recommendation,
                decision.fraud_probability,
                int(decision.coverage_ok),
                decision.confidence,
                decision.rationale,
                created,
                claim_id,
            ),
        )
        for f in decision.factors:
            conn.execute(
                """INSERT INTO decision_factors (claim_id, name, category, severity, score_delta, passed, detail)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (claim_id, f.name, f.category, f.severity, f.score_delta, int(f.passed), f.detail),
            )
        conn.execute(
            """INSERT INTO audit_log (user_id, action, entity, entity_id, detail, ip, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (1, "seed", "claim", str(claim_id), f"Seeded {public_id} as {status}", "127.0.0.1", created),
        )


MAYA_CLAIM_FORM = """CMS-1500 Claim Form
Patient: Maya Chen
Member ID: MBR-441890
DOB: 1984-04-12
Provider: Bay Clinic  NPI: 1234567893
Date of service: 2026-08-12
ICD-10: J06.9  CPT: 99213
Place of service: 11 Office
"""

MAYA_BILL = """Itemized bill — Bay Clinic
Maya Chen
08/12/2026
99213 Established patient office visit    $158.00
Total due                                 $158.00
"""

MAYA_NOTE = """Progress note
Patient: Maya Chen
History of present illness: 3 days of congestion and sore throat. No fever.
Assessment: Acute upper respiratory infection, unspecified (J06.9)
Plan: Supportive care. Return if symptoms worsen.
"""

MAYA_ID = """Member identification card
Harbor Health Plan
Maya Chen
Member ID: MBR-441890
Policy: POL-1001-MC
"""

HALE_CLAIM_FORM = """CMS-1500 Claim Form
Patient: Robert Hale
Member ID: MBR-552017
Provider: Hudson Orthopedics  NPI: 1987654328
Date of service: 2026-07-02
ICD-10: M17.11  CPT: 27447
Prior authorization: PA-88921
"""

HALE_BILL = """Itemized surgical bill — St. Anne Surgical Center
Robert Hale
07/02/2026
27447 Total knee arthroplasty                $18,400.00
Facility and implant                        $9,050.00
Total                                      $27,450.00
"""

HALE_NOTE = """Operative note
Patient: Robert Hale, age 67
Indication: Primary osteoarthritis of the right knee (M17.11) refractory to NSAIDs and PT.
Procedure: Right total knee arthroplasty (27447). Unremarkable intraoperative course.
"""

HALE_ID = """Member identification card
Harbor Health Plan
Robert Hale
Member ID: MBR-552017
"""

AISHA_BILL = """Invoice — Lakeside Imaging
Patient: Aisha Rahman
MRI brain without and with contrast (70553)   $1,420.00
"""

AISHA_ORDER = """Imaging order
MRI brain for chronic headache, R51.9
No prior authorization on file.
"""

JAMES_BILL = """Invoice
Patient: J.O.
Emergency total knee  $48000
Cash pay pavilion
"""

PARK_CLAIM_FORM = """CMS-1500 Claim Form
Patient: Linda Park
Member ID: MBR-885429
Provider: Pacific Wellness
Date of service: 2026-08-01
ICD-10: E11.9  CPT: 80053
"""

PARK_BILL = """Itemized bill
Linda Park
Comprehensive metabolic panel 80053   $85.00
"""

PARK_NOTE = """Lab report
Patient: Linda Park
Type 2 diabetes mellitus without complications (E11.9)
CMP within expected range. Continue current regimen.
"""

PARK_ID = """Member identification card
Linda Park
Member ID: MBR-885429
"""

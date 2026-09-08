# Sentinel Claim Review

Local application for insurance claim document review. A patient or reviewer submits a claim with supporting files; the engine checks coverage, documentation completeness, and fraud probability, then recommends approve, deny, request more information, or manual review.

All documents stay on this machine. They are encrypted at rest in a local folder. The server binds to `127.0.0.1` only.

## Run

```bash
cd InsuranceApprovalSystem
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

Open [http://127.0.0.1:8787](http://127.0.0.1:8787).

| Role | Username | Password |
| --- | --- | --- |
| Claims reviewer | `reviewer` | `reviewer123` |
| Patient (Maya Chen) | `patient` | `patient123` |

First launch creates `data/app.db`, encryption keys, and six sample claims so the desk is not empty.

| Sample | What it shows |
| --- | --- |
| Maya Chen, office visit 99213 | Complete packet, in-force policy → **approve**, low fraud |
| Robert Hale, knee replacement 27447 | High-cost but covered, prior auth, UCR in range → **approve** |
| Aisha Rahman, MRI after policy ended | **deny** on coverage |
| James Okonkwo, pediatric TKA | Age/procedure mismatch, bad NPI, missing docs → **deny**, fraud ≈ 97% |
| Linda Park, CMP | Out-of-network → **manual review** |
| Linda Park, same CMP again | Duplicate filing → **deny** |

## What the engine weighs

**Coverage.** Policy active on the date of service, remaining annual limit, in-network vs out-of-network, excluded procedures, prior authorization for high-cost CPTs.

**Documentation.** Claim form, itemized bill, medical record, and ID; file substance; patient name in the documents; billed amount vs claimed amount.

**Fraud.** Age vs procedure, ICD-10 vs CPT pairing, CMS NPI checksum, usual-customary-reasonable rate, duplicate filings, claim frequency, timely filing, round-dollar billing, emergency flag on elective surgery.

The fraud probability is a calibrated score from those weights. Every factor is stored with the claim so a reviewer can see why the engine recommended a decision.

## Document repository

Path: `data/repository/`

- `claims/<id>/*.enc` — encrypted uploads for a claim
- `inbox/` — optional staging drop folder (not auto-ingested)

Keys live at `data/master.key` and `data/secret.key` (mode `600`). Do not commit them.

## Security

- Localhost only; API docs disabled
- Fernet encryption for files on disk; UUID filenames
- PBKDF2 password hashes, CSRF, SameSite cookies, login throttling
- Path confinement so uploads cannot leave the repository
- Member IDs masked in the UI
- Audit log for sign-in, decisions, and downloads

This is a workstation demo, not a HIPAA-certified product. Treat demo passwords as disposable.

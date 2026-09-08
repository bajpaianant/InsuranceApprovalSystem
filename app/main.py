from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from app.config import (
    ALLOWED_EXTENSIONS,
    CLAIMS_DIR,
    HOST,
    INBOX_DIR,
    MAX_UPLOAD_BYTES,
    PORT,
    REPOSITORY_DIR,
    REQUIRED_DOC_TYPES,
    SESSION_HOURS,
)
from app.documents import decode_text, ensure_repository, guess_doc_type, read_decrypted, store_upload
from app.engine import evaluate_claim
from app.security import get_secret_key, login_throttle, mask_id, new_csrf, verify_password
from app.seed import seed
from app.store import (
    dashboard_stats,
    get_claim,
    get_document,
    get_patient,
    get_patient_for_user,
    get_policy_for_patient,
    get_user,
    get_user_by_username,
    insert_claim,
    insert_document,
    list_audit,
    list_claims,
    list_documents,
    list_factors,
    list_patients,
    now,
    prior_claims,
    replace_factors,
    update_claim,
    write_audit,
)

ROOT = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(ROOT / "templates"))
templates.env.globals["mask_id"] = mask_id
templates.env.globals["pct"] = lambda v: f"{float(v) * 100:.0f}%"

app = FastAPI(title="Sentinel Claim Review", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    SessionMiddleware,
    secret_key=get_secret_key(),
    session_cookie="sentinel_session",
    max_age=SESSION_HOURS * 3600,
    same_site="strict",
    https_only=False,
)
app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; "
        "img-src 'self' data:; form-action 'self'; base-uri 'self'; frame-ancestors 'none'"
    )
    return response


@app.on_event("startup")
def startup() -> None:
    seed()
    ensure_repository()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def current_user(request: Request) -> dict[str, Any] | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return get_user(int(user_id))


def require_user(request: Request) -> dict[str, Any] | RedirectResponse:
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return user


def csrf_ok(request: Request, token: str) -> bool:
    expected = request.session.get("csrf")
    return bool(expected) and secrets.compare_digest(str(expected), token or "")


def ensure_csrf(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = new_csrf()
        request.session["csrf"] = token
    return token


def can_access_claim(user: dict[str, Any], claim: dict[str, Any]) -> bool:
    if user["role"] == "reviewer":
        return True
    patient = get_patient_for_user(user["id"])
    return bool(patient) and patient["id"] == claim["patient_id"]


def persist_decision(claim_id: int, claim: dict[str, Any], patient: dict[str, Any], policy: dict[str, Any] | None) -> None:
    docs = list_documents(claim_id)
    for d in docs:
        try:
            raw = read_decrypted(claim_id, d["stored_name"])
            d["text"] = decode_text(raw, d["original_name"])
        except Exception:
            d["text"] = ""
    decision = evaluate_claim(claim, policy, patient, docs, prior_claims(patient["id"]))
    status = {
        "APPROVE": "APPROVED",
        "DENY": "DENIED",
        "MANUAL_REVIEW": "MANUAL_REVIEW",
        "REQUEST_INFO": "REQUEST_INFO",
    }[decision.recommendation]
    update_claim(
        claim_id,
        {
            "status": status,
            "recommendation": decision.recommendation,
            "fraud_probability": decision.fraud_probability,
            "coverage_ok": int(decision.coverage_ok),
            "confidence": decision.confidence,
            "rationale": decision.rationale,
            "updated_at": now(),
        },
    )
    replace_factors(claim_id, [f.as_dict() for f in decision.factors])


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> Any:
    if current_user(request):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        request,
        "login.html",
        {"csrf": ensure_csrf(request), "error": None},
    )


@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...), csrf: str = Form("")) -> Any:
    if not csrf_ok(request, csrf):
        return templates.TemplateResponse(request, "login.html", {"csrf": ensure_csrf(request), "error": "Session expired. Try again."}, status_code=400)
    key = f"{client_ip(request)}:{username.lower()}"
    if login_throttle.blocked(key):
        write_audit(None, "login_blocked", "user", username, "too many attempts", client_ip(request))
        return templates.TemplateResponse(request, "login.html", {"csrf": ensure_csrf(request), "error": "Too many attempts. Wait a few minutes."}, status_code=429)
    user = get_user_by_username(username.strip())
    if not user or not verify_password(password, user["password_hash"]):
        login_throttle.hit(key)
        write_audit(None, "login_failed", "user", username, "invalid credentials", client_ip(request))
        return templates.TemplateResponse(request, "login.html", {"csrf": ensure_csrf(request), "error": "Invalid username or password."}, status_code=401)
    login_throttle.clear(key)
    request.session.clear()
    request.session["user_id"] = user["id"]
    request.session["role"] = user["role"]
    request.session["csrf"] = new_csrf()
    write_audit(user["id"], "login", "user", str(user["id"]), "signed in", client_ip(request))
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
async def logout(request: Request, csrf: str = Form("")) -> Any:
    user = current_user(request)
    if csrf_ok(request, csrf) and user:
        write_audit(user["id"], "logout", "user", str(user["id"]), "signed out", client_ip(request))
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> Any:
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    patient = get_patient_for_user(user["id"]) if user["role"] == "patient" else None
    stats = dashboard_stats(user["role"], patient["id"] if patient else None)
    claims = list_claims(user["role"], user["id"], patient["id"] if patient else None)[:8]
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "user": user,
            "csrf": ensure_csrf(request),
            "stats": stats,
            "claims": claims,
            "repository": str(REPOSITORY_DIR),
        },
    )


@app.get("/claims", response_class=HTMLResponse)
def claims_page(request: Request) -> Any:
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    patient = get_patient_for_user(user["id"]) if user["role"] == "patient" else None
    return templates.TemplateResponse(
        request,
        "claims.html",
        {
            "user": user,
            "csrf": ensure_csrf(request),
            "claims": list_claims(user["role"], user["id"], patient["id"] if patient else None),
        },
    )


@app.get("/claims/new", response_class=HTMLResponse)
def new_claim_page(request: Request) -> Any:
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    patients = list_patients() if user["role"] == "reviewer" else []
    patient = get_patient_for_user(user["id"]) if user["role"] == "patient" else None
    return templates.TemplateResponse(
        request,
        "new_claim.html",
        {
            "user": user,
            "csrf": ensure_csrf(request),
            "patients": patients,
            "patient": patient,
            "error": None,
            "allowed": ", ".join(sorted(ALLOWED_EXTENSIONS)),
        },
    )


@app.post("/claims/new")
async def create_claim(
    request: Request,
    csrf: str = Form(""),
    patient_id: int | None = Form(None),
    provider_name: str = Form(...),
    provider_npi: str = Form(...),
    facility: str = Form(""),
    date_of_service: str = Form(...),
    diagnosis_code: str = Form(...),
    procedure_code: str = Form(...),
    amount: float = Form(...),
    place_of_service: str = Form("office"),
    is_emergency: str = Form("0"),
    preauth_number: str = Form(""),
    notes: str = Form(""),
    files: list[UploadFile] | None = File(None),
) -> Any:
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    ctx_patients = list_patients() if user["role"] == "reviewer" else []
    patient_self = get_patient_for_user(user["id"]) if user["role"] == "patient" else None

    def fail(msg: str) -> Any:
        return templates.TemplateResponse(
            request,
            "new_claim.html",
            {
                "user": user,
                "csrf": ensure_csrf(request),
                "patients": ctx_patients,
                "patient": patient_self,
                "error": msg,
                "allowed": ", ".join(sorted(ALLOWED_EXTENSIONS)),
            },
            status_code=400,
        )

    if not csrf_ok(request, csrf):
        return fail("Session expired. Reload and try again.")

    if user["role"] == "patient":
        if not patient_self:
            return fail("No patient record is linked to this account.")
        pid = patient_self["id"]
    else:
        if not patient_id:
            return fail("Select a patient.")
        pid = int(patient_id)

    patient = get_patient(pid)
    if not patient:
        return fail("Patient not found.")

    policy = get_policy_for_patient(pid)
    created = now()
    public_id = f"CLM-{uuid4().hex[:8].upper()}"
    claim_id = insert_claim(
        {
            "public_id": public_id,
            "patient_id": pid,
            "policy_id": policy["id"] if policy else None,
            "submitted_by": user["id"],
            "provider_name": provider_name.strip(),
            "provider_npi": provider_npi.strip(),
            "facility": facility.strip(),
            "date_of_service": date_of_service,
            "diagnosis_code": diagnosis_code.strip().upper(),
            "procedure_code": procedure_code.strip().upper(),
            "amount": float(amount),
            "place_of_service": place_of_service,
            "is_emergency": 1 if is_emergency == "1" else 0,
            "preauth_number": preauth_number.strip() or None,
            "notes": notes.strip(),
            "status": "SUBMITTED",
            "recommendation": "PENDING",
            "fraud_probability": 0,
            "coverage_ok": 0,
            "confidence": 0,
            "rationale": "",
            "created_at": created,
            "updated_at": created,
        }
    )

    uploads = [f for f in (files or []) if f.filename]
    for upload in uploads:
        raw = await upload.read()
        try:
            meta = store_upload(claim_id, upload, raw)
        except ValueError as exc:
            return fail(str(exc))
        text = decode_text(raw, meta["original_name"])
        insert_document(
            {
                "claim_id": claim_id,
                "original_name": meta["original_name"],
                "stored_name": meta["stored_name"],
                "doc_type": guess_doc_type(meta["original_name"], text),
                "sha256": meta["sha256"],
                "size_bytes": meta["size_bytes"],
                "created_at": created,
            }
        )

    claim = {
        "id": claim_id,
        "provider_name": provider_name,
        "provider_npi": provider_npi,
        "facility": facility,
        "date_of_service": date_of_service,
        "diagnosis_code": diagnosis_code.strip().upper(),
        "procedure_code": procedure_code.strip().upper(),
        "amount": float(amount),
        "place_of_service": place_of_service,
        "is_emergency": 1 if is_emergency == "1" else 0,
        "preauth_number": preauth_number.strip(),
        "notes": notes,
    }
    persist_decision(claim_id, claim, patient, policy)
    write_audit(user["id"], "create", "claim", str(claim_id), f"Submitted {public_id}", client_ip(request))
    return RedirectResponse(f"/claims/{claim_id}", status_code=303)


@app.get("/claims/{claim_id}", response_class=HTMLResponse)
def claim_detail(request: Request, claim_id: int) -> Any:
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    claim = get_claim(claim_id)
    if not claim or not can_access_claim(user, claim):
        return templates.TemplateResponse(request, "not_found.html", {"user": user, "csrf": ensure_csrf(request)}, status_code=404)
    return templates.TemplateResponse(
        request,
        "claim_detail.html",
        {
            "user": user,
            "csrf": ensure_csrf(request),
            "claim": claim,
            "documents": list_documents(claim_id),
            "factors": list_factors(claim_id),
        },
    )


@app.post("/claims/{claim_id}/decision")
async def apply_reviewer_decision(
    request: Request,
    claim_id: int,
    csrf: str = Form(""),
    action: str = Form(...),
    reviewer_note: str = Form(""),
) -> Any:
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if user["role"] != "reviewer" or not csrf_ok(request, csrf):
        return RedirectResponse(f"/claims/{claim_id}", status_code=303)
    claim = get_claim(claim_id)
    if not claim:
        return RedirectResponse("/claims", status_code=303)
    mapping = {"approve": "APPROVED", "deny": "DENIED", "review": "MANUAL_REVIEW", "info": "REQUEST_INFO"}
    if action not in mapping:
        return RedirectResponse(f"/claims/{claim_id}", status_code=303)
    update_claim(
        claim_id,
        {
            "status": mapping[action],
            "reviewer_id": user["id"],
            "reviewer_action": action,
            "reviewer_note": reviewer_note.strip(),
            "updated_at": now(),
        },
    )
    write_audit(user["id"], action, "claim", str(claim_id), reviewer_note.strip() or mapping[action], client_ip(request))
    return RedirectResponse(f"/claims/{claim_id}", status_code=303)


@app.get("/claims/{claim_id}/documents/{doc_id}")
def download_document(request: Request, claim_id: int, doc_id: int) -> Any:
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    claim = get_claim(claim_id)
    doc = get_document(doc_id)
    if not claim or not doc or doc["claim_id"] != claim_id or not can_access_claim(user, claim):
        return Response("Not found", status_code=404)
    try:
        raw = read_decrypted(claim_id, doc["stored_name"])
    except Exception:
        return Response("Unable to decrypt document", status_code=500)
    write_audit(user["id"], "download", "document", str(doc_id), doc["original_name"], client_ip(request))
    return Response(
        content=raw,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{doc["original_name"]}"'},
    )


@app.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request) -> Any:
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if user["role"] != "reviewer":
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        request,
        "audit.html",
        {"user": user, "csrf": ensure_csrf(request), "events": list_audit()},
    )


@app.get("/security", response_class=HTMLResponse)
def security_page(request: Request) -> Any:
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    claim_count = 0
    file_count = 0
    if CLAIMS_DIR.exists():
        file_count = sum(1 for p in CLAIMS_DIR.rglob("*.enc"))
        claim_count = sum(1 for p in CLAIMS_DIR.iterdir() if p.is_dir())
    return templates.TemplateResponse(
        request,
        "security.html",
        {
            "user": user,
            "csrf": ensure_csrf(request),
            "repository": str(REPOSITORY_DIR),
            "claims_dir": str(CLAIMS_DIR),
            "inbox": str(INBOX_DIR),
            "claim_count": claim_count,
            "file_count": file_count,
            "max_upload": MAX_UPLOAD_BYTES // (1024 * 1024),
            "required_docs": REQUIRED_DOC_TYPES,
            "host": HOST,
            "port": PORT,
        },
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}

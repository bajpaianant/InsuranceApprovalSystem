from __future__ import annotations

import hashlib
import re
import uuid
from pathlib import Path

from fastapi import UploadFile

from app.config import ALLOWED_EXTENSIONS, CLAIMS_DIR, INBOX_DIR, MAX_UPLOAD_BYTES, REPOSITORY_DIR
from app.security import get_fernet


SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def ensure_repository() -> None:
    CLAIMS_DIR.mkdir(parents=True, exist_ok=True)
    INBOX_DIR.mkdir(parents=True, exist_ok=True)
    (REPOSITORY_DIR / "README.txt").write_text(
        "Sentinel local document repository.\n"
        "Files under claims/ are encrypted at rest.\n"
        "Drop files into inbox/ only as a staging area; they are not ingested until attached to a claim.\n",
        encoding="utf-8",
    )


def claim_dir(claim_id: int) -> Path:
    path = CLAIMS_DIR / str(claim_id)
    path.mkdir(parents=True, exist_ok=True)
    return path


def sanitize_filename(name: str) -> str:
    base = Path(name).name
    cleaned = SAFE_NAME.sub("_", base).strip("._")
    return cleaned[:120] or "document"


def extension_ok(name: str) -> bool:
    return Path(name).suffix.lower() in ALLOWED_EXTENSIONS


def confined(path: Path) -> Path:
    resolved = path.resolve()
    root = REPOSITORY_DIR.resolve()
    if root not in resolved.parents and resolved != root:
        raise ValueError("path escapes the document repository")
    return resolved


def store_upload(claim_id: int, upload: UploadFile, raw: bytes) -> dict:
    if len(raw) > MAX_UPLOAD_BYTES:
        raise ValueError("file exceeds the 10 MB limit")
    if not extension_ok(upload.filename or ""):
        raise ValueError("file type is not allowed")
    original = sanitize_filename(upload.filename or "document")
    stored = f"{uuid.uuid4().hex}.enc"
    target = confined(claim_dir(claim_id) / stored)
    token = get_fernet().encrypt(raw)
    target.write_bytes(token)
    try:
        target.chmod(0o600)
    except OSError:
        pass
    return {
        "original_name": original,
        "stored_name": stored,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
    }


def read_decrypted(claim_id: int, stored_name: str) -> bytes:
    path = confined(claim_dir(claim_id) / stored_name)
    if not path.is_file():
        raise FileNotFoundError("document not found")
    return get_fernet().decrypt(path.read_bytes())


def decode_text(raw: bytes, name: str) -> str:
    suffix = Path(name).suffix.lower()
    if suffix in {".txt", ".md", ".json"}:
        return raw.decode("utf-8", errors="replace")
    return ""


def guess_doc_type(name: str, text: str) -> str:
    blob = f"{name} {text}".lower()
    if any(k in blob for k in ("claim form", "cms-1500", "ub-04", "claim_form")):
        return "claim_form"
    if any(k in blob for k in ("itemized", "invoice", "charges", "bill")):
        return "itemized_bill"
    if any(k in blob for k in ("progress note", "medical record", "history of present", "operative note", "lab report", "clinical note")):
        return "medical_record"
    if any(k in blob for k in ("driver license", "passport", "member id", "identification")):
        return "id_document"
    if any(k in blob for k in ("referral", "preauth", "prior auth")):
        return "preauth"
    return "supporting"

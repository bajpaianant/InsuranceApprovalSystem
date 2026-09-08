from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from collections import defaultdict, deque
from pathlib import Path

from cryptography.fernet import Fernet

from app.config import LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_SECONDS, MASTER_KEY_PATH, SECRET_KEY_PATH


def ensure_key_file(path: Path) -> bytes:
    if path.exists():
        return path.read_bytes().strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key() if path == MASTER_KEY_PATH else secrets.token_bytes(32)
    path.write_bytes(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def get_fernet() -> Fernet:
    return Fernet(ensure_key_file(MASTER_KEY_PATH))


def get_secret_key() -> bytes:
    return ensure_key_file(SECRET_KEY_PATH)


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 210_000)
    return f"pbkdf2_sha256$210000${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, rounds, salt_hex, digest_hex = stored.split("$", 3)
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(digest_hex)
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(rounds))
    return hmac.compare_digest(actual, expected)


def new_csrf() -> str:
    return secrets.token_urlsafe(32)


def mask_id(value: str, keep: int = 4) -> str:
    if not value:
        return "—"
    if len(value) <= keep:
        return "•" * len(value)
    return ("•" * (len(value) - keep)) + value[-keep:]


def npi_checksum_ok(npi: str) -> bool:
    digits = "".join(ch for ch in npi if ch.isdigit())
    if len(digits) != 10:
        return False
    # CMS NPI Luhn check with prefix 80840
    payload = "80840" + digits
    total = 0
    reverse = payload[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


class LoginThrottle:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def blocked(self, key: str) -> bool:
        now = time.time()
        window = self._hits[key]
        while window and now - window[0] > LOGIN_WINDOW_SECONDS:
            window.popleft()
        return len(window) >= LOGIN_MAX_ATTEMPTS

    def hit(self, key: str) -> None:
        self._hits[key].append(time.time())

    def clear(self, key: str) -> None:
        self._hits.pop(key, None)


login_throttle = LoginThrottle()

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Optional

from app.core.config import get_settings


settings = get_settings()

PBKDF2_ITERATIONS = 260_000
TOKEN_VERSION = 3
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


def validate_password(password: str) -> None:
    minimum = max(settings.PASSWORD_MIN_LENGTH, MIN_PASSWORD_LENGTH)
    if len(password) < minimum:
        raise ValueError(f"Password must be at least {minimum} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at most {MAX_PASSWORD_LENGTH} characters")
    if password.strip() != password:
        raise ValueError("Password must not start or end with whitespace")


def hash_password(password: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), PBKDF2_ITERATIONS
    ).hex()
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        parts = stored_hash.split("$")
        if len(parts) == 4 and parts[0] == "pbkdf2_sha256":
            _, iterations, salt, expected = parts
            computed = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), salt.encode(), int(iterations)
            ).hex()
        elif len(parts) == 2:
            salt, expected = parts
            computed = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), salt.encode(), 100_000
            ).hex()
        else:
            return False
        return hmac.compare_digest(computed, expected)
    except Exception:
        return False


def sign_token(payload: dict) -> str:
    token_payload = dict(payload)
    token_payload["ver"] = TOKEN_VERSION
    token_payload["iat"] = int(time.time())
    token_payload["exp"] = int(time.time() + settings.ACCESS_TOKEN_EXPIRE_HOURS * 3600)
    encoded = base64.urlsafe_b64encode(
        json.dumps(token_payload, separators=(",", ":")).encode()
    ).decode()
    signature = hmac.new(
        settings.SECRET_KEY.encode(), encoded.encode(), hashlib.sha256
    ).hexdigest()
    return f"{encoded}.{signature}"


def decode_token(token: str) -> Optional[dict]:
    try:
        encoded, signature = token.split(".")
        expected_signature = hmac.new(
            settings.SECRET_KEY.encode(), encoded.encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(signature, expected_signature):
            return None
        payload = json.loads(base64.urlsafe_b64decode(encoded).decode())
        if payload.get("ver") != TOKEN_VERSION:
            return None
        if int(payload.get("exp", 0)) < time.time():
            return None
        if not payload.get("sub") or not payload.get("role"):
            return None
        return payload
    except Exception:
        return None


def password_fingerprint(stored_hash: str) -> str:
    return hashlib.sha256(stored_hash.encode()).hexdigest()[:32]


def create_access_token(username: str, role: str, password_hash: str) -> str:
    return sign_token(
        {
            "sub": username,
            "role": role,
            "pv": password_fingerprint(password_hash),
        }
    )

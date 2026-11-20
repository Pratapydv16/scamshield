import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt

ALGORITHM = "HS256"


def _secret() -> str:
    secret = os.getenv("JWT_SECRET", "")
    if len(secret) < 32 or secret == "replace-with-a-long-random-secret":
        raise RuntimeError("JWT_SECRET must be at least 32 characters and unique")
    return secret


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return "scrypt$" + salt.hex() + "$" + digest.hex()


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, salt_hex, digest_hex = encoded.split("$")
        if algorithm != "scrypt":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def create_access_token(subject: str) -> tuple[str, int]:
    expires_minutes = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
    if not 1 <= expires_minutes <= 1440:
        raise RuntimeError("JWT_EXPIRE_MINUTES must be between 1 and 1440")
    expires_in = expires_minutes * 60
    expires = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    token = jwt.encode({"sub": subject, "exp": expires}, _secret(), algorithm=ALGORITHM)
    return token, expires_in


def read_access_token(token: str) -> str | None:
    try:
        claims = jwt.decode(token, _secret(), algorithms=[ALGORITHM])
        subject = claims.get("sub")
        return subject if isinstance(subject, str) else None
    except JWTError:
        return None


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def hash_scan_input(content: str) -> str:
    return hmac.new(_secret().encode(), content.encode(), hashlib.sha256).hexdigest()


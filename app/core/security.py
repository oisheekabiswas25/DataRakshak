
import os
from datetime import datetime, timedelta, timezone

import jwt
from dotenv import load_dotenv
from pwdlib import PasswordHash

load_dotenv()

SECRET_KEY = os.getenv("AUTH_SECRET_KEY")
ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv("AUTH_TOKEN_EXPIRE_MINUTES", "120")
)

if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise ValueError("A strong AUTH_SECRET_KEY is required.")

password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("Password must contain at least 12 characters.")

    return password_hash.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return password_hash.verify(password, hashed_password)


def create_access_token(
    username: str,
    role: str,
    expires_minutes: int | None = None
) -> str:

    if not username or role not in {"admin", "user"}:
        raise ValueError("Invalid username or role.")

    duration = (
        expires_minutes
        if expires_minutes is not None
        else ACCESS_TOKEN_EXPIRE_MINUTES
    )

    if duration <= 0:
        raise ValueError("Token expiry must be positive.")

    now = datetime.now(timezone.utc)

    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=duration)
    }

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"require": ["sub", "role", "iat", "exp"]}
        )

        if not isinstance(payload["sub"], str) or not payload["sub"]:
            raise PermissionError("Invalid token subject.")

        if payload["role"] not in {"admin", "user"}:
            raise PermissionError("Invalid token role.")

        return payload

    except jwt.InvalidTokenError as error:
        raise PermissionError(
            "Invalid or expired access token."
        ) from error


def can_restore_tokens(user: dict) -> bool:
    return user.get("role") == "admin"

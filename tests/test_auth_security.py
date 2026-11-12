
import jwt
import pytest

from datetime import datetime, timedelta, timezone

from app.core.security import (
    SECRET_KEY,
    ALGORITHM,
    create_access_token,
    verify_access_token
)


def test_valid_admin_token():

    token = create_access_token("testadmin", "admin")

    payload = verify_access_token(token)

    assert payload["sub"] == "testadmin"
    assert payload["role"] == "admin"


def test_valid_user_token():

    token = create_access_token("testuser", "user")

    payload = verify_access_token(token)

    assert payload["role"] == "user"


def test_expired_token():

    payload = {
        "sub": "testadmin",
        "role": "admin",
        "iat": datetime.now(timezone.utc) - timedelta(hours=2),
        "exp": datetime.now(timezone.utc) - timedelta(hours=1)
    }

    token = jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    with pytest.raises(PermissionError):
        verify_access_token(token)


def test_tampered_token():

    token = create_access_token("testadmin", "admin")

    tampered = token[:-1] + (
        "A" if token[-1] != "A" else "B"
    )

    with pytest.raises(PermissionError):
        verify_access_token(tampered)


def test_invalid_role():

    payload = {
        "sub": "testadmin",
        "role": "superuser",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=30)
    }

    token = jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    with pytest.raises(PermissionError):
        verify_access_token(token)

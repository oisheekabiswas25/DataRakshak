import hashlib
import pytest

from cryptography.fernet import Fernet
from app.database.vault import TokenVault


@pytest.fixture
def vault(tmp_path, monkeypatch):

    key = Fernet.generate_key().decode()

    monkeypatch.setenv("VAULT_ENCRYPTION_KEY", key)

    return TokenVault(
        db_path=str(tmp_path / "test_vault.db"),
        ttl_minutes=30
    )


def test_tokenization(vault):

    token = vault.store("ABCDE1234F", "IN_PAN")

    assert token.startswith("<TOKEN_")


def test_authorized_restoration(vault):

    original = "ABCDE1234F"
    token = vault.store(original, "IN_PAN")

    restored = vault.restore(token, actor="testadmin")

    assert restored == original


def test_unauthorized_restoration(vault):

    token = vault.store("ABCDE1234F", "IN_PAN")

    with pytest.raises(PermissionError):
        vault.restore(token, actor="")


def test_restoration_audit(vault):

    token = vault.store("ABCDE1234F", "IN_PAN")

    vault.restore(token, actor="testadmin")

    with vault._connect() as conn:
        row = conn.execute(
            "SELECT actor, action, outcome FROM vault_audit"
        ).fetchone()

    assert row == ("testadmin", "RESTORE", "SUCCESS")


def test_delete_token(vault):

    token = vault.store("ABCDE1234F", "IN_PAN")

    assert vault.delete(token) is True

    with pytest.raises(KeyError):
        vault.restore(token, actor="testadmin")

def test_expired_token_is_deleted_and_audited(vault):

    original = "ABCDE1234F"
    token = vault.store(original, "IN_PAN")

    # Force the token's expiry timestamp into the past.
    with vault._connect() as conn:
        conn.execute(
            "UPDATE token_vault SET expires_at = ? WHERE token = ?",
            ("2000-01-01T00:00:00+00:00", token)
        )

    # Expired tokens must not be restored.
    with pytest.raises(ValueError, match="Token has expired"):
        vault.restore(token, actor="testadmin")

    # Verify the expired token was deleted.
    with vault._connect() as conn:
        token_row = conn.execute(
            "SELECT token FROM token_vault WHERE token = ?",
            (token,)
        ).fetchone()

        audit_row = conn.execute(
            """SELECT actor, action, token_fingerprint, outcome
               FROM vault_audit"""
        ).fetchone()

    assert token_row is None
    assert audit_row[0] == "testadmin"
    assert audit_row[1] == "RESTORE"
    assert audit_row[2] == hashlib.sha256(token.encode()).hexdigest()
    assert audit_row[3] == "EXPIRED"
    assert original not in str(audit_row)

import pytest

from app.services.privacy_engine import PrivacyEngine

engine = PrivacyEngine()

sample = "My PAN is ABCDE1234F."


def test_redact():
    result = engine.process(sample, "redact")
    assert result["status"] == "protected"
    assert "ABCDE1234F" not in result["text"]


def test_block():
    result = engine.process(sample, "block")
    assert result["status"] == "blocked"
    assert result["text"] is None


def test_allow():
    result = engine.process(sample, "allow")
    assert result["status"] == "allowed"
    assert result["text"] == sample


def test_invalid_action():
    with pytest.raises(ValueError):
        engine.process(sample, "invalid")


def test_no_pii():
    result = engine.process("Hello, how are you?", "block")
    assert result["status"] == "allowed"


def test_invalid_input():
    with pytest.raises(TypeError):
        engine.process(None, "redact")


from cryptography.fernet import Fernet
from app.database.vault import TokenVault


def test_tokenize(tmp_path, monkeypatch):

    key = Fernet.generate_key().decode()

    monkeypatch.setenv(
        "VAULT_ENCRYPTION_KEY",
        key
    )

    vault = TokenVault(
        db_path=str(tmp_path / "token_test.db")
    )

    engine = PrivacyEngine(vault=vault)

    sample = "My PAN is ABCDE1234F."

    result = engine.process(
        sample,
        action="tokenize"
    )

    assert result["status"] == "tokenized"
    assert result["token_count"] == 1
    assert "ABCDE1234F" not in result["text"]
    assert "<TOKEN_" in result["text"]


def test_tokenize_multiple_identifiers(tmp_path, monkeypatch):

    key = Fernet.generate_key().decode()

    monkeypatch.setenv(
        "VAULT_ENCRYPTION_KEY",
        key
    )

    vault = TokenVault(
        db_path=str(tmp_path / "multiple_tokens.db")
    )

    engine = PrivacyEngine(vault=vault)

    sample = (
        "PAN ABCDE1234F and "
        "Driving Licence OD-02-2020-1234567"
    )

    result = engine.process(
        sample,
        action="tokenize"
    )

    assert result["status"] == "tokenized"
    assert result["token_count"] == 2
    assert "ABCDE1234F" not in result["text"]
    assert "OD-02-2020-1234567" not in result["text"]

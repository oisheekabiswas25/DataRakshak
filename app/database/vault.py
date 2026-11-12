
import os
import sqlite3
import uuid
import hashlib

from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()


class TokenVault:

    def __init__(self, db_path="data/token_vault.db", ttl_minutes=30):

        key = os.getenv("VAULT_ENCRYPTION_KEY")

        if not key:
            raise ValueError("VAULT_ENCRYPTION_KEY missing in .env")

        self.cipher = Fernet(key.encode())
        self.db_path = Path(db_path)
        self.ttl_minutes = ttl_minutes

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._create_table()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _create_table(self):

        with self._connect() as conn:

            conn.execute("""
                CREATE TABLE IF NOT EXISTS token_vault (
                    token TEXT PRIMARY KEY,
                    entity_type TEXT NOT NULL,
                    encrypted_value BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS vault_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    token_fingerprint TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
            """)

    def _audit(self, actor, action, token, outcome):

        fingerprint = hashlib.sha256(
            token.encode()
        ).hexdigest()

        timestamp = datetime.now(timezone.utc).isoformat()

        with self._connect() as conn:
            conn.execute("""
                INSERT INTO vault_audit
                (actor, action, token_fingerprint, outcome, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (
                actor,
                action,
                fingerprint,
                outcome,
                timestamp
            ))

    def store(self, value, entity_type):

        if not isinstance(value, str) or not value:
            raise ValueError("Value must be a non-empty string")

        token = f"<TOKEN_{uuid.uuid4().hex[:12]}>"

        encrypted_value = self.cipher.encrypt(value.encode())

        now = datetime.now(timezone.utc)
        expires = now + timedelta(minutes=self.ttl_minutes)

        with self._connect() as conn:
            conn.execute("""
                INSERT INTO token_vault
                VALUES (?, ?, ?, ?, ?)
            """, (
                token,
                entity_type,
                encrypted_value,
                now.isoformat(),
                expires.isoformat()
            ))

        return token

    def restore(self, token, actor):

        if not isinstance(actor, str) or not actor.strip():
            raise PermissionError("Authenticated actor required.")

        if not isinstance(token, str) or not token:
            raise ValueError("Valid token is required.")

        with self._connect() as conn:
            row = conn.execute("""
                SELECT encrypted_value, expires_at
                FROM token_vault
                WHERE token = ?
            """, (token,)).fetchone()

        if row is None:
            self._audit(actor, "RESTORE", token, "NOT_FOUND")
            raise KeyError("Token not found")

        encrypted_value, expires_at = row
        expiry = datetime.fromisoformat(expires_at)

        if datetime.now(timezone.utc) >= expiry:

            self.delete(token)
            self._audit(actor, "RESTORE", token, "EXPIRED")

            raise ValueError("Token has expired")

        restored_value = self.cipher.decrypt(
            encrypted_value
        ).decode()

        self._audit(actor, "RESTORE", token, "SUCCESS")

        return restored_value

    def delete(self, token):

        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM token_vault WHERE token = ?",
                (token,)
            )

        return cursor.rowcount > 0

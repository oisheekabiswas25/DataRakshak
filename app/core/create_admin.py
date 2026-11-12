
import sqlite3
from getpass import getpass

from app.services.auth_service import AuthService


def main():
    auth = AuthService()

    with sqlite3.connect(auth.db_path) as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0]

    if count > 0:
        print("Setup stopped: users already exist.")
        return

    username = input("Enter admin username: ").strip()
    password = getpass("Enter admin password: ")
    confirm = getpass("Confirm admin password: ")

    if password != confirm:
        print("Passwords do not match.")
        return

    try:
        result = auth.create_user(
            username=username,
            password=password,
            role="admin"
        )

        print("Admin account created successfully.")
        print("Username:", result["username"])
        print("Role:", result["role"])

    except (ValueError, TypeError) as error:
        print("Admin creation failed:", error)


if __name__ == "__main__":
    main()

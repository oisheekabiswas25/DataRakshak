
from getpass import getpass
from app.services.auth_service import AuthService

auth = AuthService()

username = input("Admin username: ").strip()
user = auth.get_user(username)

if not user or user["role"] != "admin":
    print("Admin account not found.")
else:
    password = getpass("New password: ")
    confirm = getpass("Confirm new password: ")

    if password != confirm:
        print("Passwords do not match.")
    else:
        import sqlite3
        from app.core.security import hash_password

        try:
            hashed = hash_password(password)

            with sqlite3.connect(auth.db_path) as conn:
                conn.execute(
                    "UPDATE users SET password_hash = ? WHERE username = ?",
                    (hashed, username)
                )

            print("Admin password changed successfully.")

        except ValueError as error:
            print("Error:", error)

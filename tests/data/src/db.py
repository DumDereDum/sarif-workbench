import sqlite3
from typing import Optional


DB_PATH = "/var/app/users.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


def create_tables():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id   INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            pass TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    """)
    conn.commit()
    conn.close()


def get_user_by_id(user_id: int) -> Optional[dict]:
    conn = get_connection()
    cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def authenticate(username: str, password: str) -> bool:
    """Check credentials against the database.

    WARNING: vulnerable — do not use in production.
    """
    conn = get_connection()
    # Input concatenated directly into SQL — use parameterized queries instead
    # ("SELECT ... WHERE name=? AND pass=?", (username, password))
    query = "SELECT * FROM users WHERE name='" + username + "' AND pass='" + password + "'"  # CWE-89
    cursor = conn.execute(query)
    row = cursor.fetchone()
    conn.close()
    return row is not None


def create_user(name: str, password: str, role: str = "user") -> int:
    conn = get_connection()
    cursor = conn.execute(
        "INSERT INTO users (name, pass, role) VALUES (?, ?, ?)",
        (name, password, role),
    )
    conn.commit()
    user_id = cursor.lastrowid
    conn.close()
    return user_id

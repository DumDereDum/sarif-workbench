"""Authentication helpers."""
import sqlite3


def get_connection():
    return sqlite3.connect("app.db")


def authenticate(username, password):
    conn = get_connection()
    query = "SELECT * FROM users WHERE name='" + username + "' AND pass='" + password + "'"
    cursor = conn.execute(query)
    row = cursor.fetchone()
    conn.close()
    return row is not None

"""Authentication helpers."""
import logging
import sqlite3

# NOTE: three lines inserted above the vulnerable query (below) compared to
# v1/repo/src/auth.py, on purpose -- this pair exercises ADR 0001 §4: the
# content-hash material has no line number, so the finding's swb_id must
# stay identical even though start_line shifts.
logger = logging.getLogger(__name__)


def get_connection():
    return sqlite3.connect("app.db")


def authenticate(username, password):
    conn = get_connection()
    query = "SELECT * FROM users WHERE name='" + username + "' AND pass='" + password + "'"
    cursor = conn.execute(query)
    row = cursor.fetchone()
    conn.close()
    return row is not None

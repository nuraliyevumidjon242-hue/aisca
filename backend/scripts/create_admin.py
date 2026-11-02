#!/usr/bin/env python3
"""Create or update an administrator using an interactively entered password."""
import argparse
import getpass
import sqlite3
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["argon2", "pbkdf2_sha256"], deprecated="auto")

parser = argparse.ArgumentParser()
parser.add_argument("--username", required=True)
parser.add_argument("--db", default="scans.db")
args = parser.parse_args()

password = getpass.getpass("Admin password: ")
confirmation = getpass.getpass("Confirm password: ")
if not password or password != confirmation:
    parser.error("Passwords must be non-empty and match.")

conn = sqlite3.connect(args.db)
conn.execute(
    """CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        is_admin INTEGER DEFAULT 0,
        role TEXT DEFAULT 'user'
    )"""
)
columns = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
if "role" not in columns:
    conn.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
conn.execute(
    """INSERT OR REPLACE INTO users
       (username, password_hash, is_admin, role)
       VALUES (?, ?, 1, 'admin')""",
    (args.username, pwd_context.hash(password)),
)
conn.commit()
conn.close()
print(f"Administrator '{args.username}' is ready.")

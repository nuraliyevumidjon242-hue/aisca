import os, sys
import sqlite3
from passlib.context import CryptContext

# Ensure project root on path to import backend.auth
tests_dir = os.path.dirname(__file__)
repo_root = os.path.abspath(os.path.join(tests_dir, '..', '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from backend.auth import authenticate_user

TEST_USER = 'migrate_test'
TEST_PW = 'TestPass123!'
from backend.auth import DATABASE_PATH
DB = os.path.abspath(DATABASE_PATH)



def setup_test_user():
    # create a legacy pbkdf2_sha256 hash and insert into scans.db
    legacy_ctx = CryptContext(schemes=['pbkdf2_sha256'], deprecated='auto')
    h = legacy_ctx.hash(TEST_PW)
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    # ensure users table exists (mirrors init_db)
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        is_admin INTEGER DEFAULT 0
    )''')
    c.execute("INSERT OR REPLACE INTO users (username, password_hash, is_admin) VALUES (?, ?, 0)", (TEST_USER, h))
    conn.commit()
    conn.close()
    return h


def teardown_test_user():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE username = ?", (TEST_USER,))
    conn.commit()
    conn.close()


def test_hash_is_migrated_on_login():
    # ensure user exists with legacy hash
    legacy_hash = setup_test_user()
    assert legacy_hash.startswith('$pbkdf2-sha256')

    # authenticate - this should trigger migrate to argon2
    user = authenticate_user(TEST_USER, TEST_PW)
    assert user is not False

    # read back hash
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE username = ?", (TEST_USER,))
    row = c.fetchone()
    conn.close()
    assert row is not None
    new_hash = row[0]
    # new hash should be argon2 (passlib produces $argon2id$...)
    assert ('argon2' in new_hash) or new_hash.startswith('$argon2')

    # cleanup
    teardown_test_user()

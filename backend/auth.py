from datetime import datetime, timedelta, timezone
from typing import Optional
import os
import secrets
import sqlite3
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
try:
    from .config import DATABASE_PATH
except ImportError:  # pragma: no cover - supports running as a top-level module
    from config import DATABASE_PATH

# secret for auth; in production load from env or fallback to strong random key
SECRET_KEY = os.environ.get('AISCA_SECRET_KEY') or secrets.token_hex(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Use argon2 for new hashes, but accept legacy pbkdf2-sha256 for existing users
# This allows verifying older hashes while creating new ones with argon2
pwd_context = CryptContext(schemes=["argon2","pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")


def _connect_db():
    conn = sqlite3.connect(DATABASE_PATH, timeout=30)
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT, is_admin INTEGER DEFAULT 0, role TEXT DEFAULT 'user')")
    cols = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    if 'role' not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
    if 'is_admin' not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
    conn.commit()
    return conn


def get_user(username: str):
    conn = _connect_db()
    c = conn.cursor()
    c.execute("SELECT username, password_hash, COALESCE(is_admin,0), COALESCE(role, 'user') FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return {"username": row[0], "password_hash": row[1], "is_admin": bool(row[2]), "role": row[3] or 'user'}


def _truncate_password_if_needed(password: str) -> str:
    # bcrypt has a 72-byte input limit; truncate UTF-8 encoded bytes if necessary
    b = password.encode('utf-8')
    if len(b) > 72:
        # truncate bytes and decode ignoring partial chars
        truncated = b[:72].decode('utf-8', 'ignore')
        # Note: return truncated version; caller may log this if desired
        return truncated
    return password


def create_user(username: str, password: str, is_admin: bool = False, role: str | None = None):
    safe_pw = _truncate_password_if_needed(password)
    pw_hash = pwd_context.hash(safe_pw)
    role_name = (role or ('admin' if is_admin else 'user')).lower()
    conn = _connect_db()
    c = conn.cursor()
    c.execute(
        "INSERT OR REPLACE INTO users (username, password_hash, is_admin, role) VALUES (?, ?, ?, ?)",
        (username, pw_hash, 1 if is_admin or role_name == 'admin' else 0, role_name)
    )
    conn.commit()
    conn.close()
    return {"username": username, "is_admin": is_admin or role_name == 'admin', "role": role_name}


from passlib.exc import UnknownHashError

def verify_password(plain_password, hashed_password):
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except UnknownHashError:
        # Unknown or unsupported hash format in DB — treat as authentication failure
        return False
    except Exception:
        # Any other error during verification should be a fail (avoid leaking details)
        return False


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user['password_hash']):
        return False
    # If the hash scheme is legacy or needs updating, re-hash with the preferred algorithm (argon2)
    try:
        # If the stored hash is not using the preferred scheme (argon2), re-hash and update.
        scheme = None
        try:
            scheme = pwd_context.identify(user['password_hash'])
        except Exception:
            scheme = None
        if scheme != 'argon2':
            # truncate input consistently before hashing
            safe_pw = _truncate_password_if_needed(password)
            new_hash = pwd_context.hash(safe_pw)
            conn = _connect_db()
            c = conn.cursor()
            c.execute("UPDATE users SET password_hash = ? WHERE username = ?", (new_hash, username))
            conn.commit()
            conn.close()
    except Exception:
        # If re-hash/update fails, proceed without blocking authentication
        pass
    return {**user, "role": user.get('role', 'user')}


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user


def require_admin(user: dict = Depends(get_current_user)):
    if user.get('is_admin') or str(user.get('role', '')).lower() == 'admin':
        return user
    raise HTTPException(status_code=403, detail='admin privileges required')

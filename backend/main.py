from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import time
import json
import sqlite3
import asyncio

try:
    from .scanner import run_nmap_scan
    from .ssl_audit import run_ssl_audit
    from .anomaly_engine import analyze_logs
    from .alert_manager import alert_manager
    from .cache import cache
    from .config import APP_NAME, DATABASE_PATH, DATABASE_URL, REDIS_URL
    from .auth import get_current_user, create_access_token, authenticate_user, require_admin
except ImportError:  # pragma: no cover - supports running as a top-level module in Docker
    from scanner import run_nmap_scan
    from ssl_audit import run_ssl_audit
    from anomaly_engine import analyze_logs
    from alert_manager import alert_manager
    from cache import cache
    from config import APP_NAME, DATABASE_PATH, DATABASE_URL, REDIS_URL
    from auth import get_current_user, create_access_token, authenticate_user, require_admin
from fastapi import Depends
from fastapi.security import OAuth2PasswordRequestForm

def ensure_db_parent_dir():
    parent = os.path.dirname(DATABASE_PATH)
    if parent:
        os.makedirs(parent, exist_ok=True)


import ipaddress
import re

DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
HOSTNAME_SINGLE_REGEX = re.compile(r"^[a-zA-Z0-9_-]+$")

def validate_target(target: str) -> str:
    cleaned = target.strip()
    if not cleaned or len(cleaned) > 253:
        raise HTTPException(status_code=400, detail="Invalid target: empty or too long")

    if cleaned.startswith("http://"):
        cleaned = cleaned[7:]
    elif cleaned.startswith("https://"):
        cleaned = cleaned[8:]
    cleaned = cleaned.split('/')[0].split(':')[0]

    try:
        ipaddress.ip_address(cleaned)
        return cleaned
    except ValueError:
        pass

    if DOMAIN_REGEX.match(cleaned) or HOSTNAME_SINGLE_REGEX.match(cleaned):
        return cleaned

    raise HTTPException(status_code=400, detail="Invalid target format. Must be a valid IP address or domain hostname.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    admin_user = os.environ.get('AISCA_ADMIN_USER')
    admin_pass = os.environ.get('AISCA_ADMIN_PASS')
    if admin_user and admin_pass:
        try:
            from .auth import get_user, create_user, verify_password
        except ImportError:  # pragma: no cover - top-level import fallback
            from auth import get_user, create_user, verify_password
        existing = get_user(admin_user)
        if not existing or not verify_password(admin_pass, existing.get('password_hash', '')) or existing.get('role') != 'admin' or not existing.get('is_admin'):
            create_user(admin_user, admin_pass, is_admin=True, role='admin')
    yield


app = FastAPI(title=APP_NAME, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        'http://localhost:3000',
        'http://127.0.0.1:3000',
        'http://localhost',
        'http://127.0.0.1',
    ],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

class ScanRequest(BaseModel):
    target: str
    logs: list[str] | str | None = None


class LogRequest(BaseModel):
    logs: list[str] | str


def _compute_risk_score(nmap_result=None, ssl_result=None, anomaly_result=None):
    high = medium = low = 0
    nmap_res = nmap_result or {}
    if isinstance(nmap_res, dict):
        for _, host in nmap_res.items():
            for port in host.get('ports', []):
                r = port.get('risk')
                if r == 'high':
                    high += 1
                elif r == 'medium':
                    medium += 1
                else:
                    low += 1

    score = max(0, 100 - (12 * high) - (6 * medium))
    if isinstance(anomaly_result, dict):
        score = max(0, score - int(anomaly_result.get('overall_score', 0) * 0.35))
    return max(0, min(100, score))


def ensure_alert_table():
    ensure_db_parent_dir()
    conn = sqlite3.connect(DATABASE_PATH, timeout=30)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        level TEXT,
        message TEXT,
        created_at INTEGER
    )""")
    conn.commit()
    conn.close()


def _emit_alert(message: str, level: str = 'medium'):
    payload = {
        'type': 'alert',
        'level': level,
        'message': message,
        'timestamp': int(time.time())
    }
    try:
        ensure_alert_table()
        ensure_db_parent_dir()
        conn = sqlite3.connect(DATABASE_PATH, timeout=30)
        c = conn.cursor()
        c.execute(
            "INSERT INTO alerts (level, message, created_at) VALUES (?, ?, ?)",
            (level, message, int(time.time()))
        )
        conn.commit()
        conn.close()
    except Exception:
        pass
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(alert_manager.broadcast(payload))
    except RuntimeError:
        pass


def init_db():
    ensure_db_parent_dir()
    conn = sqlite3.connect(DATABASE_PATH, timeout=30)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        timestamp INTEGER,
        result TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        is_admin INTEGER DEFAULT 0,
        role TEXT DEFAULT 'user'
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        level TEXT,
        message TEXT,
        created_at INTEGER
    )""")
    user_cols = c.execute("PRAGMA table_info(users)").fetchall()
    existing = {row[1] for row in user_cols}
    if 'role' not in existing:
        c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
    if 'is_admin' not in existing:
        c.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
    conn.commit()
    conn.close()


@app.get('/health')
def health():
    cache_status = 'enabled' if getattr(cache, 'enabled', False) else 'fallback'
    return {
        'status': 'ok',
        'app': APP_NAME,
        'database_path': DATABASE_PATH,
        'redis_url': REDIS_URL,
        'database_url_configured': bool(DATABASE_URL),
        'cache_status': cache_status,
    }


@app.post('/token')
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user['username'], "role": user.get('role', 'user')})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get('/me')
def me(user: dict = Depends(get_current_user)):
    return {"user": {"username": user['username'], "role": user.get('role', 'user'), "is_admin": bool(user.get('is_admin'))}}


@app.post('/users')
def create_user_endpoint(form: OAuth2PasswordRequestForm = Depends(), admin_user: dict = Depends(require_admin)):
    # creates a user (username in form.username, password in form.password)
    # Protected: only admin can create users
    try:
        from .auth import create_user
    except ImportError:  # pragma: no cover - top-level import fallback
        from auth import create_user
    user = create_user(form.username, form.password, role=form.data.get('role', 'user'))
    return {"user": user}


@app.get('/alerts')
def list_alerts(limit: int = 20, user: dict = Depends(get_current_user)):
    ensure_alert_table()
    ensure_db_parent_dir()
    conn = sqlite3.connect(DATABASE_PATH, timeout=30)
    c = conn.cursor()
    c.execute("SELECT level, message, created_at FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return {"alerts": [{"level": row[0], "message": row[1], "timestamp": row[2]} for row in rows]}


@app.websocket('/ws/alerts')
async def websocket_alerts(websocket: WebSocket):
    token = websocket.query_params.get('token')
    if not token:
        await websocket.close(code=1008)
        return
    try:
        get_current_user(token)
    except HTTPException:
        await websocket.close(code=1008)
        return

    await alert_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        alert_manager.disconnect(websocket)


@app.post('/analyze-logs')
def analyze_logs_endpoint(req: LogRequest, user: dict = Depends(get_current_user)):
    """Run a lightweight rule-based anomaly analysis over supplied log lines."""
    result = analyze_logs(req.logs)
    if result.get('risk_level') in ('medium', 'high'):
        _emit_alert(f"Log anomaly assessment for {user['username']}: {result['risk_level']} risk", 'high' if result['risk_level'] == 'high' else 'medium')
    return {"user": user['username'], "result": result}


@app.post("/scan")
def scan(req: ScanRequest, user: dict = Depends(get_current_user)):
    """Start a network scan for the provided target (IP or domain).
    Protected: requires bearer token.
    Returns parsed nmap results and stores them into scans.db."""
    target = validate_target(req.target)
    try:
        result = run_nmap_scan(target)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    anomaly_summary = analyze_logs(req.logs) if req.logs else {"overall_score": 0, "risk_level": "none", "detections": []}
    result_with_score = dict(result)
    result_with_score["ai_anomaly"] = anomaly_summary
    result_with_score["security_score"] = _compute_risk_score(result, anomaly_result=anomaly_summary)
    if result_with_score["security_score"] < 40 or anomaly_summary.get('risk_level') == 'high':
        _emit_alert(f"Security risk detected on {target}: score {result_with_score['security_score']}/100", 'high' if result_with_score['security_score'] < 40 else 'medium')

    ensure_db_parent_dir()
    conn = sqlite3.connect(DATABASE_PATH, timeout=30)
    c = conn.cursor()
    c.execute("INSERT INTO scans (target, timestamp, result) VALUES (?, ?, ?)",
              (target, int(time.time()), json.dumps(result_with_score)))
    conn.commit()
    conn.close()

    return {"target": target, "result": result_with_score, "user": user['username']}


@app.post("/audit")
def audit(req: ScanRequest, user: dict = Depends(get_current_user)):
    """Run both network scan and web/ssl audit for the target and store combined result.
    Protected: requires bearer token."""
    target = validate_target(req.target)

    try:
        nmap_result = run_nmap_scan(target)
    except Exception as e:
        nmap_result = {"error": f"Nmap scan failed: {str(e)}"}

    try:
        ssl_result = run_ssl_audit(target)
    except Exception as e:
        ssl_result = {"error": f"SSL/Web audit failed: {str(e)}"}

    anomaly_summary = analyze_logs(req.logs) if req.logs else {"overall_score": 0, "risk_level": "none", "detections": []}

    # Calculate score penalties for missing headers or failed SSL certs
    ssl_penalty = 0
    if isinstance(ssl_result, dict):
        cert_info = ssl_result.get('cert', {})
        if isinstance(cert_info, dict) and cert_info.get('valid') is False:
            ssl_penalty += 15
        headers_info = ssl_result.get('headers', {})
        if isinstance(headers_info, dict):
            missing_count = len(headers_info.get('missing_headers', []))
            ssl_penalty += (missing_count * 5)

    base_score = _compute_risk_score(nmap_result, ssl_result, anomaly_summary)
    final_score = max(0, base_score - ssl_penalty)

    combined = {
        "nmap": nmap_result,
        "ssl_audit": ssl_result,
        "ai_anomaly": anomaly_summary,
        "security_score": final_score
    }

    if final_score < 40 or anomaly_summary.get('risk_level') == 'high':
        _emit_alert(f"Audit flagged {target} with security score {final_score}/100", 'high' if final_score < 40 else 'medium')

    ensure_db_parent_dir()
    conn = sqlite3.connect(DATABASE_PATH, timeout=30)
    c = conn.cursor()
    c.execute("INSERT INTO scans (target, timestamp, result) VALUES (?, ?, ?)",
              (target, int(time.time()), json.dumps(combined)))
    conn.commit()
    conn.close()

    return {"target": target, "result": combined, "user": user['username']}


@app.get("/scans")
def list_scans(limit: int = 20, user: dict = Depends(get_current_user)):
    ensure_db_parent_dir()
    conn = sqlite3.connect(DATABASE_PATH, timeout=30)
    c = conn.cursor()
    c.execute("SELECT id, target, timestamp, result FROM scans ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    items = []
    for r in rows:
        # r[3] may be NULL or invalid JSON if imported/created by fallback; handle gracefully
        raw_result = r[3]
        try:
            parsed = json.loads(raw_result) if raw_result else {}
        except Exception:
            parsed = {"_raw": raw_result}
        items.append({"id": r[0], "target": r[1], "timestamp": r[2], "result": parsed})
    return {"scans": items}


@app.get("/stats")
def stats(limit: int = 50, user: dict = Depends(get_current_user)):
    """Return aggregate statistics for recent scans: counts by risk and score time-series."""
    ensure_db_parent_dir()
    conn = sqlite3.connect(DATABASE_PATH, timeout=30)
    c = conn.cursor()
    c.execute("SELECT id, target, timestamp, result FROM scans ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()

    total_high = total_medium = total_low = 0
    time_series = []

    for r in reversed(rows):
        scan_id, target, ts, result_json = r
        try:
            result = json.loads(result_json) if result_json else {}
        except Exception:
            result = {"_raw": result_json}
        nmap_res = result.get('nmap') if isinstance(result, dict) else result
        high = medium = low = 0
        if isinstance(nmap_res, dict):
            for _, h in nmap_res.items():
                for p in h.get('ports', []):
                    rsk = p.get('risk')
                    if rsk == 'high':
                        high += 1
                    elif rsk == 'medium':
                        medium += 1
                    else:
                        low += 1
        total_high += high
        total_medium += medium
        total_low += low
        anomaly = result.get('ai_anomaly') if isinstance(result, dict) else {}
        score = max(0, 100 - (10 * high) - (5 * medium) - int((anomaly.get('overall_score', 0) or 0) * 0.35))
        time_series.append({"timestamp": ts, "score": score, "high": high, "medium": medium, "low": low})

    return {
        "total": {"high": total_high, "medium": total_medium, "low": total_low},
        "time_series": time_series
    }


from fastapi.responses import Response

@app.get("/report/{scan_id}")
def get_report(scan_id: int, lang: str = 'en', user: dict = Depends(get_current_user)):
    """Return a generated PDF report for a stored scan (by scan id).
    Protected: requires bearer token. Optional query param: lang=de|en
    """
    ensure_db_parent_dir()
    conn = sqlite3.connect(DATABASE_PATH, timeout=30)
    c = conn.cursor()
    c.execute("SELECT id, target, timestamp, result FROM scans WHERE id = ?", (scan_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail='scan not found')

    try:
        parsed = json.loads(row[3]) if row[3] else {}
    except Exception:
        parsed = {"_raw": row[3]}
    record = {"id": row[0], "target": row[1], "timestamp": row[2], "result": parsed}
    # Generate PDF (HTML->PDF) using WeasyPrint; pass lang to choose language strings
    try:
        from .report_generator import generate_pdf
    except ImportError:  # pragma: no cover - top-level import fallback
        from report_generator import generate_pdf

    pdf_bytes = generate_pdf(record, lang=lang)

    return Response(content=pdf_bytes, media_type='application/pdf', headers={
        'Content-Disposition': f'attachment; filename="aisca_report_{scan_id}.pdf"'
    })

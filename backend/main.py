from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import sys
import time
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from contextlib import contextmanager

from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from PIL import Image, ImageOps

BASE_DIR = Path(__file__).resolve().parent.parent


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


load_dotenv(BASE_DIR / ".env")
APP_ENV = os.getenv("APP_ENV", "development").lower()
DATA_DIR = Path(os.getenv("LOANDESK_DATA_DIR", str(BASE_DIR / "data"))).resolve()
UPLOAD_DIR = DATA_DIR / "secure_uploads"
FRONTEND_DIR = BASE_DIR / "frontend"
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
try:
    os.chmod(DATA_DIR, 0o700)
    os.chmod(UPLOAD_DIR, 0o700)
except OSError:
    pass
DB_PATH = Path(os.getenv("DATABASE_PATH", str(DATA_DIR / "loandesk.sqlite3"))).resolve()
DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def persisted_secret(name: str, env_name: str, length: int = 32) -> str:
    value = os.getenv(env_name)
    if value:
        return value
    if APP_ENV == "production":
        raise RuntimeError(f"{env_name} must be configured in production")
    path = DATA_DIR / f"{name}.secret"
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    value = secrets.token_urlsafe(length)
    path.write_text(value, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return value


APP_SECRET = persisted_secret("app", "APP_SECRET", 48).encode("utf-8")
enc_key = os.getenv("APP_ENCRYPTION_KEY")
if not enc_key:
    if APP_ENV == "production":
        raise RuntimeError("APP_ENCRYPTION_KEY must be configured in production")
    key_file = DATA_DIR / "encryption.secret"
    if key_file.exists():
        enc_key = key_file.read_text(encoding="utf-8").strip()
    else:
        enc_key = Fernet.generate_key().decode("ascii")
        key_file.write_text(enc_key, encoding="utf-8")
        try:
            os.chmod(key_file, 0o600)
        except OSError:
            pass
CIPHER = Fernet(enc_key.encode("ascii"))

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
if not ADMIN_PASSWORD:
    if APP_ENV == "production":
        raise RuntimeError("ADMIN_PASSWORD must be configured in production")
    password_file = DATA_DIR / "admin.password.secret"
    credentials_file = DATA_DIR / "admin-initial-credentials.txt"
    if password_file.exists():
        ADMIN_PASSWORD = password_file.read_text(encoding="utf-8").strip()
    else:
        ADMIN_PASSWORD = secrets.token_urlsafe(18)
        password_file.write_text(ADMIN_PASSWORD, encoding="utf-8")
        try:
            os.chmod(password_file, 0o600)
        except OSError:
            pass
        credentials_file.write_text(
            "LoanDesk local admin credentials\n"
            f"Username: {ADMIN_USERNAME}\n"
            f"Password: {ADMIN_PASSWORD}\n\n"
            "Development only. Set ADMIN_PASSWORD in .env before deployment.\n",
            encoding="utf-8",
        )
        try:
            os.chmod(credentials_file, 0o600)
        except OSError:
            pass
        print(f"[LoanDesk] First-run admin password saved to: {credentials_file}", file=sys.stderr)

SMS_PROVIDER = os.getenv("SMS_PROVIDER", "console" if APP_ENV != "production" else "").lower()
SMS_TWILIO_ACCOUNT_SID = os.getenv("SMS_TWILIO_ACCOUNT_SID", "")
SMS_TWILIO_AUTH_TOKEN = os.getenv("SMS_TWILIO_AUTH_TOKEN", "")
SMS_TWILIO_FROM = os.getenv("SMS_TWILIO_FROM", "")
OTP_TTL_SECONDS = int(os.getenv("OTP_TTL_SECONDS", "300"))
OTP_MAX_ATTEMPTS = int(os.getenv("OTP_MAX_ATTEMPTS", "5"))
MAX_UPLOAD_BYTES = 5 * 1024 * 1024

if APP_ENV == "production" and SMS_PROVIDER in ("", "console", "log", "dev"):
    raise RuntimeError("Production requires a real SMS_PROVIDER; console OTP delivery is disabled")

app = FastAPI(
    title="LoanDesk API",
    version="1.0.0",
    description=(
        "Secure mobile loan application API. OTP values are never returned by the API or stored in audit logs. "
        "Configure real SMS delivery and HTTPS before production use."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
)
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(self), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' blob: data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
    )
    return response


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def db_connect() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 20000")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with db_connect() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                phone_hash TEXT NOT NULL UNIQUE,
                phone_enc TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS otp_challenges (
                id TEXT PRIMARY KEY,
                phone_hash TEXT NOT NULL,
                phone_enc TEXT NOT NULL,
                otp_hash TEXT NOT NULL,
                expires_at REAL NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                consumed INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_otp_phone_created ON otp_challenges(phone_hash, created_at);
            CREATE TABLE IF NOT EXISTS auth_audit (
                id TEXT PRIMARY KEY,
                challenge_id TEXT,
                phone_hash TEXT NOT NULL,
                phone_enc TEXT NOT NULL,
                event TEXT NOT NULL,
                outcome TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_audit_created ON auth_audit(created_at);
            CREATE INDEX IF NOT EXISTS ix_audit_phone_event ON auth_audit(phone_hash, event, created_at);
            CREATE TABLE IF NOT EXISTS applications (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id),
                status TEXT NOT NULL,
                offer_amount INTEGER NOT NULL,
                pan_number_enc TEXT,
                selfie_path TEXT,
                pan_image_path TEXT,
                liveness_status TEXT NOT NULL DEFAULT 'manual_review_required',
                consent_at TEXT,
                review_note_enc TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_apps_status ON applications(status, created_at);
            CREATE TABLE IF NOT EXISTS account_details (
                id TEXT PRIMARY KEY,
                application_id TEXT NOT NULL UNIQUE REFERENCES applications(id),
                holder_enc TEXT NOT NULL,
                bank_name_enc TEXT NOT NULL,
                account_number_enc TEXT NOT NULL,
                routing_code_enc TEXT,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        c.execute(
            "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES('offer_amount','50000',?)",
            (utc_now(),),
        )


init_db()


def encrypt_text(value: str | None) -> str | None:
    if value is None:
        return None
    return CIPHER.encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_text(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return CIPHER.decrypt(value.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeError):
        return None


def stable_hash(value: str) -> str:
    return hmac.new(APP_SECRET, value.encode("utf-8"), hashlib.sha256).hexdigest()


def phone_hash(phone: str) -> str:
    return stable_hash("phone:" + phone)


def normalize_phone(phone: str) -> str:
    result = "".join(ch for ch in phone.strip() if ch.isdigit() or ch == "+")
    if result.startswith("++") or result.count("+") > 1:
        raise HTTPException(status_code=422, detail="Enter a valid phone number.")
    digits = result[1:] if result.startswith("+") else result
    if not digits.isdigit() or not (10 <= len(digits) <= 15):
        raise HTTPException(status_code=422, detail="Enter a phone number with 10–15 digits, including country code.")
    return result


def mask_phone(phone: str | None) -> str:
    if not phone:
        return "—"
    digits = "".join(c for c in phone if c.isdigit())
    if len(digits) < 4:
        return "••••"
    return f"••••••{digits[-4:]}"


def mask_value(value: str | None, visible: int = 4) -> str:
    if not value:
        return "—"
    clean = value.strip()
    if len(clean) <= visible:
        return "•" * len(clean)
    return "•" * max(4, len(clean) - visible) + clean[-visible:]


def new_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def otp_hash(challenge_id: str, code: str) -> str:
    return hmac.new(APP_SECRET, f"otp:{challenge_id}:{code}".encode(), hashlib.sha256).hexdigest()


def make_token(subject: str, role: str, ttl_seconds: int = 3600) -> str:
    payload = {"sub": subject, "role": role, "exp": int(time.time()) + ttl_seconds, "iat": int(time.time())}
    raw = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    sig = hmac.new(APP_SECRET, raw.encode(), hashlib.sha256).digest()
    signature = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{raw}.{signature}"


def decode_token(token: str) -> dict[str, Any]:
    try:
        raw, signature = token.split(".", 1)
        expected = base64.urlsafe_b64encode(hmac.new(APP_SECRET, raw.encode(), hashlib.sha256).digest()).decode().rstrip("=")
        if not hmac.compare_digest(signature, expected):
            raise ValueError("signature")
        payload = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        if int(payload.get("exp", 0)) < int(time.time()):
            raise ValueError("expired")
        if payload.get("role") not in ("user", "admin"):
            raise ValueError("role")
        return payload
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Your session has expired. Please sign in again.") from exc


def principal(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Please sign in to continue.")
    return decode_token(authorization.split(" ", 1)[1].strip())


def require_user(auth: dict[str, Any] = Depends(principal)) -> dict[str, Any]:
    if auth["role"] != "user":
        raise HTTPException(status_code=403, detail="Customer access required.")
    return auth


def require_admin(auth: dict[str, Any] = Depends(principal)) -> dict[str, Any]:
    if auth["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required.")
    return auth


def get_request_meta(request: Request) -> tuple[str, str]:
    # Only trust X-Forwarded-For after configuring a trusted reverse proxy.
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "")[:240]
    return ip[:64], ua


def add_audit(
    c: sqlite3.Connection,
    *,
    challenge_id: str | None,
    p_hash: str,
    p_enc: str,
    event: str,
    outcome: str,
    request: Request | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
) -> None:
    if request is not None:
        ip, user_agent = get_request_meta(request)
    c.execute(
        "INSERT INTO auth_audit(id,challenge_id,phone_hash,phone_enc,event,outcome,ip_address,user_agent,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (str(uuid.uuid4()), challenge_id, p_hash, p_enc, event, outcome, (ip or "")[:64], (user_agent or "")[:240], utc_now()),
    )


def send_otp(phone: str, code: str) -> None:
    if SMS_PROVIDER in ("console", "log", "dev") and APP_ENV != "production":
        # Development-only sink. It is not exposed to the customer API or admin portal and is not persisted.
        print(f"[LoanDesk DEV SMS] To {mask_phone(phone)} | code={code} | expires in {OTP_TTL_SECONDS}s", file=sys.stderr, flush=True)
        return
    if SMS_PROVIDER == "twilio":
        if not all((SMS_TWILIO_ACCOUNT_SID, SMS_TWILIO_AUTH_TOKEN, SMS_TWILIO_FROM)):
            raise RuntimeError("Twilio SMS credentials are incomplete")
        url = f"https://api.twilio.com/2010-04-01/Accounts/{SMS_TWILIO_ACCOUNT_SID}/Messages.json"
        body = urllib.parse.urlencode({"To": phone, "From": SMS_TWILIO_FROM, "Body": f"Your LoanDesk verification code is {code}. It expires in 5 minutes. Do not share it."}).encode()
        credentials = base64.b64encode(f"{SMS_TWILIO_ACCOUNT_SID}:{SMS_TWILIO_AUTH_TOKEN}".encode()).decode()
        req = urllib.request.Request(url, data=body, headers={"Authorization": f"Basic {credentials}", "Content-Type": "application/x-www-form-urlencoded"}, method="POST")
        with urllib.request.urlopen(req, timeout=12) as resp:
            if resp.status >= 300:
                raise RuntimeError(f"SMS provider returned HTTP {resp.status}")
        return
    raise RuntimeError("No valid SMS provider is configured")


def setting_int(key: str, default: int) -> int:
    with db_connect() as c:
        row = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    try:
        return int(row["value"]) if row else default
    except (TypeError, ValueError):
        return default


def get_latest_application(c: sqlite3.Connection, user_id: str):
    return c.execute("SELECT * FROM applications WHERE user_id=? ORDER BY created_at DESC LIMIT 1", (user_id,)).fetchone()


def app_summary(c: sqlite3.Connection, row: sqlite3.Row | None) -> dict[str, Any] | None:
    if not row:
        return None
    acc = c.execute("SELECT account_number_enc FROM account_details WHERE application_id=?", (row["id"],)).fetchone()
    pan = decrypt_text(row["pan_number_enc"])
    acct = decrypt_text(acc["account_number_enc"]) if acc else None
    return {
        "id": row["id"], "status": row["status"], "offer_amount": row["offer_amount"],
        "pan_masked": mask_value(pan), "account_saved": bool(acc), "account_masked": mask_value(acct),
        "liveness_status": row["liveness_status"], "created_at": row["created_at"], "updated_at": row["updated_at"],
        "review_note": decrypt_text(row["review_note_enc"]),
    }


class PhoneRequest(BaseModel):
    phone: str = Field(min_length=10, max_length=20)


class OtpVerify(BaseModel):
    challenge_id: str = Field(min_length=20, max_length=80)
    otp: str = Field(pattern=r"^\d{6}$")


class AdminLogin(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


class ReviewUpdate(BaseModel):
    status: str = Field(pattern=r"^(under_review|needs_information|approved|rejected)$")
    review_note: str = Field(default="", max_length=2000)
    offer_amount: int | None = Field(default=None, ge=0, le=10000000)


class RevealRequest(BaseModel):
    purpose: str = Field(min_length=5, max_length=200)


class OfferSetting(BaseModel):
    offer_amount: int = Field(ge=1000, le=1000000)


class AccountPayload(BaseModel):
    account_holder: str = Field(min_length=2, max_length=120)
    bank_name: str = Field(min_length=2, max_length=120)
    account_number: str = Field(min_length=5, max_length=50)
    routing_code: str = Field(default="", max_length=40)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def home():
    return FileResponse(FRONTEND_DIR / "customer.html")


@app.get("/app", response_class=HTMLResponse, include_in_schema=False)
async def customer_app():
    return FileResponse(FRONTEND_DIR / "customer.html")


@app.get("/admin", response_class=HTMLResponse, include_in_schema=False)
async def admin_app():
    return FileResponse(FRONTEND_DIR / "admin.html")


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "service": "LoanDesk API", "environment": APP_ENV}


@app.get("/api/v1/public/config")
def public_config():
    return {"brand": "LoanDesk", "max_offer_amount": setting_int("offer_amount", 50000), "otp_ttl_seconds": OTP_TTL_SECONDS}


@app.post("/api/v1/auth/request-otp")
def request_otp(payload: PhoneRequest, request: Request):
    phone = normalize_phone(payload.phone)
    p_hash = phone_hash(phone)
    p_enc = encrypt_text(phone) or ""
    ip, ua = get_request_meta(request)
    now = time.time()
    challenge = None
    code = None
    limited = False
    with db_connect() as c:
        since = datetime.fromtimestamp(now - 60, timezone.utc).isoformat(timespec="seconds")
        last_phone = c.execute(
            "SELECT COUNT(*) AS n FROM auth_audit WHERE phone_hash=? AND event='otp_requested' AND created_at >= ?",
            (p_hash, since),
        ).fetchone()["n"]
        last_ip = c.execute(
            "SELECT COUNT(*) AS n FROM auth_audit WHERE ip_address=? AND event='otp_requested' AND created_at >= ?",
            (ip, since),
        ).fetchone()["n"]
        if last_phone >= 3 or last_ip >= 10:
            add_audit(c, challenge_id=None, p_hash=p_hash, p_enc=p_enc, event="otp_requested", outcome="rate_limited", ip=ip, user_agent=ua)
            limited = True
        else:
            # Invalidate previously active codes for this phone so only the newest one remains valid.
            c.execute("UPDATE otp_challenges SET consumed=1 WHERE phone_hash=? AND consumed=0", (p_hash,))
            challenge = str(uuid.uuid4())
            code = new_otp()
            c.execute(
                "INSERT INTO otp_challenges(id,phone_hash,phone_enc,otp_hash,expires_at,attempts,consumed,created_at) VALUES(?,?,?,?,?,0,0,?)",
                (challenge, p_hash, p_enc, otp_hash(challenge, code), now + OTP_TTL_SECONDS, utc_now()),
            )
            add_audit(c, challenge_id=challenge, p_hash=p_hash, p_enc=p_enc, event="otp_requested", outcome="queued", ip=ip, user_agent=ua)
    if limited:
        raise HTTPException(status_code=429, detail="Too many code requests. Please try again in a minute.")
    try:
        assert challenge is not None and code is not None
        send_otp(phone, code)
    except Exception as exc:
        with db_connect() as c:
            c.execute("DELETE FROM otp_challenges WHERE id=?", (challenge,))
            add_audit(c, challenge_id=challenge, p_hash=p_hash, p_enc=p_enc, event="otp_delivery", outcome="provider_error", ip=ip, user_agent=ua)
        print(f"[LoanDesk] SMS delivery failed: {type(exc).__name__}", file=sys.stderr)
        raise HTTPException(status_code=503, detail="We could not send a code right now. Please try again later.") from exc
    return {"challenge_id": challenge, "expires_in": OTP_TTL_SECONDS, "message": "If the number can receive messages, a verification code has been sent."}


@app.post("/api/v1/auth/verify-otp")
def verify_otp(payload: OtpVerify, request: Request):
    now = time.time()
    ip, ua = get_request_meta(request)
    failure_status = None
    failure_detail = None
    user_id = None
    with db_connect() as c:
        challenge = c.execute("SELECT * FROM otp_challenges WHERE id=?", (payload.challenge_id,)).fetchone()
        if not challenge:
            failure_status, failure_detail = 400, "The code is invalid or expired. Request a new code."
        elif challenge["consumed"]:
            add_audit(c, challenge_id=payload.challenge_id, p_hash=challenge["phone_hash"], p_enc=challenge["phone_enc"], event="otp_verify", outcome="already_used", ip=ip, user_agent=ua)
            failure_status, failure_detail = 400, "The code is invalid or expired. Request a new code."
        elif challenge["expires_at"] < now:
            c.execute("UPDATE otp_challenges SET consumed=1 WHERE id=?", (payload.challenge_id,))
            add_audit(c, challenge_id=payload.challenge_id, p_hash=challenge["phone_hash"], p_enc=challenge["phone_enc"], event="otp_verify", outcome="expired", ip=ip, user_agent=ua)
            failure_status, failure_detail = 400, "The code is invalid or expired. Request a new code."
        elif challenge["attempts"] >= OTP_MAX_ATTEMPTS:
            c.execute("UPDATE otp_challenges SET consumed=1 WHERE id=?", (payload.challenge_id,))
            add_audit(c, challenge_id=payload.challenge_id, p_hash=challenge["phone_hash"], p_enc=challenge["phone_enc"], event="otp_verify", outcome="attempt_limit", ip=ip, user_agent=ua)
            failure_status, failure_detail = 429, "Too many incorrect attempts. Request a new code."
        else:
            supplied_hash = otp_hash(payload.challenge_id, payload.otp)
            if not hmac.compare_digest(supplied_hash, challenge["otp_hash"]):
                attempts = challenge["attempts"] + 1
                consumed = 1 if attempts >= OTP_MAX_ATTEMPTS else 0
                c.execute("UPDATE otp_challenges SET attempts=?, consumed=? WHERE id=?", (attempts, consumed, payload.challenge_id))
                add_audit(c, challenge_id=payload.challenge_id, p_hash=challenge["phone_hash"], p_enc=challenge["phone_enc"], event="otp_verify", outcome="incorrect", ip=ip, user_agent=ua)
                failure_status, failure_detail = 400, "The code is incorrect or expired."
            else:
                c.execute("UPDATE otp_challenges SET consumed=1 WHERE id=?", (payload.challenge_id,))
                add_audit(c, challenge_id=payload.challenge_id, p_hash=challenge["phone_hash"], p_enc=challenge["phone_enc"], event="otp_verify", outcome="verified", ip=ip, user_agent=ua)
                row = c.execute("SELECT * FROM users WHERE phone_hash=?", (challenge["phone_hash"],)).fetchone()
                if row:
                    user_id = row["id"]
                else:
                    user_id = str(uuid.uuid4())
                    c.execute("INSERT INTO users(id,phone_hash,phone_enc,created_at) VALUES(?,?,?,?)", (user_id, challenge["phone_hash"], challenge["phone_enc"], utc_now()))
    if failure_status:
        raise HTTPException(status_code=failure_status, detail=failure_detail)
    assert user_id is not None
    return {"access_token": make_token(user_id, "user"), "token_type": "bearer", "expires_in": 3600}


@app.get("/api/v1/me")
def me(auth: dict[str, Any] = Depends(require_user)):
    with db_connect() as c:
        row = c.execute("SELECT * FROM users WHERE id=?", (auth["sub"],)).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="User not found.")
        phone = decrypt_text(row["phone_enc"])
        app_row = get_latest_application(c, auth["sub"])
        return {"user_id": row["id"], "phone_masked": mask_phone(phone), "max_offer_amount": setting_int("offer_amount", 50000), "application": app_summary(c, app_row)}


def save_image_upload(upload: UploadFile) -> tuple[str, str]:
    raw = upload.file.read(MAX_UPLOAD_BYTES + 1)
    if not raw or len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Each image must be no larger than 5 MB.")
    try:
        image = Image.open(io.BytesIO(raw))
        image = ImageOps.exif_transpose(image)
        if image.width > 6000 or image.height > 6000:
            raise HTTPException(status_code=400, detail="Image dimensions are too large.")
        image.load()
        image = image.convert("RGB")
        out = io.BytesIO()
        image.save(out, format="JPEG", quality=88, optimize=True)
        normalized = out.getvalue()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Upload a valid photo (JPEG, PNG, or WebP).") from exc
    file_id = f"{uuid.uuid4()}.enc"
    path = UPLOAD_DIR / file_id
    path.write_bytes(CIPHER.encrypt(normalized))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return file_id, "image/jpeg"


@app.post("/api/v1/application/kyc")
def submit_kyc(
    request: Request,
    pan_number: str = Form(min_length=5, max_length=30),
    consent: str = Form(),
    selfie: UploadFile = File(),
    pan_image: UploadFile = File(),
    auth: dict[str, Any] = Depends(require_user),
):
    if consent.lower() not in ("true", "1", "yes", "on"):
        raise HTTPException(status_code=400, detail="Consent is required before submitting identity documents.")
    pan_number = "".join(pan_number.upper().split())
    if len(pan_number) < 5:
        raise HTTPException(status_code=422, detail="Enter a valid PAN/card identifier.")
    selfie_id = None
    pan_id = None
    try:
        selfie_id, _ = save_image_upload(selfie)
        pan_id, _ = save_image_upload(pan_image)
        with db_connect() as c:
            existing = c.execute(
                "SELECT * FROM applications WHERE user_id=? AND status IN ('under_review','approved','needs_information') ORDER BY created_at DESC LIMIT 1",
                (auth["sub"],),
            ).fetchone()
            if existing:
                raise HTTPException(status_code=409, detail="An active or approved application already exists. Check your application status.")
            app_id = str(uuid.uuid4())
            amount = setting_int("offer_amount", 50000)
            c.execute(
                "INSERT INTO applications(id,user_id,status,offer_amount,pan_number_enc,selfie_path,pan_image_path,liveness_status,consent_at,review_note_enc,created_at,updated_at) VALUES(?,?, 'under_review', ?, ?, ?, ?, 'manual_review_required', ?, NULL, ?, ?)",
                (app_id, auth["sub"], amount, encrypt_text(pan_number), selfie_id, pan_id, utc_now(), utc_now(), utc_now()),
            )
        return {"application_id": app_id, "status": "under_review", "message": "Your documents have been submitted for review. A photo was received; live-presence verification is not automated by this service."}
    except Exception:
        for file_id in (selfie_id, pan_id):
            if file_id:
                try:
                    (UPLOAD_DIR / file_id).unlink(missing_ok=True)
                except OSError:
                    pass
        raise


@app.get("/api/v1/application/me")
def application_me(auth: dict[str, Any] = Depends(require_user)):
    with db_connect() as c:
        row = get_latest_application(c, auth["sub"])
        if not row:
            return {"application": None}
        acc = c.execute("SELECT * FROM account_details WHERE application_id=?", (row["id"],)).fetchone()
        summary = app_summary(c, row)
        summary["account"] = None
        if acc:
            summary["account"] = {
                "account_holder": decrypt_text(acc["holder_enc"]),
                "bank_name": decrypt_text(acc["bank_name_enc"]),
                "account_masked": mask_value(decrypt_text(acc["account_number_enc"])),
                "routing_code": mask_value(decrypt_text(acc["routing_code_enc"])),
            }
        return {"application": summary}


@app.post("/api/v1/application/account")
def save_account(payload: AccountPayload, auth: dict[str, Any] = Depends(require_user)):
    with db_connect() as c:
        app_row = get_latest_application(c, auth["sub"])
        if not app_row:
            raise HTTPException(status_code=409, detail="Submit your identity documents before adding account details.")
        if app_row["status"] == "rejected":
            raise HTTPException(status_code=409, detail="This application was rejected. Contact support before updating account details.")
        existing = c.execute("SELECT id FROM account_details WHERE application_id=?", (app_row["id"],)).fetchone()
        values = (encrypt_text(payload.account_holder.strip()), encrypt_text(payload.bank_name.strip()), encrypt_text(payload.account_number.strip()), encrypt_text(payload.routing_code.strip()), utc_now())
        if existing:
            c.execute("UPDATE account_details SET holder_enc=?,bank_name_enc=?,account_number_enc=?,routing_code_enc=?,updated_at=? WHERE application_id=?", (*values, app_row["id"]))
        else:
            c.execute("INSERT INTO account_details(id,application_id,holder_enc,bank_name_enc,account_number_enc,routing_code_enc,updated_at) VALUES(?,?,?,?,?,?,?)", (str(uuid.uuid4()), app_row["id"], *values))
        c.execute("UPDATE applications SET updated_at=? WHERE id=?", (utc_now(), app_row["id"]))
    return {"status": "saved", "message": "Account details saved securely."}


@app.post("/api/v1/admin/login")
def admin_login(payload: AdminLogin):
    user_ok = hmac.compare_digest(payload.username, ADMIN_USERNAME)
    pass_ok = hmac.compare_digest(payload.password, ADMIN_PASSWORD or "")
    if not (user_ok and pass_ok):
        raise HTTPException(status_code=401, detail="Invalid administrator credentials.")
    return {"access_token": make_token("admin", "admin", ttl_seconds=1800), "token_type": "bearer", "expires_in": 1800}


@app.get("/api/v1/admin/overview")
def admin_overview(_: dict[str, Any] = Depends(require_admin)):
    with db_connect() as c:
        total = c.execute("SELECT COUNT(*) n FROM applications").fetchone()["n"]
        under_review = c.execute("SELECT COUNT(*) n FROM applications WHERE status='under_review'").fetchone()["n"]
        approved = c.execute("SELECT COUNT(*) n FROM applications WHERE status='approved'").fetchone()["n"]
        needs_info = c.execute("SELECT COUNT(*) n FROM applications WHERE status='needs_information'").fetchone()["n"]
        rejected = c.execute("SELECT COUNT(*) n FROM applications WHERE status='rejected'").fetchone()["n"]
        otp_events = c.execute("SELECT COUNT(*) n FROM auth_audit WHERE event='otp_verify' AND created_at>=?", (datetime.fromtimestamp(time.time()-86400, timezone.utc).isoformat(timespec="seconds"),)).fetchone()["n"]
    return {"total_applications": total, "under_review": under_review, "approved": approved, "needs_information": needs_info, "rejected": rejected, "otp_verification_attempts_24h": otp_events, "offer_amount": setting_int("offer_amount", 50000)}


@app.get("/api/v1/admin/applications")
def admin_applications(status: str | None = None, limit: int = 100, _: dict[str, Any] = Depends(require_admin)):
    limit = max(1, min(limit, 300))
    query = "SELECT a.*,u.phone_enc FROM applications a JOIN users u ON u.id=a.user_id"
    args: list[Any] = []
    if status and status in ("under_review", "needs_information", "approved", "rejected"):
        query += " WHERE a.status=?"
        args.append(status)
    query += " ORDER BY a.created_at DESC LIMIT ?"
    args.append(limit)
    result = []
    with db_connect() as c:
        for row in c.execute(query, args).fetchall():
            summary = app_summary(c, row)
            phone = decrypt_text(row["phone_enc"])
            summary["phone_masked"] = mask_phone(phone)
            summary["has_selfie"] = bool(row["selfie_path"])
            summary["has_pan_image"] = bool(row["pan_image_path"])
            summary["liveness_status"] = row["liveness_status"]
            result.append(summary)
    return {"applications": result}


@app.get("/api/v1/admin/applications/{application_id}")
def admin_application_detail(application_id: str, _: dict[str, Any] = Depends(require_admin)):
    with db_connect() as c:
        row = c.execute("SELECT a.*,u.phone_enc FROM applications a JOIN users u ON u.id=a.user_id WHERE a.id=?", (application_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Application not found.")
        summary = app_summary(c, row)
        acc = c.execute("SELECT * FROM account_details WHERE application_id=?", (application_id,)).fetchone()
        summary.update({
            "phone_masked": mask_phone(decrypt_text(row["phone_enc"])),
            "selfie_available": bool(row["selfie_path"]),
            "pan_image_available": bool(row["pan_image_path"]),
            "account": None,
        })
        if acc:
            summary["account"] = {
                "account_holder": decrypt_text(acc["holder_enc"]),
                "bank_name": decrypt_text(acc["bank_name_enc"]),
                "account_number_masked": mask_value(decrypt_text(acc["account_number_enc"])),
                "routing_code_masked": mask_value(decrypt_text(acc["routing_code_enc"])),
                "updated_at": acc["updated_at"],
            }
        return summary


@app.post("/api/v1/admin/applications/{application_id}/reveal")
def admin_reveal(application_id: str, payload: RevealRequest, request: Request, auth: dict[str, Any] = Depends(require_admin)):
    with db_connect() as c:
        row = c.execute("SELECT a.*,u.phone_enc FROM applications a JOIN users u ON u.id=a.user_id WHERE a.id=?", (application_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Application not found.")
        acc = c.execute("SELECT * FROM account_details WHERE application_id=?", (application_id,)).fetchone()
        phone = decrypt_text(row["phone_enc"]) or ""
        add_audit(c, challenge_id=None, p_hash=phone_hash(phone), p_enc=row["phone_enc"], event="admin_sensitive_reveal", outcome="success", request=request)
        return {
            "application_id": application_id,
            "purpose": payload.purpose,
            "pan_number": decrypt_text(row["pan_number_enc"]),
            "account": ({
                "account_holder": decrypt_text(acc["holder_enc"]),
                "bank_name": decrypt_text(acc["bank_name_enc"]),
                "account_number": decrypt_text(acc["account_number_enc"]),
                "routing_code": decrypt_text(acc["routing_code_enc"]),
            } if acc else None),
        }


@app.patch("/api/v1/admin/applications/{application_id}")
def admin_update_application(application_id: str, payload: ReviewUpdate, _: dict[str, Any] = Depends(require_admin)):
    with db_connect() as c:
        row = c.execute("SELECT id FROM applications WHERE id=?", (application_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Application not found.")
        if payload.offer_amount is None:
            c.execute("UPDATE applications SET status=?,review_note_enc=?,updated_at=? WHERE id=?", (payload.status, encrypt_text(payload.review_note.strip()) if payload.review_note.strip() else None, utc_now(), application_id))
        else:
            c.execute("UPDATE applications SET status=?,offer_amount=?,review_note_enc=?,updated_at=? WHERE id=?", (payload.status, payload.offer_amount, encrypt_text(payload.review_note.strip()) if payload.review_note.strip() else None, utc_now(), application_id))
    return {"status": "updated", "application_id": application_id}


@app.get("/api/v1/admin/documents/{application_id}/{kind}")
def admin_document(application_id: str, kind: str, _: dict[str, Any] = Depends(require_admin)):
    if kind not in ("selfie", "pan"):
        raise HTTPException(status_code=404, detail="Document not found.")
    with db_connect() as c:
        row = c.execute("SELECT selfie_path,pan_image_path FROM applications WHERE id=?", (application_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Application not found.")
        file_id = row["selfie_path"] if kind == "selfie" else row["pan_image_path"]
        if not file_id:
            raise HTTPException(status_code=404, detail="Document not found.")
        add_audit(c, challenge_id=None, p_hash="application:" + application_id, p_enc="", event="admin_document_view", outcome=kind, ip="admin", user_agent="admin-portal")
    try:
        encrypted = (UPLOAD_DIR / file_id).read_bytes()
        data = CIPHER.decrypt(encrypted)
    except (OSError, InvalidToken) as exc:
        raise HTTPException(status_code=500, detail="Document could not be read.") from exc
    return Response(data, media_type="image/jpeg", headers={"Cache-Control": "no-store", "Content-Disposition": "inline"})


@app.get("/api/v1/admin/otp-audit")
def admin_otp_audit(limit: int = 100, _: dict[str, Any] = Depends(require_admin)):
    limit = max(1, min(limit, 500))
    with db_connect() as c:
        rows = c.execute("SELECT challenge_id,phone_enc,event,outcome,ip_address,user_agent,created_at FROM auth_audit ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    events = []
    for row in rows:
        events.append({
            "challenge_id": row["challenge_id"], "phone_masked": mask_phone(decrypt_text(row["phone_enc"])),
            "event": row["event"], "outcome": row["outcome"], "ip_address": row["ip_address"],
            "user_agent": row["user_agent"], "created_at": row["created_at"],
            "note": "OTP values are intentionally not stored or displayed.",
        })
    return {"events": events}


@app.patch("/api/v1/admin/settings/offer")
def admin_set_offer(payload: OfferSetting, _: dict[str, Any] = Depends(require_admin)):
    with db_connect() as c:
        c.execute("INSERT INTO settings(key,value,updated_at) VALUES('offer_amount',?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at", (str(payload.offer_amount), utc_now()))
    return {"offer_amount": payload.offer_amount}


@app.get("/api/v1/admin/export/applications.csv")
def admin_export_applications(_: dict[str, Any] = Depends(require_admin)):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["application_id", "phone_masked", "status", "offer_amount", "pan_masked", "account_masked", "account_saved", "created_at", "updated_at"])
    with db_connect() as c:
        rows = c.execute("SELECT a.*,u.phone_enc FROM applications a JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC").fetchall()
        for row in rows:
            summary = app_summary(c, row)
            writer.writerow([summary["id"], mask_phone(decrypt_text(row["phone_enc"])), summary["status"], summary["offer_amount"], summary["pan_masked"], summary["account_masked"], summary["account_saved"], summary["created_at"], summary["updated_at"]])
    return Response(output.getvalue().encode("utf-8-sig"), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": "attachment; filename=loandesk-applications.csv", "Cache-Control": "no-store"})


@app.get("/api/v1/admin/export/otp-audit.csv")
def admin_export_audit(_: dict[str, Any] = Depends(require_admin)):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["created_at", "phone_masked", "event", "outcome", "challenge_id", "ip_address", "user_agent"])
    with db_connect() as c:
        rows = c.execute("SELECT * FROM auth_audit ORDER BY created_at DESC").fetchall()
        for row in rows:
            writer.writerow([row["created_at"], mask_phone(decrypt_text(row["phone_enc"])), row["event"], row["outcome"], row["challenge_id"], row["ip_address"], row["user_agent"]])
    return Response(output.getvalue().encode("utf-8-sig"), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": "attachment; filename=loandesk-otp-audit.csv", "Cache-Control": "no-store"})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "8000")), reload=(APP_ENV != "production"))

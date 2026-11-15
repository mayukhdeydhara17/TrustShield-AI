import hashlib
import hmac
import os
import secrets
import sqlite3
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel, EmailStr, Field

DB_PATH = Path(os.getenv("TRUSTSHIELD_DB_PATH", Path(__file__).with_name("trustshield.db")))
router = APIRouter(prefix="/auth", tags=["authentication"])


def db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_auth_db():
    """Create authentication/history tables and safely handle older scan schemas.

    Old scans without an owner are preserved in a backup table rather than
    being incorrectly assigned to whichever user logs in first.
    """
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        existing = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='scans'"
        ).fetchone()
        if existing:
            columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(scans)").fetchall()
            }
            required = {
                "id", "user_id", "url", "risk_score",
                "risk_level", "report_json", "scanned_at"
            }
            if not required.issubset(columns):
                backup_name = "scans_legacy_unassigned"
                backup_exists = conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                    (backup_name,),
                ).fetchone()
                if not backup_exists:
                    conn.execute(f"ALTER TABLE scans RENAME TO {backup_name}")
                else:
                    # Keep the existing backup and move the conflicting legacy table
                    # aside under a deterministic second name.
                    conn.execute("ALTER TABLE scans RENAME TO scans_legacy_unassigned_2")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                url TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                report_json TEXT NOT NULL,
                scanned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_user_scanned ON scans(user_id, scanned_at DESC)"
        )


class SignUpRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class SignInRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"{salt.hex()}:{digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split(":", 1)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 310_000)
        return hmac.compare_digest(actual.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def issue_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with db() as conn:
        conn.execute("INSERT INTO sessions (token_hash, user_id) VALUES (?, ?)", (token_hash, user_id))
    return token


def current_user(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Please sign in.")
    token = authorization[7:].strip()
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with db() as conn:
        row = conn.execute("""
            SELECT users.id, users.name, users.email
            FROM sessions JOIN users ON users.id = sessions.user_id
            WHERE sessions.token_hash = ?
        """, (token_hash,)).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Your session is invalid. Please sign in again.")
    return dict(row)


@router.post("/signup", status_code=201)
def signup(payload: SignUpRequest):
    name = payload.name.strip()
    email = str(payload.email).strip().lower()
    if not name:
        raise HTTPException(status_code=400, detail="Please enter your name.")
    try:
        with db() as conn:
            cursor = conn.execute(
                "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                (name, email, hash_password(payload.password)),
            )
            user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="An account with this email already exists.")
    return {"access_token": issue_session(user_id), "token_type": "bearer",
            "user": {"id": user_id, "name": name, "email": email}}


@router.post("/login")
def login(payload: SignInRequest):
    email = str(payload.email).strip().lower()
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password.")
    return {"access_token": issue_session(user["id"]), "token_type": "bearer",
            "user": {"id": user["id"], "name": user["name"], "email": user["email"]}}


@router.get("/me")
def me(user=Depends(current_user)):
    return user


@router.post("/logout")
def logout(authorization: str | None = Header(default=None)):
    if authorization and authorization.startswith("Bearer "):
        token_hash = hashlib.sha256(authorization[7:].strip().encode()).hexdigest()
        with db() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
    return {"message": "Signed out."}

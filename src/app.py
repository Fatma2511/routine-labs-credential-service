"""
Routine Labs — Third-Party Credential Storage Service
======================================================

Why encryption, not hashing
-----------------------------
This service stores credentials that a background automation process must later
use to log into external third-party systems.  Because the plaintext password
must be recoverable, one-way hashing (bcrypt, Argon2) is explicitly NOT suitable.

Instead we use **symmetric authenticated encryption**:
  - Algorithm : AES-128-CBC with HMAC-SHA256, exposed via the Fernet abstraction
                from the `cryptography` library.  Fernet guarantees both
                confidentiality (the value cannot be read without the key) and
                integrity (tampered ciphertext is rejected on decryption).
  - Key       : A 32-byte URL-safe base64 key loaded from the environment variable
                ENCRYPTION_KEY.  Never committed to source control.
  - At rest   : Only the base64-encoded ciphertext is written to the database.
                The plaintext and the key never coexist in a DB row.

The key is the single secret that must be protected.  In production this would
come from a secrets manager (AWS Secrets Manager, HashiCorp Vault, GCP Secret
Manager) rather than a .env file.

Error handling strategy
------------------------
- 400  Bad Request       : client sent something semantically wrong that Pydantic
                           could not catch (e.g. PATCH body with no fields at all).
- 404  Not Found         : requested credential ID does not exist.
- 422  Unprocessable     : Pydantic validation failure (wrong type, missing field,
                           failed regex). Returned automatically by FastAPI.
- 500  Internal Error    : downstream failure — database unreachable, encryption/
                           decryption error, or any other unexpected server-side
                           problem. Generic message returned to client; full detail
                           is logged server-side only.
"""

import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import create_engine, Column, String, DateTime, Text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import declarative_base, sessionmaker, Session
import uuid

# ---------------------------------------------------------------------------
# Logging  — structured, no secrets ever logged
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("routine_labs.credentials")

# ---------------------------------------------------------------------------
# Configuration — loaded from environment, never hardcoded
# ---------------------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./credentials.db")
_raw_key = os.getenv("ENCRYPTION_KEY", "")

if not _raw_key:
    raise RuntimeError(
        "ENCRYPTION_KEY environment variable is not set. "
        "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
    )

try:
    fernet = Fernet(_raw_key.encode())
except Exception as exc:
    raise RuntimeError(f"ENCRYPTION_KEY is not a valid Fernet key: {exc}") from exc

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")

# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class CredentialRecord(Base):
    """
    Database model.

    `encrypted_password` holds the Fernet-encrypted ciphertext of the
    original password string.  The plaintext never appears here.
    """
    __tablename__ = "credentials"

    id                 = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    system_identifier  = Column(String(128), nullable=False, index=True)
    username           = Column(String(256), nullable=False)
    encrypted_password = Column(Text, nullable=False)   # Fernet token, base64url-encoded
    label              = Column(String(256), nullable=True)
    created_at         = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at         = Column(DateTime(timezone=True),
                                default=lambda: datetime.now(timezone.utc),
                                onupdate=lambda: datetime.now(timezone.utc))


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------------------------------------------------------------------------
# Encryption helpers
# ---------------------------------------------------------------------------

def encrypt_password(plaintext: str) -> str:
    """
    Return the Fernet-encrypted, base64url-encoded ciphertext.
    Raises HTTP 500 if encryption fails — this should never happen in normal
    operation but guards against unexpected key or library issues.
    """
    try:
        return fernet.encrypt(plaintext.encode()).decode()
    except Exception as exc:
        logger.error("Encryption failed unexpectedly: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to encrypt credential. Please try again.",
        ) from exc


def decrypt_password(ciphertext: str) -> str:
    """
    Decrypt a stored ciphertext back to the plaintext password.

    Raises HTTP 500 if the token is invalid or tampered with.
    This is a downstream failure — the data in the DB does not match the
    current key, which means either the key was rotated without re-encrypting,
    or the ciphertext was corrupted / tampered with.
    """
    try:
        return fernet.decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        logger.error("Decryption failed — token invalid or key mismatch")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to decrypt credential. Key mismatch or data corruption.",
        ) from exc

# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class CredentialCreate(BaseModel):
    """
    Input schema for storing a new third-party credential.

    Fields
    ------
    system_identifier : machine-readable identifier for the target system
                        (e.g. "salesforce-prod", "jira-acme").
    username          : login identifier on that system.
    password          : plaintext password — encrypted before any persistence.
    label             : optional human-readable description.
    """
    system_identifier: str = Field(
        ..., min_length=1, max_length=128,
        examples=["salesforce-prod"],
        description="Machine-readable identifier for the target third-party system.",
    )
    username: str = Field(
        ..., min_length=1, max_length=256,
        examples=["alice@example.com"],
    )
    password: str = Field(
        ..., min_length=1, max_length=1024,
        description="Plaintext password — encrypted at rest, never logged.",
    )
    label: Optional[str] = Field(
        None, max_length=256,
        examples=["Salesforce production account"],
    )

    @field_validator("system_identifier")
    @classmethod
    def system_identifier_slug(cls, v: str) -> str:
        if not re.match(r"^[A-Za-z0-9_\-\.]{1,128}$", v):
            raise ValueError(
                "system_identifier must be 1-128 characters: letters, digits, hyphens, "
                "underscores, or dots."
            )
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "system_identifier": "salesforce-prod",
                "username": "alice@example.com",
                "password": "super-secret-password",
                "label": "Salesforce production account",
            }
        }


class CredentialMetadata(BaseModel):
    """
    Safe response model — password is NEVER included.
    Only metadata is returned to the caller.
    """
    id: str
    system_identifier: str
    username: str
    label: Optional[str]
    created_at: datetime
    updated_at: datetime


class CredentialWithSecret(BaseModel):
    """
    Response model for the retrieve endpoint.
    The decrypted password is included — only call this from trusted internal services.
    """
    id: str
    system_identifier: str
    username: str
    password: str          # decrypted — only exposed on explicit retrieval
    label: Optional[str]
    created_at: datetime
    updated_at: datetime


class CredentialUpdate(BaseModel):
    """
    Partial update — all fields optional.
    At least one field must be provided (validated in the route).
    """
    username: Optional[str] = Field(None, min_length=1, max_length=256)
    password: Optional[str] = Field(None, min_length=1, max_length=1024)
    label:    Optional[str] = Field(None, max_length=256)

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Third-Party Credential Storage — Routine Labs",
    description=(
        "Stores encrypted credentials for external systems used by automation workflows.\n\n"
        "**Passwords are encrypted with AES-128 (Fernet) and never stored in plaintext.**\n\n"
        "Transport security (HTTPS/TLS) is assumed to be provided by an upstream reverse proxy."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health", tags=["Operations"], summary="Liveness probe")
def health():
    return {"status": "ok"}


@app.post(
    "/credentials",
    response_model=CredentialMetadata,
    status_code=status.HTTP_201_CREATED,
    tags=["Credentials"],
    summary="Store a new third-party credential",
)
def create_credential(body: CredentialCreate, db: Session = Depends(get_db)):
    """
    Accepts a system identifier, username, and password.

    The password is **immediately encrypted** with AES-128 (Fernet) before
    being written to the database.  The plaintext is discarded after encryption.

    Returns metadata only — the password is never echoed back.

    Errors
    ------
    422 : validation failure (missing field, wrong type, invalid system_identifier format)
    500 : database write failed or encryption failed unexpectedly
    """
    encrypted = encrypt_password(body.password)

    record = CredentialRecord(
        system_identifier=body.system_identifier,
        username=body.username,
        encrypted_password=encrypted,
        label=body.label,
    )

    try:
        db.add(record)
        db.commit()
        db.refresh(record)
    except SQLAlchemyError as exc:
        db.rollback()
        logger.error("Database error on create: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to store credential. Please try again.",
        ) from exc

    logger.info(
        "Credential stored | id=%s system=%s username=<redacted>",
        record.id, record.system_identifier,
    )
    return _to_metadata(record)


@app.get(
    "/credentials",
    response_model=list[CredentialMetadata],
    tags=["Credentials"],
    summary="List all stored credentials (metadata only)",
)
def list_credentials(
    system_identifier: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """
    Returns metadata for all stored credentials.
    Passwords are never included in this response.

    Optionally filter by `system_identifier`.

    Errors
    ------
    500 : database read failed
    """
    try:
        q = db.query(CredentialRecord)
        if system_identifier:
            q = q.filter(CredentialRecord.system_identifier == system_identifier)
        return [_to_metadata(r) for r in q.all()]
    except SQLAlchemyError as exc:
        logger.error("Database error on list: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve credentials. Please try again.",
        ) from exc


@app.get(
    "/credentials/{credential_id}",
    response_model=CredentialMetadata,
    tags=["Credentials"],
    summary="Get credential metadata (no password)",
)
def get_credential_metadata(credential_id: str, db: Session = Depends(get_db)):
    """
    Returns metadata for a single credential. Password is NOT included.

    Errors
    ------
    404 : credential ID does not exist
    500 : database read failed
    """
    record = _get_or_404(db, credential_id)
    return _to_metadata(record)


@app.get(
    "/credentials/{credential_id}/secret",
    response_model=CredentialWithSecret,
    tags=["Credentials"],
    summary="Retrieve a credential including the decrypted password",
)
def get_credential_with_secret(credential_id: str, db: Session = Depends(get_db)):
    """
    Returns the full credential including the **decrypted password**.

    This is a downstream operation: it reads from the database AND decrypts
    the stored ciphertext.  Both operations can fail independently.

    Errors
    ------
    404 : credential ID does not exist
    500 : database read failed, OR decryption failed (key mismatch / data corruption)

    WARNING: This endpoint should only be accessible from trusted internal services
    (automation workers), not from public-facing clients.
    In production: protect with mTLS, an internal network policy, or a service
    token — do not expose this route publicly.
    """
    record = _get_or_404(db, credential_id)
    decrypted = decrypt_password(record.encrypted_password)

    logger.info(
        "Credential secret retrieved | id=%s system=%s",
        record.id, record.system_identifier,
    )
    return CredentialWithSecret(
        id=record.id,
        system_identifier=record.system_identifier,
        username=record.username,
        password=decrypted,
        label=record.label,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


@app.patch(
    "/credentials/{credential_id}",
    response_model=CredentialMetadata,
    tags=["Credentials"],
    summary="Update a stored credential",
)
def update_credential(
    credential_id: str,
    body: CredentialUpdate,
    db: Session = Depends(get_db),
):
    """
    Partially update a credential.  Supply only the fields you want to change.
    If `password` is supplied it is re-encrypted before storage.

    Errors
    ------
    400 : PATCH body contains no fields to update
    404 : credential ID does not exist
    422 : validation failure (field too long, wrong type)
    500 : database write failed or re-encryption failed
    """
    # 400 — client sent a PATCH with no fields at all
    if body.username is None and body.password is None and body.label is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one field (username, password, or label) must be provided.",
        )

    record = _get_or_404(db, credential_id)

    if body.username is not None:
        record.username = body.username
    if body.password is not None:
        record.encrypted_password = encrypt_password(body.password)
    if body.label is not None:
        record.label = body.label

    record.updated_at = datetime.now(timezone.utc)

    try:
        db.commit()
        db.refresh(record)
    except SQLAlchemyError as exc:
        db.rollback()
        logger.error("Database error on update | id=%s : %s", credential_id, type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update credential. Please try again.",
        ) from exc

    logger.info("Credential updated | id=%s system=%s", record.id, record.system_identifier)
    return _to_metadata(record)


@app.delete(
    "/credentials/{credential_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Credentials"],
    summary="Delete a stored credential",
)
def delete_credential(credential_id: str, db: Session = Depends(get_db)):
    """
    Permanently removes the credential record.

    Errors
    ------
    404 : credential ID does not exist
    500 : database delete failed
    """
    record = _get_or_404(db, credential_id)

    try:
        db.delete(record)
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        logger.error("Database error on delete | id=%s : %s", credential_id, type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete credential. Please try again.",
        ) from exc

    logger.info("Credential deleted | id=%s system=%s", record.id, record.system_identifier)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_or_404(db: Session, credential_id: str) -> CredentialRecord:
    """
    Fetch a record by ID or raise HTTP 404.
    Also catches database errors and raises HTTP 500.
    """
    try:
        record = db.get(CredentialRecord, credential_id)
    except SQLAlchemyError as exc:
        logger.error("Database error on lookup | id=%s : %s", credential_id, type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve credential. Please try again.",
        ) from exc

    if record is None:
        raise HTTPException(status_code=404, detail="Credential not found.")
    return record


def _to_metadata(record: CredentialRecord) -> CredentialMetadata:
    return CredentialMetadata(
        id=record.id,
        system_identifier=record.system_identifier,
        username=record.username,
        label=record.label,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )

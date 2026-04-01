"""
routes.py
---------
All API route handlers. Imported and registered in main.py.

Each route is responsible for:
1. Receiving validated input (Pydantic handles this automatically)
2. Calling the appropriate service logic (encryption, DB)
3. Returning a safe response (never including plaintext passwords except /secret)
4. Handling downstream errors (SQLAlchemy, decryption) cleanly
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from src.database import get_db
from src.encryption import encrypt_password, decrypt_password
from src.models import CredentialRecord
from src.schemas import (
    CredentialCreate,
    CredentialMetadata,
    CredentialUpdate,
    CredentialWithSecret,
)

logger = logging.getLogger("routine_labs.routes")
router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_or_404(db: Session, credential_id: str) -> CredentialRecord:
    """Fetch a record by ID or raise HTTP 404. Catches DB errors as 500."""
    try:
        record = db.get(CredentialRecord, credential_id)
    except SQLAlchemyError as exc:
        logger.error("DB error on lookup | id=%s : %s", credential_id, type(exc).__name__)
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


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post(
    "/credentials",
    response_model=CredentialMetadata,
    status_code=status.HTTP_201_CREATED,
    summary="Store a new third-party credential",
)
def create_credential(body: CredentialCreate, db: Session = Depends(get_db)):
    """
    Encrypts the password with AES-128 (Fernet) and persists it.
    Returns metadata only — password is never echoed back.

    Errors
    ------
    409 : system_identifier already exists
    422 : validation failure
    500 : encryption or database failure
    """
    # Check unique constraint before hitting the DB to give a clear 409
    existing = db.query(CredentialRecord).filter_by(
        system_identifier=body.system_identifier
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A credential for '{body.system_identifier}' already exists. "
                   f"Use PATCH /credentials/{existing.id} to update it.",
        )

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
        logger.error("DB error on create: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to store credential. Please try again.",
        ) from exc

    logger.info("Credential stored | id=%s system=%s", record.id, record.system_identifier)
    return _to_metadata(record)


@router.get(
    "/credentials",
    response_model=list[CredentialMetadata],
    summary="List all credentials (metadata only)",
)
def list_credentials(
    system_identifier: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Returns metadata for all stored credentials. Passwords never included."""
    try:
        q = db.query(CredentialRecord)
        if system_identifier:
            q = q.filter(CredentialRecord.system_identifier == system_identifier)
        return [_to_metadata(r) for r in q.all()]
    except SQLAlchemyError as exc:
        logger.error("DB error on list: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve credentials. Please try again.",
        ) from exc


@router.get(
    "/credentials/{credential_id}",
    response_model=CredentialMetadata,
    summary="Get credential metadata (no password)",
)
def get_credential_metadata(credential_id: str, db: Session = Depends(get_db)):
    """Returns metadata for a single credential. Password is NOT included."""
    return _to_metadata(_get_or_404(db, credential_id))


@router.get(
    "/credentials/{credential_id}/secret",
    response_model=CredentialWithSecret,
    summary="Retrieve credential including decrypted password (internal only)",
)
def get_credential_with_secret(credential_id: str, db: Session = Depends(get_db)):
    """
    Returns the decrypted password.

    WARNING: Internal use only. In production protect with mTLS or a
    service token — never expose publicly.

    Errors
    ------
    404 : credential not found
    500 : DB failure or decryption failure (key mismatch / data corruption)
    """
    record = _get_or_404(db, credential_id)
    decrypted = decrypt_password(record.encrypted_password)

    logger.info("Secret retrieved | id=%s system=%s", record.id, record.system_identifier)
    return CredentialWithSecret(
        id=record.id,
        system_identifier=record.system_identifier,
        username=record.username,
        password=decrypted,
        label=record.label,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


@router.patch(
    "/credentials/{credential_id}",
    response_model=CredentialMetadata,
    summary="Update a stored credential",
)
def update_credential(
    credential_id: str,
    body: CredentialUpdate,
    db: Session = Depends(get_db),
):
    """
    Partially update a credential. Supply only the fields to change.
    Password is re-encrypted if supplied.

    Errors
    ------
    400 : no fields provided
    404 : credential not found
    500 : DB or encryption failure
    """
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
        logger.error("DB error on update | id=%s : %s", credential_id, type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update credential. Please try again.",
        ) from exc

    logger.info("Credential updated | id=%s system=%s", record.id, record.system_identifier)
    return _to_metadata(record)


@router.delete(
    "/credentials/{credential_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a stored credential",
)
def delete_credential(credential_id: str, db: Session = Depends(get_db)):
    """
    Permanently removes the credential.

    Errors
    ------
    404 : credential not found
    500 : DB failure
    """
    record = _get_or_404(db, credential_id)

    try:
        db.delete(record)
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        logger.error("DB error on delete | id=%s : %s", credential_id, type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete credential. Please try again.",
        ) from exc

    logger.info("Credential deleted | id=%s system=%s", record.id, record.system_identifier)

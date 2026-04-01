"""
encryption.py
-------------
Thin wrapper around Fernet for encrypting and decrypting passwords.

Keeping encryption logic here means:
- It can be tested in isolation
- The algorithm can be swapped without touching route code
- Errors are handled in one place
"""

import logging

from cryptography.fernet import InvalidToken
from fastapi import HTTPException, status

from src.config import fernet

logger = logging.getLogger("routine_labs.encryption")


def encrypt_password(plaintext: str) -> str:
    """
    Encrypt a plaintext password and return the Fernet ciphertext string.
    Raises HTTP 500 on unexpected failure.
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
    Decrypt a stored Fernet ciphertext back to plaintext.

    Raises HTTP 500 if the token is invalid or tampered with.
    This typically means the ENCRYPTION_KEY was rotated without
    re-encrypting existing records.
    """
    try:
        return fernet.decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        logger.error("Decryption failed — token invalid or key mismatch")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to decrypt credential. Key mismatch or data corruption.",
        ) from exc

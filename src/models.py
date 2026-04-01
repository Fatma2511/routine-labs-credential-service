"""
models.py
---------
SQLAlchemy ORM model for stored credentials.

Design notes
------------
- `system_identifier` has a UNIQUE constraint — only one credential per
  third-party system is allowed. This prevents ambiguity when an automation
  worker looks up which credential to use for e.g. "salesforce-prod".
- `encrypted_password` stores the Fernet ciphertext only. Plaintext never
  appears in any column.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, Text, UniqueConstraint

from src.database import Base


class CredentialRecord(Base):
    __tablename__ = "credentials"

    id                 = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    system_identifier  = Column(String(128), nullable=False, index=True, unique=True)
    username           = Column(String(256), nullable=False)
    encrypted_password = Column(Text, nullable=False)
    label              = Column(String(256), nullable=True)
    created_at         = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at         = Column(DateTime(timezone=True),
                                default=lambda: datetime.now(timezone.utc),
                                onupdate=lambda: datetime.now(timezone.utc))

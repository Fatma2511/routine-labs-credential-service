"""
schemas.py
----------
Pydantic models for request validation and response serialisation.

CredentialCreate     — input for POST /credentials
CredentialMetadata   — safe response (no password field)
CredentialWithSecret — response including decrypted password (internal only)
CredentialUpdate     — input for PATCH /credentials/{id}
"""

import re
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class CredentialCreate(BaseModel):
    system_identifier: str = Field(
        ..., min_length=1, max_length=128,
        description="Machine-readable identifier for the target system e.g. 'salesforce-prod'.",
    )
    username: str = Field(..., min_length=1, max_length=256)
    password: str = Field(..., min_length=1, max_length=1024,
                          description="Plaintext password — encrypted before persistence.")
    label: Optional[str] = Field(None, max_length=256)

    @field_validator("system_identifier")
    @classmethod
    def system_identifier_slug(cls, v: str) -> str:
        if not re.match(r"^[A-Za-z0-9_\-\.]{1,128}$", v):
            raise ValueError(
                "system_identifier must be 1-128 characters: "
                "letters, digits, hyphens, underscores, or dots."
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
    """Safe response — password is never included."""
    id: str
    system_identifier: str
    username: str
    label: Optional[str]
    created_at: datetime
    updated_at: datetime


class CredentialWithSecret(BaseModel):
    """Full response including decrypted password — internal services only."""
    id: str
    system_identifier: str
    username: str
    password: str
    label: Optional[str]
    created_at: datetime
    updated_at: datetime


class CredentialUpdate(BaseModel):
    """All fields optional — supply only what should change."""
    username: Optional[str] = Field(None, min_length=1, max_length=256)
    password: Optional[str] = Field(None, min_length=1, max_length=1024)
    label:    Optional[str] = Field(None, max_length=256)

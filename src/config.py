"""
config.py
---------
Loads environment variables from .env at startup via python-dotenv.
All configuration is centralised here — no os.getenv() calls scattered
across other modules.
"""

import os
from dotenv import load_dotenv
from cryptography.fernet import Fernet

# Load .env file first — must happen before any os.getenv() call
load_dotenv()

DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./credentials.db")
ALLOWED_ORIGINS: list[str] = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")

_raw_key: str = os.getenv("ENCRYPTION_KEY", "")

if not _raw_key:
    raise RuntimeError(
        "ENCRYPTION_KEY is not set. "
        "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
    )

try:
    fernet = Fernet(_raw_key.encode())
except Exception as exc:
    raise RuntimeError(f"ENCRYPTION_KEY is not a valid Fernet key: {exc}") from exc

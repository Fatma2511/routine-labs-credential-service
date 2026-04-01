"""
main.py
-------
Application entry point.

Responsibilities
----------------
- Create the FastAPI app instance
- Register middleware
- Register routes
- Create database tables on startup
"""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.config import ALLOWED_ORIGINS
from src.database import engine, Base
from src.routes import router

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

# ---------------------------------------------------------------------------
# Create tables
# ---------------------------------------------------------------------------
Base.metadata.create_all(bind=engine)

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Third-Party Credential Storage — Routine Labs",
    description=(
        "Stores encrypted credentials for external systems used by automation workflows.\n\n"
        "**Passwords are encrypted with AES-128 (Fernet) and never stored in plaintext.**\n\n"
        "Transport security (HTTPS/TLS) is assumed at the reverse proxy layer."
    ),
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

app.include_router(router)


@app.get("/health", tags=["Operations"], summary="Liveness probe")
def health():
    return {"status": "ok"}

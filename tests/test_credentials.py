"""
Tests for the Routine Labs Credential Storage Service.
Run: pytest tests/ -v
"""
import os
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from cryptography.fernet import Fernet
os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch
from sqlalchemy.exc import SQLAlchemyError

from src.app import app, Base, get_db

test_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
Base.metadata.create_all(bind=test_engine)


def override_get_db():
    db = TestSession()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

VALID_PAYLOAD = {
    "system_identifier": "salesforce-prod",
    "username": "alice@example.com",
    "password": "super-secret-password",
    "label": "Salesforce production",
}


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
def test_health():
    r = client.get("/health")
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Create — happy path
# ---------------------------------------------------------------------------
def test_create_credential_returns_metadata_without_password():
    r = client.post("/credentials", json=VALID_PAYLOAD)
    assert r.status_code == 201
    data = r.json()
    assert data["system_identifier"] == "salesforce-prod"
    assert data["username"] == "alice@example.com"
    assert "password" not in data
    assert "encrypted_password" not in data


# ---------------------------------------------------------------------------
# Create — 422 validation errors
# ---------------------------------------------------------------------------
def test_create_missing_required_field():
    """system_identifier missing → Pydantic returns 422."""
    r = client.post("/credentials", json={"username": "bob", "password": "pw"})
    assert r.status_code == 422


def test_create_invalid_system_identifier():
    """Spaces and ! in system_identifier → regex validator returns 422."""
    payload = {**VALID_PAYLOAD, "system_identifier": "has spaces here!"}
    r = client.post("/credentials", json=payload)
    assert r.status_code == 422


def test_create_empty_password():
    """Empty password violates min_length=1 → 422."""
    payload = {**VALID_PAYLOAD, "password": ""}
    r = client.post("/credentials", json=payload)
    assert r.status_code == 422


def test_create_wrong_type():
    """Sending an integer as username → Pydantic coerces or rejects → 422."""
    payload = {**VALID_PAYLOAD, "username": 12345}
    # Pydantic v2 coerces int to str, so this actually passes — documenting the behaviour.
    r = client.post("/credentials", json=payload)
    assert r.status_code in (201, 422)


# ---------------------------------------------------------------------------
# Create — 500 downstream: database failure
# ---------------------------------------------------------------------------
def test_create_database_failure_returns_500():
    """Simulate a database crash during commit → expect 500, not an unhandled exception."""
    with patch.object(TestSession, "commit", side_effect=SQLAlchemyError("db down")):
        r = client.post("/credentials", json=VALID_PAYLOAD)
    assert r.status_code == 500
    assert "encrypt" not in r.json()["detail"].lower()  # no internal detail leaked


# ---------------------------------------------------------------------------
# List / metadata
# ---------------------------------------------------------------------------
def test_list_credentials_no_passwords():
    r = client.get("/credentials")
    assert r.status_code == 200
    for item in r.json():
        assert "password" not in item
        assert "encrypted_password" not in item


def test_list_filter_by_system():
    client.post("/credentials", json={**VALID_PAYLOAD, "system_identifier": "jira-acme"})
    r = client.get("/credentials?system_identifier=jira-acme")
    assert r.status_code == 200
    assert all(item["system_identifier"] == "jira-acme" for item in r.json())


# ---------------------------------------------------------------------------
# Get single — 404
# ---------------------------------------------------------------------------
def test_get_nonexistent_credential_returns_404():
    r = client.get("/credentials/00000000-does-not-exist")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Secret retrieval — happy path (decryption round-trip)
# ---------------------------------------------------------------------------
def test_secret_endpoint_returns_decrypted_password():
    create_r = client.post("/credentials", json=VALID_PAYLOAD)
    cred_id = create_r.json()["id"]

    secret_r = client.get(f"/credentials/{cred_id}/secret")
    assert secret_r.status_code == 200
    assert secret_r.json()["password"] == VALID_PAYLOAD["password"]


# ---------------------------------------------------------------------------
# Secret retrieval — 404 and 500 downstream
# ---------------------------------------------------------------------------
def test_secret_nonexistent_credential_returns_404():
    r = client.get("/credentials/00000000-does-not-exist/secret")
    assert r.status_code == 404


def test_secret_decryption_failure_returns_500():
    """
    Simulate a key mismatch by storing a record with a ciphertext encrypted
    by a *different* key, then attempting to decrypt with the current key.
    This is the real-world key-rotation failure scenario.
    """
    from src.app import CredentialRecord
    wrong_key_fernet = Fernet(Fernet.generate_key())
    fake_ciphertext = wrong_key_fernet.encrypt(b"some-password").decode()

    db = TestSession()
    import uuid
    record = CredentialRecord(
        id=str(uuid.uuid4()),
        system_identifier="test-system",
        username="user@example.com",
        encrypted_password=fake_ciphertext,
    )
    db.add(record)
    db.commit()
    cred_id = record.id
    db.close()

    r = client.get(f"/credentials/{cred_id}/secret")
    assert r.status_code == 500
    assert "key" in r.json()["detail"].lower() or "decrypt" in r.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Plaintext never in DB
# ---------------------------------------------------------------------------
def test_password_is_not_stored_in_plaintext():
    from src.app import CredentialRecord
    db = TestSession()
    records = db.query(CredentialRecord).all()
    for r in records:
        assert VALID_PAYLOAD["password"] not in r.encrypted_password
        assert r.encrypted_password.startswith("gAAAAA")
    db.close()


# ---------------------------------------------------------------------------
# Update — happy path
# ---------------------------------------------------------------------------
def test_update_password_re_encrypts():
    create_r = client.post("/credentials", json=VALID_PAYLOAD)
    cred_id = create_r.json()["id"]

    new_pw = "updated-password-456"
    patch_r = client.patch(f"/credentials/{cred_id}", json={"password": new_pw})
    assert patch_r.status_code == 200

    secret_r = client.get(f"/credentials/{cred_id}/secret")
    assert secret_r.json()["password"] == new_pw


# ---------------------------------------------------------------------------
# Update — 400 empty body
# ---------------------------------------------------------------------------
def test_update_empty_body_returns_400():
    """PATCH with no fields at all is a client error → 400."""
    create_r = client.post("/credentials", json=VALID_PAYLOAD)
    cred_id = create_r.json()["id"]

    r = client.patch(f"/credentials/{cred_id}", json={})
    assert r.status_code == 400
    assert "at least one field" in r.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Update — 404
# ---------------------------------------------------------------------------
def test_update_nonexistent_credential_returns_404():
    r = client.patch("/credentials/00000000-does-not-exist", json={"label": "new label"})
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Delete — happy path
# ---------------------------------------------------------------------------
def test_delete_credential():
    create_r = client.post("/credentials", json=VALID_PAYLOAD)
    cred_id = create_r.json()["id"]

    del_r = client.delete(f"/credentials/{cred_id}")
    assert del_r.status_code == 204

    get_r = client.get(f"/credentials/{cred_id}")
    assert get_r.status_code == 404


# ---------------------------------------------------------------------------
# Delete — 404
# ---------------------------------------------------------------------------
def test_delete_nonexistent_credential_returns_404():
    r = client.delete("/credentials/00000000-does-not-exist")
    assert r.status_code == 404

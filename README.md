# Third-Party Credential Storage Service

A Python backend service that securely stores login credentials for external third-party systems used by automation workflows.

---

## The core design decision: encryption, not hashing

This service stores credentials that an automation worker must later use to log into external systems. Because the **plaintext password must be recoverable**, one-way hashing (bcrypt, Argon2) is not appropriate here — a hash cannot be reversed.

Instead, passwords are protected with **symmetric authenticated encryption** using AES-128 via the [Fernet](https://cryptography.io/en/latest/fernet/) construction from the Python `cryptography` library:

- The password is encrypted before any write to the database.
- Only the ciphertext is stored — the plaintext and the encryption key never coexist in a database row.
- Fernet provides both **confidentiality** (AES-128-CBC) and **integrity** (HMAC-SHA256). A tampered ciphertext is rejected at decryption time.
- The encryption key lives in an environment variable (`ENCRYPTION_KEY`). In production this should come from a secrets manager (Vault, AWS Secrets Manager, GCP Secret Manager) — not a `.env` file.

---

## Quick start (local)

### 1. Clone and install dependencies

```bash
git clone <repo>
cd routine-labs-credentials
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Generate an encryption key

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### 3. Configure environment

```bash
cp .env.example .env
# Paste the generated key as ENCRYPTION_KEY in .env
```

### 4. Start the service

```bash
# From the repo root
uvicorn src.app:app --reload --port 8000
```

API docs available at: http://localhost:8000/docs

### 5. Run tests

```bash
pytest tests/ -v
```

---

## Docker (with PostgreSQL)

```bash
# 1. Set your encryption key in .env (same step as above)

# 2. Start everything
docker compose up --build

# Service: http://localhost:8000
# PostgreSQL: localhost:5432
```

---

## Example requests

### Store a credential

```bash
curl -X POST http://localhost:8000/credentials \
  -H "Content-Type: application/json" \
  -d '{
    "system_identifier": "salesforce-prod",
    "username": "alice@example.com",
    "password": "super-secret-password",
    "label": "Salesforce production account"
  }'
```

Response (no password):

```json
{
  "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "system_identifier": "salesforce-prod",
  "username": "alice@example.com",
  "label": "Salesforce production account",
  "created_at": "2026-03-20T10:00:00Z",
  "updated_at": "2026-03-20T10:00:00Z"
}
```

### List credentials (metadata only)

```bash
curl http://localhost:8000/credentials
curl "http://localhost:8000/credentials?system_identifier=salesforce-prod"
```

### Retrieve decrypted credential (internal services only)

```bash
curl http://localhost:8000/credentials/{id}/secret
```

### Update a credential

```bash
curl -X PATCH http://localhost:8000/credentials/{id} \
  -H "Content-Type: application/json" \
  -d '{"password": "new-password"}'
```

### Delete a credential

```bash
curl -X DELETE http://localhost:8000/credentials/{id}
```

---

## API design

| Method | Path | Description | Returns password? |
|---|---|---|---|
| `POST` | `/credentials` | Store a new credential | No |
| `GET` | `/credentials` | List all (optional `?system_identifier=` filter) | No |
| `GET` | `/credentials/{id}` | Get metadata for one credential | No |
| `GET` | `/credentials/{id}/secret` | Get credential with decrypted password | **Yes** |
| `PATCH` | `/credentials/{id}` | Update username, password, or label | No |
| `DELETE` | `/credentials/{id}` | Remove a credential | — |
| `GET` | `/health` | Liveness probe | — |

The `/secret` endpoint is the only one that returns a decrypted password. In production it should be protected by an internal network policy, mTLS, or a service token, and should never be publicly routable.

---

## Storage design

```
credentials table
─────────────────────────────────────────────────────────
 id                  UUID (PK)
 system_identifier   VARCHAR(128)
 username            VARCHAR(256)
 encrypted_password  TEXT           Fernet token (AES-128 ciphertext)
 label               VARCHAR(256)   nullable
 created_at          TIMESTAMPTZ
 updated_at          TIMESTAMPTZ
─────────────────────────────────────────────────────────
```

The `encrypted_password` column contains a Fernet token: a base64url string that embeds the version, timestamp, IV, ciphertext, and HMAC. The plaintext never appears in the database.

---

## Security considerations

**Encryption key management** is the critical trust boundary. A few notes:

- The key must be stored separately from the database. If both are compromised simultaneously, all passwords are exposed.
- Key rotation requires re-encrypting all stored values with the new key before retiring the old one. This is not implemented here but should be a production concern.
- In a real deployment: store the key in AWS Secrets Manager / GCP Secret Manager / HashiCorp Vault, not in a `.env` file.

**The `/secret` endpoint** exposes decrypted passwords. It must be treated as an internal-only API surface. Options for protecting it in production: mTLS between services, an API gateway that blocks it from public routes, or a service token validated in middleware.

**Logs never contain passwords.** The logger redacts usernames too, only logging the credential ID and system identifier.

**SQL injection** is prevented by SQLAlchemy's ORM with parameterised queries throughout.

**Input validation** is enforced by Pydantic before any logic runs. The `system_identifier` field only accepts safe characters (letters, digits, hyphens, underscores, dots).

---

## Trade-offs and limitations

| Area | Decision | Trade-off |
|---|---|---|
| Encryption algorithm | Fernet (AES-128-CBC + HMAC-SHA256) | Simple, well-audited. AES-256-GCM would offer stronger confidentiality; Fernet is slightly simpler to operate correctly. |
| Key storage | Environment variable | Easy to operate locally; must be replaced with a secrets manager in production. |
| Database | SQLite (dev) / PostgreSQL (prod) | SQLite requires no infrastructure; PostgreSQL is the right choice for anything beyond a single server. |
| Key rotation | Not implemented | A production service should support dual-key decryption during rotation windows. |
| `/secret` auth | Not implemented | Marked in code; in production this needs mTLS or a service token. |
| Rate limiting | Not implemented | Should be added (e.g. `slowapi`) before production to prevent enumeration. |

---

## Decision log

**Framework — FastAPI**
FastAPI offers async support, automatic OpenAPI docs, and Pydantic integration for schema validation. It is the pragmatic modern choice for a small Python API without the ceremony of Django.

**Database — SQLite (dev) / PostgreSQL (prod)**
SQLite requires zero infrastructure and is appropriate for local development. The `DATABASE_URL` environment variable makes it trivial to swap to PostgreSQL for any real deployment.

**Security pattern — Fernet encryption (not hashing)**
The task explicitly states that passwords must later be used to log into external systems. This means the plaintext must be recoverable, ruling out one-way hashing. Fernet (AES-128-CBC + HMAC-SHA256) provides both confidentiality and tamper detection with a clean Python API, without requiring low-level AES plumbing.

**API design — metadata / secret split**
The standard credential endpoints return metadata only. A separate `/secret` endpoint returns the decrypted password. This makes it easy to audit who is requesting plaintext passwords, and makes it straightforward to protect that single route in production (network policy, mTLS, service token) without restricting access to metadata.

---

## AI usage

See [docs/ai_usage.md](docs/ai_usage.md) for a full account of how AI tools were used during development, which decisions were materially my own, and where I disagreed with or corrected AI-generated suggestions.

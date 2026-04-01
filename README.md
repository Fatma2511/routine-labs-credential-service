# Third-Party Credential Storage Service

A Python backend service that securely stores login credentials for external third-party systems used by automation workflows.

---

## The core design decision: encryption, not hashing

This service stores credentials that an automation worker must later use to log into external systems. Because the **plaintext password must be recoverable**, one-way hashing (bcrypt, Argon2) is not appropriate — a hash cannot be reversed.

Instead, passwords are protected with **symmetric authenticated encryption** using AES-128 via [Fernet](https://cryptography.io/en/latest/fernet/):

- The password is encrypted before any write to the database
- Only the ciphertext is stored — the plaintext and the key never coexist in a DB row
- Fernet provides both **confidentiality** (AES-128-CBC) and **integrity** (HMAC-SHA256)
- The encryption key is loaded from the `ENCRYPTION_KEY` environment variable via `python-dotenv` — in production this should come from a secrets manager

---

## Project structure

```
src/
├── __init__.py      ← makes src a Python package
├── main.py          ← app instance, middleware, startup
├── config.py        ← loads .env, validates and exposes config
├── database.py      ← SQLAlchemy engine, session, Base
├── models.py        ← ORM model (credentials table)
├── schemas.py       ← Pydantic request/response models
├── encryption.py    ← encrypt_password / decrypt_password
└── routes.py        ← all API endpoints
tests/
└── test_credentials.py
docs/
├── architecture.md
└── ai_usage.md
```

Each module has a single responsibility. This makes the code easier to read,
test in isolation, and extend without touching unrelated parts.

---

## Quick start

### 1. Install dependencies

```bash
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
uvicorn src.main:app --reload --port 8000
```

API docs available at: http://localhost:8000/docs

### 5. Run tests

```bash
pytest tests/ -v
```

---

## Docker

```bash
# Set ENCRYPTION_KEY in .env first
docker compose up --build
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

### List credentials (no passwords)

```bash
curl http://localhost:8000/credentials
curl "http://localhost:8000/credentials?system_identifier=salesforce-prod"
```

### Retrieve decrypted password (internal only)

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
| `GET` | `/credentials` | List all (filter by `?system_identifier=`) | No |
| `GET` | `/credentials/{id}` | Get metadata | No |
| `GET` | `/credentials/{id}/secret` | Get with decrypted password | **Yes** |
| `PATCH` | `/credentials/{id}` | Update fields | No |
| `DELETE` | `/credentials/{id}` | Remove | — |
| `GET` | `/health` | Liveness probe | — |

The `/secret` endpoint is the only surface that returns a plaintext password.
In production it must be protected by an internal network policy, mTLS, or a
service token — it should never be publicly routable.

---

## Storage design

```
credentials table
─────────────────────────────────────────────────────────
 id                  UUID (PK)
 system_identifier   VARCHAR(128)   UNIQUE
 username            VARCHAR(256)
 encrypted_password  TEXT           Fernet token (AES-128 ciphertext)
 label               VARCHAR(256)   nullable
 created_at          TIMESTAMPTZ
 updated_at          TIMESTAMPTZ
─────────────────────────────────────────────────────────
```

`system_identifier` is unique — only one credential per third-party system is
allowed. Submitting the same identifier twice returns 409. Use
`PATCH /credentials/{id}` to update an existing credential.

---

## Security considerations

- Passwords are encrypted with Fernet (AES-128-CBC + HMAC-SHA256) before any DB write
- The `ENCRYPTION_KEY` is loaded at startup via `python-dotenv` — never hardcoded
- Logs never contain passwords — only credential IDs and system identifiers
- SQL injection is prevented by SQLAlchemy's parameterised queries throughout
- The `/secret` endpoint is the only route that returns plaintext — treat as internal-only
- All database errors are caught explicitly — no raw stack traces reach the client

**Key management in production:** Store `ENCRYPTION_KEY` in a secrets manager
(AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager) rather than a `.env` file.

---

## Trade-offs and limitations

| Area | Decision | Trade-off |
|---|---|---|
| Encryption | Fernet (AES-128) | Simple and well-audited. AES-256-GCM would be stronger; Fernet is easier to operate correctly. |
| Key storage | Environment variable | Simple for local dev; must use a secrets manager in production. |
| Database | SQLite (dev) / PostgreSQL (prod) | SQLite needs no infrastructure; swap via `DATABASE_URL`. |
| Key rotation | Not implemented | Production should support dual-key decryption during rotation windows. |
| `/secret` auth | Not implemented | Needs mTLS or service token before going public. |
| Rate limiting | Not implemented | Should be added (e.g. `slowapi`) in production. |

---

## Decision log

**Framework — FastAPI**
FastAPI with Pydantic gives automatic input validation, OpenAPI docs, and clean
dependency injection. Flask would require too much manual wiring; Django REST is
oversized for a small service.

**Database — SQLite (dev) / PostgreSQL (prod)**
SQLite requires no infrastructure and works immediately for local development.
The `DATABASE_URL` variable makes the switch to PostgreSQL trivial.

**Security pattern — Fernet encryption (not hashing)**
The task requires passwords to be reused to log into external systems — the
plaintext must be recoverable. One-way hashing is therefore not suitable.
Fernet provides confidentiality and tamper detection with a clean Python API.

**system_identifier uniqueness**
Only one credential per system is allowed. This prevents ambiguity when an
automation worker looks up which credential to use for a given system.

**Project structure**
Logic is split across six modules, each with a single responsibility. This makes
the codebase easier to read, test, and extend without touching unrelated parts.

---

## AI usage

See [docs/ai_usage.md](docs/ai_usage.md) for a full account of how AI tools
were used during development, which decisions were materially my own, and where
I disagreed with or corrected AI-generated suggestions.


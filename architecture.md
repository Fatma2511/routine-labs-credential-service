# Architecture & Design

## System Overview

```mermaid
sequenceDiagram
    participant Client as Web Form / Client
    participant Proxy as nginx (TLS termination)
    participant API as FastAPI Service
    participant DB as SQLite / PostgreSQL

    Client->>Proxy: HTTPS POST /credentials {system_id, username, password}
    Proxy->>API: HTTP POST /credentials (internal network)
    API->>API: Validate input (Pydantic)
    API->>API: Fernet.encrypt(password) → ciphertext
    API->>DB: INSERT {system_id, username, ciphertext, label}
    DB-->>API: record saved
    API-->>Proxy: 201 {id, system_id, username, label, timestamps}
    Proxy-->>Client: 201 (no password in response)

    Note over Client,DB: Password never travels beyond the API in plaintext
```

```mermaid
sequenceDiagram
    participant Worker as Automation Worker
    participant API as FastAPI Service
    participant DB as SQLite / PostgreSQL

    Worker->>API: GET /credentials/{id}/secret
    API->>DB: SELECT encrypted_password WHERE id = ?
    DB-->>API: ciphertext
    API->>API: Fernet.decrypt(ciphertext) → plaintext
    API-->>Worker: {id, system_id, username, password, ...}
    Worker->>Worker: Use password to log in to third-party system
```

## Storage Model

```
credentials table
─────────────────────────────────────────────────────────
 id                  UUID (PK)
 system_identifier   VARCHAR(128)   e.g. "salesforce-prod"
 username            VARCHAR(256)   e.g. "alice@example.com"
 encrypted_password  TEXT           Fernet token (AES-128 ciphertext)
 label               VARCHAR(256)   optional description
 created_at          TIMESTAMPTZ
 updated_at          TIMESTAMPTZ
─────────────────────────────────────────────────────────
```

The `encrypted_password` column holds a Fernet token which is a base64url-encoded
string containing: version byte | timestamp | IV | ciphertext | HMAC.

## Encryption Key Lifecycle

```
Production (recommended)
────────────────────────
Secrets Manager (Vault / AWS SM)
        │
        ▼
   App on startup  ──reads──►  ENCRYPTION_KEY env var
        │
        ▼
   Fernet(key)  ──used for──►  encrypt() / decrypt()
        │
        ▼
   Key never written to disk or DB
```

## Endpoint Map

| Method   | Path                              | Returns password? |
|----------|-----------------------------------|-------------------|
| POST     | /credentials                      | No — metadata only |
| GET      | /credentials                      | No — metadata only |
| GET      | /credentials/{id}                 | No — metadata only |
| GET      | /credentials/{id}/secret          | Yes — decrypted    |
| PATCH    | /credentials/{id}                 | No — metadata only |
| DELETE   | /credentials/{id}                 | —                  |

The `/secret` endpoint should only be reachable from internal services in production.

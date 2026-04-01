# AI Usage Documentation

This document describes how AI (Claude) was used during this exercise,
which parts were shaped by my own decisions, and where I disagreed with
or corrected the AI-generated output.

---

## How AI was used

I used Claude as a coding assistant — similar to a pair programmer.
I described the problem, reviewed the output, asked questions about
specific implementation choices, and pushed back when something was wrong.

---

## Correction 1 — Hashing vs. encryption

**What Claude initially built:**

Claude's first version used **Argon2id password hashing** to store the credentials.
The implementation was technically correct for a login system — but completely
wrong for this use case.

```python
# Claude's first (wrong) approach
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
hashed = ph.hash(body.password)
record = CredentialRecord(username=body.username, hash=hashed)
```

**Why I rejected it:**

I re-read the task description which explicitly states:

> "If the password must later be used again to log into another external system,
> simple password hashing is not sufficient, because hashes cannot be reversed."

This is a credential storage service for automation workflows — the service
needs to log into Salesforce, Jira, or other third-party systems on behalf of
the user. That means the plaintext password must be recoverable.

Hashing is a one-way function. You cannot get "my-password" back from its
Argon2 hash. Claude had missed this fundamental distinction.

**What I told Claude to change:**

I pointed out the mismatch and asked Claude to rebuild the solution using
reversible encryption instead. Claude then switched to Fernet (AES-128)
which is the correct pattern for this use case.

---

## Correction 2 — Missing error handling

**What Claude initially built:**

The routes had no error handling around database operations:

```python
# Claude's first version — no error handling
db.add(record)
db.commit()      # if the database is down, unhandled exception
db.refresh(record)
```

If the database was unreachable, the service would crash with an unhandled
SQLAlchemy exception and return a raw 500 error with internal details visible
to the client. Similarly, encrypt_password() had no try/except.

**What I asked Claude to add:**

- try/except SQLAlchemyError around every db.commit(), db.delete(), and db.get()
- db.rollback() in every except block to prevent partial writes
- A 400 check in the PATCH route for empty bodies
- A test that simulates a real key-rotation failure (wrong key → 500)

---

## Correction 3 — Everything in one file

**What Claude initially built:**

All logic — configuration, database setup, ORM model, Pydantic schemas,
encryption helpers, and all routes — was in a single app.py file.
This makes the code hard to read, test in isolation, and extend.

**What I asked Claude to change:**

I asked Claude to split the code into separate modules, each with a single
responsibility:

```
src/
├── main.py        ← app instance and startup
├── config.py      ← environment variables and Fernet key init
├── database.py    ← SQLAlchemy engine and session
├── models.py      ← ORM model
├── schemas.py     ← Pydantic schemas
├── encryption.py  ← encrypt / decrypt logic
└── routes.py      ← API endpoints
```

---

## Correction 4 — .env not loaded at startup

**What Claude initially built:**

python-dotenv was listed in requirements.txt but load_dotenv() was
never actually called. This meant the .env file was never read at startup —
ENCRYPTION_KEY would always be empty and the app would crash immediately
unless the variables were exported manually in the shell.

**What I told Claude to fix:**

I noticed the .env was never loaded and asked Claude to add load_dotenv()
at the top of config.py, before any os.getenv() call:

```python
from dotenv import load_dotenv
load_dotenv()  # must run before os.getenv()
```

---

## Correction 5 — system_identifier not unique

**What Claude initially built:**

There was no unique constraint on system_identifier. The same system could
be stored multiple times, creating ambiguous duplicate records. An automation
worker looking up credentials for "salesforce-prod" could get multiple results
and would not know which one to use.

**What I asked Claude to fix:**

I pointed out that only one credential per system should be allowed and asked
Claude to add a unique constraint at the database level and a 409 response
at the API level:

```python
# models.py
system_identifier = Column(String(128), nullable=False, unique=True)
```

```python
# routes.py — explicit 409 before hitting the DB
existing = db.query(CredentialRecord).filter_by(
    system_identifier=body.system_identifier
).first()
if existing:
    raise HTTPException(status_code=409, detail="Already exists...")
```

---

## Where I agreed with Claude's suggestions

- **FastAPI over Flask or Django REST** — right fit for the task size
- **Fernet over raw AES** — well-audited, hard to misuse, correct abstraction level
- **Metadata / secret endpoint split** — clean way to isolate the sensitive surface
- **SQLite for dev, PostgreSQL for prod** — pragmatic trade-off, easy to switch

---

## Summary

The decisions that materially shaped the final solution were all mine:

1. Recognising that hashing was wrong for this use case — encryption was needed
2. Requiring explicit error handling for all downstream failures
3. Splitting the code into separate modules for clarity and extensibility
4. Noticing that load_dotenv() was never called — the .env bug
5. Identifying that system_identifier needed a unique constraint

The AI was useful for generating boilerplate, structuring modules, and writing
tests — but every significant engineering decision came from reading the task
carefully and reviewing the output critically.


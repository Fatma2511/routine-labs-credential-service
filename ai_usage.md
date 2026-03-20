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

## Critical correction I made: hashing vs. encryption

**What Claude initially built:**

Claude's first version used **Argon2id password hashing** to store the credentials.
The implementation was technically correct for a login system — but completely
wrong for this use case.

The first version stored credentials like this:

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

Hashing is a one-way function. You cannot get `"my-password"` back from its
Argon2 hash. Claude had missed this fundamental distinction.

**What I told Claude to change:**

I pointed out the mismatch and asked Claude to rebuild the solution using
**reversible encryption** instead. Claude then switched to Fernet (AES-128)
which is the correct pattern for this use case.

**Why this matters:**

This is the central security decision in the entire exercise. Getting it wrong
would have meant storing credentials that the automation worker could never
actually use. The task description explicitly called this out as the key
evaluation criterion — and the AI missed it on the first attempt.

---

## Second correction: missing error handling

**What Claude initially built:**

The routes had no error handling around database operations. For example:

```python
# Claude's first version — no error handling
db.add(record)
db.commit()      # if the database is down, this raises an unhandled exception
db.refresh(record)
```

If the database was unreachable, the service would crash with an unhandled
SQLAlchemy exception and return an unformatted 500 error with internal
stack trace details visible to the client.

Similarly, `encrypt_password()` had no try/except — any unexpected failure
would bubble up uncontrolled.

**Why I asked for the change:**

A production backend service must handle downstream failures gracefully.
The database is an external dependency — it can be unavailable, slow, or
return unexpected errors. The service should:

- Catch these errors explicitly
- Roll back any partial database changes
- Log the full error server-side
- Return a clean, generic 500 message to the client without leaking internals

I also pointed out that the PATCH endpoint had no validation for an empty
body — sending `{}` would silently do nothing, which is a semantic error
that should return 400.

**What I asked Claude to add:**

- `try/except SQLAlchemyError` around every `db.commit()`, `db.delete()`,
  and `db.get()` call
- `db.rollback()` in every except block
- A 400 check in the PATCH route for empty bodies
- A test that simulates a real key-rotation failure (wrong key → 500)

---

## Where I agreed with Claude's suggestions

- **FastAPI over Flask or Django REST**: I agreed with this choice.
  Flask would require too much manual wiring. Django REST is oversized
  for a small service. FastAPI with Pydantic is the right fit.

- **Fernet over raw AES**: Once the encryption approach was agreed,
  I accepted Claude's suggestion to use Fernet rather than building
  AES-CBC + HMAC manually. Fernet is a well-audited, hard-to-misuse
  abstraction and is the right choice for this scope.

- **Metadata / secret endpoint split**: Separating the normal metadata
  endpoints from the `/secret` endpoint that returns decrypted passwords
  is a clean design. It makes the sensitive surface area explicit and
  easy to protect separately in production.

- **SQLite for dev, PostgreSQL for prod**: Reasonable trade-off for a
  small exercise. The `DATABASE_URL` environment variable makes the
  switch trivial.

---

## Summary

The two decisions that materially shaped the final solution were both mine:

1. Recognising that hashing was the wrong security pattern for this use case
   and insisting on reversible encryption instead.

2. Identifying that database and encryption failures were unhandled downstream
   errors and requiring explicit error handling with rollback and clean HTTP
   responses.

The AI was useful for generating boilerplate, structuring the project, and
writing tests — but the two most important engineering judgements came from
reading the task carefully and pushing back on the initial output.

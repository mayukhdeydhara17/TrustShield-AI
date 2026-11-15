# TrustShield AI

AI-powered phishing detection and website security assessment platform.

## Run locally

### Backend (from the repository root)

```bash
python -m pip install -r requirements.txt
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

The API creates `backend/trustshield.db` automatically on first startup. Set
`TRUSTSHIELD_DB_PATH` to choose a persistent database location. Set
`FRONTEND_URL` to your deployed frontend origin when deploying.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

By default, the frontend connects to `http://127.0.0.1:8000`. To use a deployed
API, create `frontend/.env` with:

```env
VITE_API_URL=https://your-api-domain.example
```

## Authentication

- Create an account from `#/sign-in` using a name, email, and password (minimum
  8 characters).
- Sign in with the same email and password.
- Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes; plaintext passwords
  are never stored.
- The API issues a random bearer token and stores only its SHA-256 hash.
- The frontend stores the token in browser local storage.

Google/GitHub OAuth, password-reset email, and magic-link login are not
configured in this project yet; the login screen does not pretend those flows
are active.

## Account-specific scan history

- Website scans require a valid signed-in session.
- Each completed scan is saved in the backend SQLite database with its owner account ID and full JSON report.
- `GET /scans` returns only the current account's scan history (up to the latest 500 records).
- The frontend loads history from the API after validating the session; it does not use one shared browser-local history list.
- The navigation bar shows a Profile control. Hovering or focusing it reveals the signed-in account name and email, a link to scan history, and Sign out.
- Signing out revokes the current server session and clears the browser's local session data.

Existing scans that were saved only in the old browser-local history are not automatically assigned to an account. They remain local in the previous browser storage and are not uploaded because their owner cannot be verified.


## If scan history does not appear

1. Start the backend from the project root with `uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000`.
2. Sign in to the same account before scanning. The `/scan` endpoint requires a bearer token.
3. After a successful scan, the backend inserts the full report into `backend/trustshield.db`; `GET /scans` returns that account's records.
4. If you use a hosted backend, its filesystem must be persistent. For a hosted service with an ephemeral filesystem, set `TRUSTSHIELD_DB_PATH` to a persistent mounted volume.
5. If the database was created by an older version of TrustShield with a different `scans` table structure, the backend now preserves that old table as `scans_legacy_unassigned` and creates the account-linked table. Old records without known account ownership are not silently assigned to a user.

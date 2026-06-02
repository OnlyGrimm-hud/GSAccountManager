# GS Account Manager

GS Account Manager is a Render-ready, server-rendered web app for secure account storage and manual workflow tracking.

The app is intentionally manual-only. It stores encrypted account data, provides copy buttons, opens configured pages in new tabs, and tracks local progress. It does not automate third-party logins, submit forms, create external accounts, solve CAPTCHA, bypass security checks, or perform unattended browser actions.

## Stack

- Node.js + Express
- EJS templates
- PostgreSQL with `pg`
- `express-session` with PostgreSQL session storage
- AES-256-GCM field encryption using `ENCRYPTION_KEY`
- Helmet secure headers
- Login rate limiting
- CSRF protection for forms
- Built-in TOTP generation for saved OTP secrets

## Render Settings

Use these exact settings for the GitHub repo `OnlyGrimm-hud/GSAccountManager`:

- Root Directory: leave blank / repository root
- Build Command: `npm install`
- Start Command: `npm start`
- Health Check Path: `/healthz`
- Runtime: Node

The app listens on `process.env.PORT`.

## Required Environment Variables

- `DATABASE_URL`: Render Postgres internal connection string.
- `ENCRYPTION_KEY`: 32 random bytes encoded as base64, or a 64-character hex string.
- `SESSION_SECRET`: long random session secret.
- `ADMIN_USERNAME`: temporary local admin username.
- `ADMIN_PASSWORD`: temporary local admin password.
- `NODE_ENV=production`
- `COOKIE_SECURE=true`
- `AUTO_MIGRATE=true`

Optional:

- `ADMIN_PASSWORD_HASH`: optional `scrypt:salt:hexhash` admin password hash.
- `APP_NAME=GS Account Manager`
- `DISCORD_CLIENT_ID`
- `DISCORD_CLIENT_SECRET`
- `DISCORD_REDIRECT_URI`

Generate an encryption key in PowerShell:

```powershell
$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
[Convert]::ToBase64String($bytes)
$rng.Dispose()
```

Do not change `ENCRYPTION_KEY` after storing real account data, or existing encrypted fields will no longer decrypt.

## Local Setup

1. Install Node.js 20 or newer.
2. Create a PostgreSQL database.
3. Copy `.env.example` to `.env`.
4. Fill in the required environment variables.
5. Install dependencies:

```bash
npm install
```

6. Run smoke checks:

```bash
npm run smoke
```

7. Start the app:

```bash
npm start
```

## Database

Schema and idempotent startup migrations live in `db/init.sql`. `AUTO_MIGRATE=true` runs the schema on startup.

Existing MVP columns are preserved. The v1 migration adds:

- `legacy_login`
- `legacy_password_encrypted`
- `email_password_encrypted`
- `jagex_email_encrypted`
- `jagex_name`
- `first_name`
- `last_name`
- `birth_month`
- `birth_day`
- `birth_year`
- `assigned_http_proxy_id`
- `assigned_socks5_proxy_id`
- `credential_status`
- `upgrade_status`
- `email_creation_status`
- `exported_at`
- `archived_at`

No database reset should be required for normal upgrades.

## Import Formats

Default delimiter is `:`.

- `username:password`
- `username:password:otp`
- `username:password:bank_pin:otp`
- `username:password:otp:notes`

The import page shows valid rows, duplicate rows, and invalid rows before committing.

## Export Formats

- `legacy username:password`
- `legacy username:password:otp`
- `jagex email:password`
- `jagex email:password:otp`
- `full safe CSV export`

After export, accounts can be kept, marked exported, or archived. Delete-after-export is review-only and never deletes automatically.

## Security Notes

- Sensitive account fields are encrypted at rest.
- Sensitive values are masked by default in list views.
- Copy actions log the field name only, never the copied value.
- Passwords, OTP secrets, OTP codes, proxy passwords, and encryption keys are not written to logs.
- `.env` is ignored and must not be committed.

## Future Discord OAuth

Discord placeholders are included for a later OAuth login upgrade. The current v1 keeps env-based admin login.

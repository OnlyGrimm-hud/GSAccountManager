# GS Account Manager

GS Account Manager is a Render-ready, server-rendered web app for secure account storage and manual workflow tracking.

The app is intentionally manual-only. It stores encrypted account data, provides copy buttons, opens configured pages in new tabs, and tracks local progress. It does not automate third-party logins, submit forms, create external accounts, solve CAPTCHA, bypass security checks, or perform unattended browser actions.

## Stack

- Node.js + Express
- EJS templates
- PostgreSQL with `pg`
- `express-session` with PostgreSQL session storage
- Discord OAuth2 login
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
- `DISCORD_CLIENT_ID`
- `DISCORD_CLIENT_SECRET`
- `DISCORD_CALLBACK_URL`
- `APP_BASE_URL`
- `AUTH_MODE=discord`
- `NODE_ENV=production`
- `COOKIE_SECURE=true`
- `AUTO_MIGRATE=true`

Optional:

- `ADMIN_PASSWORD_HASH`: optional `scrypt:salt:hexhash` admin password hash.
- `ADMIN_USERNAME`: optional emergency fallback username.
- `ADMIN_PASSWORD`: optional emergency fallback password.
- `APP_NAME=GS Account Manager`

Add these redirect URLs in the Discord Developer Portal:

- `https://gsaccountmanager.com/auth/discord/callback`
- `http://localhost:3000/auth/discord/callback`

For Render production, set `APP_BASE_URL=https://gsaccountmanager.com` and `DISCORD_CALLBACK_URL=https://gsaccountmanager.com/auth/discord/callback`.

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

- `users`
- `username`, `global_name`, `avatar`, and `email` Discord profile fields on users
- `subscription_status` on users, defaulting new Discord users to `inactive`
- `user_id` ownership columns on accounts, proxies, settings, and activity logs
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

If old rows have no `user_id`, the first Discord user who logs in claims them only when no prior owner exists yet. The app writes a setup warning to activity logs when this happens. Existing data is not deleted.

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

## GS Local Helper

GS Account Manager is a hosted web app, so it cannot directly launch a user's local Chrome with proxy flags or local browser profiles. GS Local Helper is the planned Windows companion app that will run on the user's PC and connect to the user's Discord-authenticated workspace.

Current web-side support:

- Local Helper page at `/local-helper`
- Windows download placeholder at `/downloads/helper/windows`
- user-scoped `helper_devices`, `helper_commands`, and `helper_pairing_codes` tables
- short-lived pairing code generation
- hashed pairing-code storage
- helper status cards and website-only browser warnings
- Local Helper settings for proxy/browser-open behavior
- assisted-fill command creators that create user-scoped helper commands only
- masked proxy-mode summaries on Dashboard and Workflow

Default Local Helper settings:

- require helper for proxied browser actions: true
- allow website-only normal browser open: true
- warn before opening without helper/proxy: true
- require confirmation before direct/no-proxy open: true
- show proxy mode before opening page: true
- enable assisted fill buttons: false

Planned helper capabilities:

- open Chrome locally with a selected proxy
- use per-account browser profiles
- show proxy/direct mode
- receive user-click browser actions
- later fill visible login/signup fields from selected records only after explicit user action

The helper will not bypass CAPTCHA, Cloudflare, robot checks, phone verification, email verification, security checks, or 2FA. It will not run hidden background actions, unattended mass actions, automatic account creation, or sensitive form submission without explicit user confirmation.

## Security Notes

- Sensitive account fields are encrypted at rest.
- Sensitive values are masked by default in list views.
- Copy actions log the field name only, never the copied value.
- Passwords, OTP secrets, OTP codes, proxy passwords, and encryption keys are not written to logs.
- Discord client secrets are used only server-side.
- Discord users are created with `subscription_status=inactive`; the optional emergency admin fallback is created as active.
- User-specific records are filtered by the logged-in user's internal `user_id`.
- `.env` is ignored and must not be committed.

## Browser Assist Placeholder

`src/browser-assist.js` is a disabled scaffold for future user-triggered form fill helpers. It does not automate website login, submit forms, create external accounts, bypass CAPTCHA, bypass Cloudflare, bypass security checks, or bypass 2FA.

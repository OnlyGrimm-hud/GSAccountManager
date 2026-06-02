# GS Account Manager

GS Account Manager is a Render-ready, server-rendered MVP for secure account storage and manual workflow tracking.

It is intentionally manual only. It does not automate third-party logins, submit forms, create external accounts, type into external websites, solve CAPTCHA, bypass checks, or route requests through stored proxies. Copy buttons and external links are provided for user-directed work.

## Stack

- Node.js + Express
- EJS templates
- PostgreSQL with `pg`
- `express-session` with PostgreSQL session storage
- AES-256-GCM field encryption using `ENCRYPTION_KEY`
- Built-in TOTP generation for saved OTP secrets
- Custom CSRF token for forms

## Local Setup

1. Install Node.js 20 or newer.
2. Create a PostgreSQL database.
3. Copy `.env.example` to `.env`.
4. Fill in the required environment variables.
5. Install dependencies:

```bash
npm install
```

6. Start the app:

```bash
npm start
```

The app listens on `process.env.PORT` and exposes `/healthz`.

## Required Environment Variables

- `DATABASE_URL`: PostgreSQL connection string.
- `ENCRYPTION_KEY`: 32 random bytes encoded as base64 or 64-character hex.
- `SESSION_SECRET`: long random string for session signing.
- `ADMIN_USERNAME`: temporary local admin username.
- `ADMIN_PASSWORD`: temporary local admin password.
- `NODE_ENV`: use `production` on Render.
- `COOKIE_SECURE`: use `true` on Render.
- `AUTO_MIGRATE`: defaults to `true`.

Generate an encryption key:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

## Render Setup

1. Create a new Render PostgreSQL database.
2. Copy its internal database URL.
3. Create a Render Web Service from this repository.
4. Use these service settings:

- Runtime: Node
- Build Command: `npm install`
- Start Command: `npm start`
- Health Check Path: `/healthz`
- Environment: `NODE_ENV=production`
- Add `DATABASE_URL` from Render Postgres.
- Add `ENCRYPTION_KEY`, `SESSION_SECRET`, `ADMIN_USERNAME`, and `ADMIN_PASSWORD`.
- Set `COOKIE_SECURE=true`.

Do not deploy until you have generated real secrets and chosen a strong admin password.

## TXT Import Formats

One account per line:

- `USERNAME:PASSWORD`
- `USERNAME:PASSWORD:OTP_KEY`
- `USERNAME:PASSWORD:BANK_PIN:OTP_KEY`
- `USERNAME:PASSWORD:BANK_PIN:OTP_KEY:RECOVERY_EMAIL:RECOVERY_EMAIL_PASSWORD`

Duplicate handling defaults to skipping duplicate usernames, with an update option on the import page.

## TXT Export Formats

- `USERNAME:PASSWORD`
- `USERNAME:PASSWORD:OTP_KEY`
- `USERNAME:PASSWORD:BANK_PIN:OTP_KEY`
- `TARGET_EMAIL:JAGEX_PASSWORD`
- `TARGET_EMAIL:JAGEX_PASSWORD:DISPLAY_NAME`

Masked exports are the default. Full export requires explicit confirmation. Delete-after-export is review-only and never deletes automatically.

## Database

Schema lives in `db/init.sql`. The app runs it at startup by default when `AUTO_MIGRATE` is not `false`.

Tables:

- `accounts`
- `proxies`
- `activity_logs`
- `settings`
- session table created by `connect-pg-simple`

## Smoke Test

```bash
npm run smoke
```

The smoke test checks import parsing and TOTP generation without connecting to a real database.

## Future Discord OAuth

Placeholders are included:

- `DISCORD_CLIENT_ID`
- `DISCORD_CLIENT_SECRET`
- `DISCORD_REDIRECT_URI`

Future setup tasks:

- Register a Discord application.
- Add the Render callback URL to Discord OAuth redirects.
- Add Passport or a small OAuth client flow.
- Map Discord user IDs to admin access rules.
- Replace or supplement the temporary local admin login.

## Future Cloudflare Custom Domain

For `gsaccountmanager.com`:

1. Add the domain to Cloudflare.
2. Point DNS to Render using Render's custom domain instructions.
3. Enable HTTPS on Render.
4. Keep Cloudflare SSL mode compatible with Render's certificate.
5. Add security headers and a stricter CSP before wider use.

## Security Notes

- Sensitive values are encrypted at rest.
- Sensitive values are masked in lists by default.
- Passwords, OTP secrets, generated OTP codes, proxy passwords, and encryption keys are not written to activity logs.
- Keep `.env` private and never commit real secrets.

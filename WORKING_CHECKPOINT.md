# GS Account Manager Working Checkpoint

Checkpoint version: v0.1.0

This checkpoint documents the currently deployed, working state of GS Account Manager before adding new features.

## Current Project Structure

```text
GSAccountManager/
  db/
    init.sql
  public/
    css/app.css
    js/app.js
  scripts/
    smoke.js
  src/
    activity.js
    app-constants.js
    config.js
    crypto-fields.js
    db.js
    generators.js
    otp.js
    parsers.js
    security.js
    server.js
  views/
    accounts/form.ejs
    accounts/index.ejs
    partials/foot.ejs
    partials/head.ejs
    dashboard.ejs
    error.ejs
    imports-exports.ejs
    login.ejs
    logs.ejs
    proxies.ejs
    settings.ejs
    workflow.ejs
  .env.example
  .gitignore
  package.json
  README.md
  render.yaml
  WORKING_CHECKPOINT.md
```

## Current Render Settings

- Service name: GSAccountManager
- Service type: Node web service
- Repository: `https://github.com/OnlyGrimm-hud/GSAccountManager`
- Branch: `main`
- Auto deploy: enabled for new commits
- Root Directory: blank / repository root
- Build Command: `npm install`
- Start Command: `npm start`
- Health Check Path: `/healthz`

The app exposes `/healthz` and returns `200 OK`. If the Render dashboard still shows a blank health check path, set it manually to `/healthz`.

## Required Environment Variables

- `DATABASE_URL`: Render PostgreSQL internal connection string.
- `ENCRYPTION_KEY`: must decode to exactly 32 bytes. Use base64 from 32 random bytes or a 64-character hex string.
- `SESSION_SECRET`: long random session secret.
- `ADMIN_USERNAME`: admin username.
- `ADMIN_PASSWORD`: admin password.
- `NODE_ENV=production`
- `COOKIE_SECURE=true`
- `AUTO_MIGRATE=true`

Optional:

- `ADMIN_PASSWORD_HASH`: optional `scrypt:salt:hexhash` admin password hash.
- `APP_NAME=GS Account Manager`
- `DISCORD_CLIENT_ID`
- `DISCORD_CLIENT_SECRET`
- `DISCORD_REDIRECT_URI`

## Database Requirement

PostgreSQL is required before launch. The app uses PostgreSQL for:

- account storage
- proxy storage
- settings
- activity logs
- session storage

`db/init.sql` is idempotent and runs on startup when `AUTO_MIGRATE=true`. A database reset is not expected for this checkpoint.

## Current Login Flow

- `/login` is public.
- Admin credentials are read from environment variables.
- Login attempts are rate limited.
- Successful login stores an authenticated session.
- Forms use CSRF protection.
- Protected pages redirect to `/login` when no authenticated session exists.
- `/logout` destroys the session and redirects to `/login`.

## Current Working Pages

- Dashboard: selected account workflow, empty state, progress cards, quick copy actions, safe open-page links.
- Accounts: list, filters, add/edit account page, masked secrets with reveal/copy controls.
- Imports / Exports: TXT import preview, duplicate/invalid row review, export preview, safe post-export actions.
- Proxies: proxy storage, import, assignment counts, auto-assign request, private proxy credentials.
- Settings: app settings, URL settings, Render checklist, production checklist, app version.
- Logs: activity log list with filters.
- Upgrade Workflow: manual progress and status controls.
- Health: `/healthz`.

## Known Unfinished Items

- Discord OAuth is only a placeholder and is not active.
- Render MCP cannot update every dashboard setting; confirm the Render health check field is `/healthz` in the dashboard.
- Logged-in UI flows still need manual browser testing with real admin credentials after each deploy.
- No automated end-to-end browser test suite exists yet.
- `ADMIN_PASSWORD_HASH` is optional; the current required path still supports env-based `ADMIN_PASSWORD`.

## Manual-Workflow-Only Boundaries

Allowed:

- store account fields securely
- import and export local account lists
- generate local passwords
- generate/display OTP codes from stored OTP secrets
- copy fields only when the admin clicks a button
- open configured external pages in a new tab
- track manual workflow progress and status
- mark accounts as upgraded, skipped, blocked, exported, or archived

Not allowed:

- no automatic website login
- no automatic form submission
- no automatic Outlook/Microsoft account creation
- no CAPTCHA bypass
- no security or verification bypass
- no unattended background account actions


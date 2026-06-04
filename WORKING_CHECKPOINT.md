# GS Account Manager Working Checkpoint

Checkpoint version: v0.1.0

This checkpoint documents the currently deployed, working state of GS Account Manager before adding new features.

## Current Project Structure

```text
GSAccountManager/
  companion/
    package.json
    README.md
    src/main.js
    src/browser-automator.js
    src/preload.js
    src/renderer/index.html
    src/renderer/renderer.js
    src/renderer/style.css
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
    browser-assist.js
    config.js
    crypto-fields.js
    db.js
    discord-auth.js
    generators.js
    otp.js
    osrs-stats.js
    parsers.js
    security.js
    server.js
  views/
    admin/dashboard.ejs
    admin/downloads.ejs
    admin/logs.ejs
    admin/subscriptions.ejs
    admin/system.ejs
    admin/users.ejs
    accounts/form.ejs
    accounts/index.ejs
    workflows/form.ejs
    workflows/index.ejs
    workflows/run.ejs
    partials/foot.ejs
    partials/head.ejs
    clients.ejs
    compatibility.ejs
    companion.ejs
    dashboard.ejs
    downloads.ejs
    error.ejs
    helper-download.ejs
    instance.ejs
    instances.ejs
    locked.ejs
    login.ejs
    local-jobs.ejs
    logs.ejs
    proxies.ejs
    setup.ejs
    setup-guide.ejs
    settings.ejs
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

The app exposes `/healthz` and returns `200 OK` when the database is reachable.

## Required Environment Variables

- `DATABASE_URL`: Render PostgreSQL internal connection string.
- `ENCRYPTION_KEY`: must decode to exactly 32 bytes. Use base64 from 32 random bytes or a 64-character hex string.
- `SESSION_SECRET`: long random session secret.
- `DISCORD_CLIENT_ID`: Discord OAuth application client ID.
- `DISCORD_CLIENT_SECRET`: Discord OAuth application client secret.
- `DISCORD_CALLBACK_URL`: deployed Discord callback URL.
- `APP_BASE_URL`: deployed base URL, for example `https://gsaccountmanager.com`.
- `ADMIN_DISCORD_IDS`: comma-separated Discord IDs that should automatically receive admin access.
- `AUTH_MODE=discord`
- `NODE_ENV=production`
- `COOKIE_SECURE=true`
- `AUTO_MIGRATE=true`

Optional:

- `ADMIN_USERNAME`: emergency fallback username.
- `ADMIN_PASSWORD`: emergency fallback password.
- `ADMIN_PASSWORD_HASH`: optional `scrypt:salt:hexhash` admin password hash.
- `APP_NAME=GS Account Manager`

## Database Requirement

PostgreSQL is required before launch. The app uses PostgreSQL for:

- account storage
- proxy storage
- settings
- activity logs
- session storage
- subscription tiers and daily browser task usage
- downloads/setup cards
- payment settings placeholders

`db/init.sql` is idempotent and runs on startup when `AUTO_MIGRATE=true`. A database reset is not expected for this checkpoint.

Current subscription/download foundation tables:

- `subscription_tiers`
- `browser_task_usage`
- `download_items`
- `payment_settings`

Current subscription columns on `users`:

- `subscription_tier_id`
- `subscription_started_at`
- `subscription_expires_at`
- `manually_paid_at`
- `payment_method`
- `payment_note`

If old records have no `user_id`, they are assigned to the first admin user when one exists and no prior data owner exists yet. The app writes a setup warning to activity logs when this happens. If no admin exists yet, old unowned rows remain hidden from normal users until an admin is created.

## Current Login Flow

- `/login` is public.
- Discord OAuth is the primary login path.
- Emergency admin credentials are optional fallback-only environment variables.
- New Discord users default to `subscription_status=inactive`; the emergency admin fallback is `active`.
- Roles are `user`, `staff`, and `admin`.
- Subscription statuses are `inactive`, `active`, `trial`, `expired`, and `banned`.
- Discord IDs in `ADMIN_DISCORD_IDS` are automatically admin and active.
- Inactive, expired, and banned users only see the locked access page.
- Active and trial users can access the dashboard.
- Admin users bypass subscription gating.
- Login attempts are rate limited.
- Successful login stores an authenticated session.
- Sessions store the internal `user_id` and Discord identity display data.
- Forms use CSRF protection.
- Protected pages redirect to `/login` when no authenticated session exists.
- `/logout` destroys the session and redirects to `/login`.

## Current Working Pages

- Dashboard: account metrics, empty state, progress cards, quick copy actions, safe open-page links.
- Accounts: list, filters, add/edit account page, full owner-visible non-secret account labels, and encrypted secrets with reveal/copy controls.
- Accounts Import / Export: built into the Accounts page.
- Proxies: proxy storage, proxy import/export, assignment counts, auto-assign request, private proxy credentials.
- Browser Automator: automation definitions, run history, local app job handoff, and visible Playwright execution through GS Browser Automator.
- Setup Wizard: automation-first onboarding for GS Agent one-time pairing, imports, launch profiles, jobs, and live sessions.
- Setup Guide: local automation setup docs and safe operating boundaries.
- Compatibility: matrix for GS Agent, GS Browser Automator, RuneLite, Jagex Launcher, Official Client, DreamBot, and custom local clients.
- Launch Profiles: local client launch profile foundation.
- Live Sessions: user-scoped detected client sessions, account matching, public OSRS stats sync, and status summaries.
- Local Jobs: local app queue visibility.
- Client Monitor: pairing-code generation, connected device management, heartbeat/job/client status foundation, and clear Working/Placeholder/Coming Soon status.
- Downloads: GS Agent packaging status, browser runtime notes, setup guide, and configurable client setup links.
- Settings: user settings, URL settings, local app settings, Render checklist, production checklist, app version.
- Logs: activity log list with filters.
- Admin: dashboard, users, subscriptions, downloads manager, platform logs, and system health.
- Health: `/healthz`.

## Known Unfinished Items

- Admin role enforcement is active for `/admin`, `/admin/users`, `/admin/logs`, `/admin/system`, and `/admin/subscriptions`.
- Subscription gating is active for inactive, expired, and banned Discord users.
- Render MCP cannot update every dashboard setting; confirm the Render health check field is `/healthz` in the dashboard.
- Logged-in UI flows still need manual browser testing with real admin credentials after each deploy.
- No automated end-to-end browser test suite exists yet.
- Emergency admin fallback is optional and creates its own isolated workspace.
- Browser Automator job records, GS Agent handoff, visible Chromium execution, owner credential field fill, safe clicks, screenshots, and manual pauses are implemented in GS Browser Automator.
- Windows GS Agent packaging is scaffolded but not built yet.
- GS Agent one-time pairing is implemented with a stable local install ID. Re-pairing the same install refreshes the same device slot; a different install/computer counts against the user's subscription device limit.
- Live snapshots are opt-in and Browser Automator screenshot steps require local user confirmation before upload.
- Browser proxy launch support is not production-enabled yet.
- Proxy testing is a Coming Soon placeholder.
- Starter/Standard/Pro/Admin tier records and manual admin assignment are implemented.
- Real subscription payment processing is not implemented.
- LTC, BTC, and ETH payment settings are placeholders only.

## Safe Automation Boundaries

Allowed:

- store account fields securely
- import and export local account lists
- generate local passwords
- generate/display OTP codes from stored OTP secrets
- copy fields only when the user clicks a button
- open configured external pages in a new tab
- queue visible local browser automation jobs through GS Browser Automator
- fill visible browser fields, including the owner's saved login/email/password fields, only after user action through GS Browser Automator
- pause for CAPTCHA, 2FA, email verification, phone verification, Cloudflare, and security checks
- launch configured local clients through user-triggered GS Agent jobs
- detect local windows/process names without injection or memory reads
- track manual workflow progress and status
- mark accounts as upgraded, skipped, blocked, exported, or archived

Not allowed:

- no hidden/background browser automation
- no unattended automatic website login
- no auto-submit of sensitive forms
- no automatic Outlook/Microsoft account creation
- no CAPTCHA bypass
- no security or verification bypass
- no 2FA, email verification, or phone verification bypass
- no client injection
- no game memory reads
- no gameplay bot scripts
- no session, cookie, or token theft
- no unattended background account actions

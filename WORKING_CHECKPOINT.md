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
    src/preload.js
    src/renderer/index.html
    src/renderer/renderer.js
    src/renderer/style.css
  db/
    init.sql
  local-helper/
    HELPER_PLAN.md
    README.md
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
    parsers.js
    security.js
    server.js
  views/
    admin/dashboard.ejs
    admin/users.ejs
    accounts/form.ejs
    accounts/index.ejs
    partials/foot.ejs
    partials/head.ejs
    dashboard.ejs
    downloads.ejs
    error.ejs
    helper-download.ejs
    imports-exports.ejs
    local-helper.ejs
    locked.ejs
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
- Health Check Path: dashboard currently reports blank; target value is `/healthz`

The app exposes `/healthz` and returns `200 OK`. If the Render dashboard still shows a blank health check path, set it manually to `/healthz`.

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

`db/init.sql` is idempotent and runs on startup when `AUTO_MIGRATE=true`. A database reset is not expected for this checkpoint.

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

- Dashboard: selected account workflow, empty state, progress cards, quick copy actions, safe open-page links.
- Accounts: list, filters, add/edit account page, masked secrets with reveal/copy controls.
- Accounts Import / Export: TXT import preview, duplicate/invalid row review, selected-account export controls, and safe post-export actions.
- Proxies: proxy storage, import, assignment counts, auto-assign request, private proxy credentials.
- Settings: app settings, URL settings, Render checklist, production checklist, app version.
- Logs: activity log list with filters.
- Workflow: manual progress and status controls.
- Companion: companion status, pairing-code generation, download placeholder, setup instructions, API placeholders, and safety boundaries.
- Downloads: Windows companion download placeholder and setup instructions.
- Admin Users: admin-only Discord user list, role controls, subscription controls, and disable via banned status.
- Health: `/healthz`.

## Known Unfinished Items

- Admin role enforcement is active for `/admin/users`.
- Subscription gating is active for inactive, expired, and banned Discord users.
- Render MCP cannot update every dashboard setting; confirm the Render health check field is `/healthz` in the dashboard.
- Logged-in UI flows still need manual browser testing with real admin credentials after each deploy.
- No automated end-to-end browser test suite exists yet.
- Emergency admin fallback is optional and creates its own isolated workspace.
- Browser assist is a disabled placeholder for future user-triggered form filling only.
- Windows Companion packaging is scaffolded but not built yet.
- Assisted fill buttons remain disabled by default until the helper app exists.

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

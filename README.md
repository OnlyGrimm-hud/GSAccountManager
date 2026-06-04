# GS Account Manager

GS Account Manager is a Render-ready Node/Express app for Discord-authenticated account storage, proxy storage, admin management, subscription gating, and a safe GS Agent foundation.

The product is intentionally manual-workflow-only. It can fill the logged-in owner's stored login, email, and password fields into visible browser jobs when the user starts that job, but it does not solve or bypass CAPTCHA, 2FA, email verification, phone verification, security checks, Cloudflare checks, or account creation protections. Browser and local app work must stay visible, user-triggered, and safe.

## Current Project Structure

```text
GSAccountManager/
  package.json                 Web app scripts and dependencies
  render.yaml                  Render blueprint reference
  db/init.sql                  Non-destructive PostgreSQL schema/migrations
  src/                         Express app, auth, config, encryption, parsers
  views/                       EJS pages and partials
  public/css/app.css           Web app styling
  public/js/app.js             Browser-side modal/import helpers
  scripts/smoke.js             Local smoke checks
  companion/                   Electron GS Agent app
  WORKING_CHECKPOINT.md        Stable deployment checkpoint notes
```

## Render Settings

Use these settings for the GitHub repository root:

- Root Directory: blank
- Build Command: `npm install`
- Start Command: `npm start`
- Health Check Path: `/healthz`

The app listens on Render's `PORT` environment variable.

## Required Environment Variables

- `DATABASE_URL`
- `ENCRYPTION_KEY`
- `SESSION_SECRET`
- `DISCORD_CLIENT_ID`
- `DISCORD_CLIENT_SECRET`
- `DISCORD_CALLBACK_URL`
- `APP_BASE_URL`
- `AUTH_MODE=discord`
- `ADMIN_DISCORD_IDS`
- `NODE_ENV=production`
- `COOKIE_SECURE=true`

Optional:

- `AUTO_MIGRATE=true`
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `ADMIN_PASSWORD_HASH`
- `APP_NAME=GS Account Manager`

`ENCRYPTION_KEY` must decode to exactly 32 bytes. Use a 32-byte base64 key or a 64-character hex key. Do not change it after real encrypted data exists.

Discord redirect URLs:

- `https://gsaccountmanager.com/auth/discord/callback`
- `http://localhost:3000/auth/discord/callback`

## What Works Now

- Discord OAuth login with `identify` and `email` scopes.
- Optional emergency admin username/password fallback.
- Admin promotion and active access through `ADMIN_DISCORD_IDS`.
- User-owned accounts, proxies, settings, logs, automations, connected devices, local jobs, live sessions, and stats.
- Subscription gating for `inactive`, `expired`, and `banned` users.
- Admin dashboard, user management, subscription controls, downloads manager, platform logs, and system health under `/admin`.
- Account import/export on the Accounts page.
- Proxy import/export on the Proxies page.
- Encrypted sensitive account and proxy fields.
- Owner-only reveal and copy controls for sensitive account values on list/detail views.
- Copy/reveal endpoints that return sensitive fields only on user action and only for the logged-in record owner.
- `/healthz` public health check.
- Browser Automator definitions, job records, job events, local job queue foundation, and visible Playwright execution in GS Browser Automator.
- Browser Automator supports `open_url`, `wait_for_selector`, owner credential `fill_field`, `click`, `screenshot`, `pause_for_user`, `wait_for_user_continue`, `mark_complete`, `fail`, and `note` steps.
- GS Browser Automator uses Playwright Chromium when installed and falls back to system Microsoft Edge or Chrome when the Playwright browser runtime is not installed yet.
- Automation-first setup wizard at `/setup`.
- Local automation setup guide at `/setup-guide`.
- Compatibility matrix at `/compatibility` for GS Agent, GS Browser Automator, RuneLite, Jagex Launcher, Official Client, DreamBot, and custom local clients.
- GS Agent pairing codes, connected device records, heartbeats, revoke/rename controls, and token-authenticated local app APIs.
- One-time GS Agent pairing: a stable local install ID lets the same PC refresh its device token without consuming another subscription device slot.
- GS Agent app with pairing, heartbeat, job polling, opt-in client detection, and local status reporting.
- Launch Profiles and Live Sessions pages for user-scoped launch profiles, detected sessions, matching, and public OSRS hiscore stats sync.
- Downloads page with GS Agent, browser runtime, setup guide, and configurable third-party client setup cards.
- Admin Downloads Manager at `/admin/downloads`.
- Subscription tier foundation with Starter, Standard, Pro, and Admin/Owner tiers.
- Admin subscription assignment at `/admin/subscriptions`.
- Crypto payment placeholders for LTC, BTC, and ETH. No real payment verification is implemented.
- Logs with user scoping and admin high-level visibility.

## Placeholders And Coming Soon

- Windows GS Agent packaged download is still a packaging placeholder unless `companion/dist/GS Agent Setup.exe` exists. The app also supports `GS Local App Setup.exe` and the previous companion installer filename as fallbacks.
- Browser proxy launch is not production-enabled yet. Browser jobs currently open a visible local Playwright-controlled browser without authenticated proxy launch.
- Live snapshots are opt-in and Browser Automator screenshot steps require local user confirmation before upload.
- Proxy testing is a Coming Soon placeholder.
- Subscription payment processing is not implemented. Admins can assign tiers/status manually.
- Advanced process detection is limited to safe process/window title detection. There is no memory reading, injection, session theft, or hidden automation.

## Database

`db/init.sql` contains idempotent, non-destructive schema setup. Normal deployment should not require wiping or dropping data.

Important tables and ownership:

- `users`
- `accounts`
- `proxies`
- `user_settings`
- `activity_logs`
- `audit_logs`
- `import_export_runs`
- `workflows`, `workflow_steps`, `workflow_runs`, `workflow_run_events`
- `companion_devices`, `companion_sessions`, `companion_jobs`, `companion_job_events`
- `client_profiles`, `client_instances`, `client_instance_events`
- `account_stats`
- `live_snapshots`
- `download_items`
- `subscription_tiers`
- `browser_task_usage`
- `payment_settings`

User-owned tables include `user_id` and queries should scope normal user access by the logged-in internal user ID.

If old account/proxy/log rows have no `user_id`, startup migration logic preserves the rows and assigns them only through the documented ownership migration path. Do not reset the database to upgrade.

## Admin Access

New Discord users default to `role=user` and `subscription_status=inactive`.

Any Discord ID in `ADMIN_DISCORD_IDS` becomes `role=admin` and `subscription_status=active` after login.

Manual SQL fallback:

```sql
UPDATE users
SET role = 'admin', subscription_status = 'active', updated_at = NOW()
WHERE discord_id = 'YOUR_DISCORD_ID';
```

Admins can edit role and subscription status at `/admin/users`.

## Local Development

Install web dependencies:

```bash
npm install
```

Run smoke checks:

```bash
npm run smoke
```

Start the web app:

```bash
npm start
```

Install GS Agent dependencies:

```bash
cd companion
npm install
npm start
```

## Cleanup Notes

The active UI surfaces are:

- Dashboard: workspace overview.
- Setup: onboarding wizard for paid local automation.
- Accounts: account storage, account import, account export, stats refresh.
- Proxies: proxy storage, proxy import, proxy export.
- Browser Automator: automation definitions, queued jobs, visible GS Browser Automator execution, manual pause handling, and safe event reporting.
- Launch Profiles: local client launch profile foundation.
- Live Sessions: detected local client sessions and account matching.
- Local Jobs: local app queue visibility.
- Client Monitor: pairing, devices, heartbeat/job/client status.
- Downloads: GS Agent packaging status, browser runtime notes, setup guide, and client setup links.
- Compatibility: clear matrix of working, partial, placeholder, and blocked automation support.
- Logs: safe user activity logs.
- Settings: user-specific settings.
- Admin: admin-only platform, user, subscription, downloads, logs, and system health management.

Legacy duplicate pages for imports/exports, local helper, and the old singular workflow screen are retired behind redirects.

## Next Development Priorities

1. Package and test the Windows GS Agent installer.
2. Add browser proxy launch support in GS Browser Automator.
3. Add production-quality live snapshot controls with clear opt-in behavior.
4. Expand safe client detection and matching without injection or memory reads.
5. Add real subscription/payment flow when ready.
6. Add deeper integration tests for user isolation, admin-only actions, and local automation jobs.

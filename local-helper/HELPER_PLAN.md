# GS Local Helper Plan

## Current Stage

The web app now has Local Helper pages, pairing-code storage, helper device tables, and helper command tables. The Windows helper binary is not implemented yet.

## Pairing Flow

1. User signs in to GS Account Manager with Discord.
2. User opens Local Helper page.
3. User generates a short-lived pairing code.
4. The server stores only a hash of the pairing code.
5. The Windows helper asks the user to paste the code.
6. The helper exchanges the code for a generated device token.
7. The server stores only a hash of the device token.
8. Future helper requests authenticate with the token and are scoped to the linked `user_id`.

Pairing codes expire after 10 minutes.

## Future Command Flow

Future helper commands should be created only from an explicit user click in the web app. Every command must include `user_id`, and any referenced `account_id` or `proxy_id` must be verified to belong to that same user.

Possible future command types:

- `open_chrome_with_proxy`
- `open_chrome_direct`
- `open_url`
- `open_email_signup`
- `open_email_login`
- `open_jagex_login`
- `open_jagex_upgrade`
- `fill_visible_login_form`
- `fill_visible_login_fields`
- `fill_visible_signup_form`
- `fill_visible_email_fields`
- `fill_visible_upgrade_fields`
- `copy_otp_code`
- `browser_back`
- `browser_forward`
- `close_browser`

## Required Safety Rules

- Do not bypass CAPTCHA, Cloudflare, robot checks, phone verification, email verification, security checks, or 2FA.
- Do not run hidden or unattended account actions.
- Do not submit sensitive forms unless the user explicitly confirms that action.
- Do not log passwords, OTP secrets, generated OTP codes, proxy passwords, Discord secrets, cookies, database URLs, or encryption keys.
- Keep all helper devices and commands scoped to one `user_id`.

## Not In Scope Yet

- Packaging a Windows installer.
- Playwright or Chrome automation implementation.
- Device-token exchange endpoint.
- Polling/WebSocket command channel.
- Actual browser-launch commands.

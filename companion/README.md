# GS Agent

Local Windows app for GS Account Manager. It currently ships as one install with two clear modules:

- **GS Agent** for client launching, client monitoring, pairing, heartbeat, and local status.
- **GS Browser Automator** for visible, user-triggered Playwright browser jobs.

The app pairs each PC once. The device token stays stored locally until the user revokes the device, clears local app data, or moves to another computer. Re-pairing the same install refreshes the same device slot; a different install/computer counts against the user's subscription device limit.

Current status:

- Electron shell
- pairing UI
- safe local app API pairing request
- stable local install ID for one-time pairing and same-install re-pairing
- local device token storage
- heartbeat support
- job polling and job status reporting
- visible Browser Automator execution through Playwright Chromium
- browser runtime fallback to system Microsoft Edge or Chrome when Playwright Chromium is not installed
- Browser Automator support for open_url, wait_for_selector, fill_field, click, screenshot, pause_for_user, wait_for_user_continue, mark_complete, fail, and note steps
- Windows process/window title detection using normal OS APIs
- client status reporting to GS Account Manager
- local-only launch profile storage
- visible user-triggered executable launch
- submit-like clicks are paused for manual user action
- CAPTCHA, MFA, security-check, email verification, and phone verification screens pause for manual user action
- selected-window screenshot upload is placeholder-only
- no CAPTCHA, MFA, security-check, or anti-abuse bypass
- no hidden automation
- no automatic sensitive form submission
- no process injection, memory reading, client hooks, or gameplay scripts

Current local-only automation behavior:

- Browser Automator opens a visible Chromium window
- isolated local profile
- account fields are fetched only during a user-approved job step
- user-owned login, email, password, and OTP-code fields can be filled into visible browser forms when the user starts/approves the job
- passwords, OTP codes, and other sensitive values are not written to logs
- OTP code fill requires explicit user confirmation
- screenshot steps require local opt-in and a user confirmation
- selected proxy display is noted, but proxy browser launch is not production-enabled yet

Planned local-only features:

- packaged Windows installer
- stronger selected-window screenshot controls
- browser proxy launch support
- richer pause/resume controls in the UI

Commands:

```bash
npm install
npm start
npm run build
npm run package
```

The packaged Windows artifact is planned as `GS Agent Setup.exe`.

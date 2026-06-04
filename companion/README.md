# GS Local App

Local Windows app skeleton for GS Account Manager.

Current status:

- Electron shell
- pairing UI
- safe local app API pairing request
- local device token storage
- heartbeat placeholder
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

The packaged Windows artifact is planned as `GS Local App Setup.exe`.

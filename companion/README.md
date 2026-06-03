# GS Account Manager Companion

Local Windows companion app skeleton for GS Account Manager.

Current status:

- Electron shell
- pairing UI
- safe companion API pairing request
- local device token storage
- heartbeat placeholder
- job polling and job status reporting placeholders
- Windows process/window title detection using normal OS APIs
- client status reporting to GS Account Manager
- local-only launch profile storage
- visible user-triggered executable launch
- no browser automation implementation yet
- selected-window screenshot upload is placeholder-only
- no CAPTCHA, MFA, security-check, or anti-abuse bypass
- no hidden automation
- no automatic sensitive form submission
- no process injection, memory reading, client hooks, or gameplay scripts

Planned local-only features:

- controlled Chromium window
- isolated local profile
- selected proxy display
- user-triggered field fill
- selected-window snapshots only when enabled by the user

Commands:

```bash
npm install
npm start
npm run build
npm run package
```

The packaged Windows artifact is planned as `GS Account Manager Companion Setup.exe`.

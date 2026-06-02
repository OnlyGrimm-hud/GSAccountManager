# GS Account Manager Companion

Local Windows companion app skeleton for GS Account Manager.

Current status:

- Electron shell
- pairing UI
- safe companion API pairing request
- local device token storage
- heartbeat placeholder
- job polling and job status reporting placeholders
- manual local status reporting placeholder
- no browser automation implementation yet
- no CAPTCHA, MFA, security-check, or anti-abuse bypass
- no hidden automation
- no automatic sensitive form submission

Planned local-only features:

- controlled Chromium window
- isolated local profile
- selected proxy display
- user-triggered field fill
- process/window status detection
- optional snapshots only when enabled by the user

Commands:

```bash
npm install
npm start
npm run build
npm run package
```

The packaged Windows artifact is planned as `GS Account Manager Companion Setup.exe`.

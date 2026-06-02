# GS Account Manager Companion

Local Windows companion app skeleton for GS Account Manager.

Current status:

- Electron shell
- pairing UI placeholder
- safe companion API pairing request
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
npm run package:win
```

The packaged Windows artifact is planned as `GSWorkFlowManager.exe`.

# GS Local Helper

This folder is a placeholder for the future Windows Local Helper app.

GS Account Manager runs as a hosted web app. A hosted website cannot directly launch a user's local Chrome with custom proxy flags, local browser profiles, or device-level browser settings. The Local Helper will run on the user's Windows PC and connect to the user's GS Account Manager account.

Planned responsibilities:

- connect to GS Account Manager with a short-lived pairing code
- store only local helper configuration needed on the user's PC
- open Chrome locally with selected proxy settings
- use per-account local browser profiles
- receive user-click assisted browser actions
- later fill visible forms from selected account records only after explicit user action

Safety boundaries:

- no CAPTCHA bypass
- no Cloudflare or security-check bypass
- no phone or email verification bypass
- no hidden background account actions
- no unattended mass actions
- no automatic account creation
- no sensitive form submission without explicit user confirmation
- no logging of passwords, OTP secrets, OTP codes, tokens, cookies, database URLs, or encryption keys

The helper app itself is not built yet. This stage only adds web-side support and product structure.

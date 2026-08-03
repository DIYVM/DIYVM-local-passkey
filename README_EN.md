<div align="center">
  <img src="./extension/src/logo.png" width="112" height="112" alt="DIYVM Local Vault">
  <h1>DIYVM Local Vault</h1>
  <p>A password and passkey manager that runs entirely inside Chrome.</p>
  <p>
    <img src="https://img.shields.io/badge/version-1.0.0-2458d3?style=flat-square" alt="Version 1.0.0">
    <img src="https://img.shields.io/badge/Manifest-V3-34a853?style=flat-square" alt="Manifest V3">
    <img src="https://img.shields.io/badge/license-Apache--2.0-f59e0b?style=flat-square" alt="Apache-2.0">
  </p>
  <p>
    <a href="./README.md">中文</a> ·
    <a href="./CHANGELOG.md">Changelog</a> ·
    <a href="./docs/privacy-policy.md">Privacy Policy</a> ·
    <a href="./docs/security-boundary.md">Security Boundary</a>
  </p>
</div>

## Overview

DIYVM Local Vault `1.0.0` expands the original Amazon local-passkey extension into a
local password and passkey vault. It requires no account or cloud service. Passwords,
passkey private keys, and audit events are encrypted before they are stored locally.

An existing `0.4.x` vault migrates its key-derivation metadata after the first successful
unlock. Existing passkeys do not need to be recreated.

## Features

- One encrypted vault for passwords and ES256 passkeys.
- Passkey creation and sign-in on the major Amazon marketplaces worldwide.
- User-initiated password matching and filling for the current page, without form submission.
- Optional persistent autofill that the user grants one HTTPS origin at a time.
- Add, edit, search, favorite, tag, annotate, rename, trash, restore, and permanently delete.
- Configurable password generator and local weak, reused, and stale-password checks.
- Automatic locking after 5, 15, 30, or 60 minutes.
- Encrypted backup, structural verification, full restore, and master-password change.
- Encrypted local audit history that never contains plaintext passwords.

## Security model

- New vaults use Argon2id (19 MiB, 2 iterations, parallelism 1) to derive a key that
  wraps a random 256-bit Vault Key.
- Each password, passkey, and audit record is independently encrypted with AES-256-GCM.
- The master password is not stored. The unlocked Vault Key lives only in
  `chrome.storage.session` and is subject to automatic locking.
- Passwords match an exact HTTPS origin. The extension never clicks a sign-in button
  or submits a form.
- The passkey page bridge is limited to supported top-level Amazon pages and validates
  the browser-provided sender origin and RP ID.
- No remote JavaScript, Wasm, or configuration code is loaded.

See [Security Boundary](./docs/security-boundary.md) for the threat model and limitations.

## Permissions

| Permission | Purpose |
| --- | --- |
| `storage` | Stores non-secret settings and the temporary unlocked session |
| `activeTab` | Reads or fills the current login page after an explicit user click |
| `scripting` | Performs one-time capture/fill and registers scripts for user-approved sites |
| `alarms` | Locks the vault after the selected inactivity period |
| Required `amazon.com` hosts | Preserves the original Amazon US passkey workflow |
| Optional Amazon hosts | Requested only when the user enables a marketplace |
| Optional HTTPS hosts | Requested for one exact origin only when persistent autofill is enabled |

Click-to-fill does not need persistent site access. The `https://*/*` optional pattern only
allows Chrome to display a per-site permission prompt for the specific origin selected by
the user; the extension never requests all sites at once.

## Supported Amazon marketplaces

The US marketplace is enabled by default. Canada, Mexico, Brazil, the United Kingdom,
Germany, France, Italy, Spain, the Netherlands, Sweden, Poland, Belgium, Ireland, Türkiye,
Japan, India, Australia, Singapore, the United Arab Emirates, Saudi Arabia, Egypt, and
South Africa can be enabled individually, including their HTTPS subdomains.

## Build and test

Requires Node.js 20+ and Chrome 120+.

```bash
npm ci
npm run test:pure
```

Load `extension/dist/` as an unpacked extension from `chrome://extensions`. A store build
without source maps is generated with:

```bash
npm run build:store
```

## Version 1.0 limitations

- No cloud sync, shared vaults, payment cards, or identity-profile autofill.
- A software passkey is not isolated as strongly as a TPM, Secure Enclave, or hardware key.
- Once a password is filled, scripts belonging to that page may read the input value.
  Fill credentials only on trusted sites whose domain is correct.
- The project has automated tests and a code-level security review, but it does not claim
  an independent third-party security audit.
- A previously approved Chrome Web Store version and the `1.0.0` update are separate review
  submissions. Google must review the update after it is uploaded.

## Privacy

The extension has no analytics or advertising and does not sell or transmit user data.
Uninstalling it deletes Chrome-managed extension data. Exported backup files must be
deleted by the user. See the [Privacy Policy](./docs/privacy-policy.md).

## License

[Apache License 2.0](./LICENSE)

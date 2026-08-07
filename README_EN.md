<div align="center">
  <img src="./extension/src/logo.png" width="112" height="112" alt="DIYVM Local Passkey">
  <h1>DIYVM Local Passkey</h1>
  <p>A local-first password and passkey manager with optional backup to user-owned OSS.</p>
  <p>
    <img src="https://img.shields.io/badge/version-1.2.3-2458d3?style=flat-square" alt="Version 1.2.3">
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

DIYVM Local Passkey `1.2.3` is a local password and passkey vault for general websites.
It requires no DIYVM account or developer-operated
server. Passwords, passkey private keys, and audit events are encrypted before local
storage. Users may also manually upload the complete encrypted backup to their own
Alibaba Cloud OSS bucket.

An existing `0.4.x` vault migrates its key-derivation metadata after the first successful
unlock. Existing passkeys do not need to be recreated.

## Features

- One encrypted vault for passwords and ES256 passkeys.
- User-enabled passkey creation and sign-in for ordinary WebAuthn on all HTTPS sites,
  with no website access granted at installation.
- User-initiated password capture, matching, and filling on HTTP/HTTPS pages, without form submission.
- Prioritizes the active login dialog and supports same-origin iframes, open Shadow DOM, and multi-step sign-in.
- Optional persistent autofill that the user grants one HTTPS origin at a time.
- HTTP credentials support manual save and fill only, with confirmation before every fill.
- Add, edit, search, favorite, tag, annotate, rename, trash, restore, and permanently delete.
- Configurable password generator and local weak, reused, and stale-password checks.
- Automatic locking from 5 minutes to 24 hours; closing Chrome discards the session key.
- Optional keep-unlocked mode for the current Chrome session without storing the master password.
- A first-install guide offers one-click optional all-HTTPS Passkey access and can be skipped.
- Encrypted backup, structural verification, full restore, and master-password change.
- Optional manual encrypted backup to user-owned Alibaba Cloud OSS, without a DIYVM server.
- Encrypted local audit history that never contains plaintext passwords.

## Security model

- New vaults use Argon2id (19 MiB, 2 iterations, parallelism 1) to derive a key that
  wraps a random 256-bit Vault Key.
- Each password, passkey, and audit record is independently encrypted with AES-256-GCM.
- The master password is not stored. The unlocked Vault Key lives only in
  `chrome.storage.session` and is subject to automatic locking.
- Passwords match an exact HTTP/HTTPS origin; HTTP and HTTPS credentials never cross-match.
  The extension never clicks a sign-in button or submits a form, and warns before HTTP fill.
- The passkey page bridge runs only on authorized top-level HTTPS pages and validates
  the sender origin, RP ID, and public suffix. Unsupported or declined local operations
  fall back to the original Chrome/system authenticator.
- No remote JavaScript, Wasm, or configuration code is loaded.

See [Security Boundary](./docs/security-boundary.md) for the threat model and limitations.

## Permissions

| Permission | Purpose |
| --- | --- |
| `storage` | Stores non-secret settings and the temporary unlocked session |
| `activeTab` | Reads or fills the current login page after an explicit user click |
| `scripting` | Performs one-time capture/fill and registers scripts for user-approved sites |
| `alarms` | Locks the vault after the selected inactivity period |
| Optional HTTPS hosts | Requested when the user enables generic Passkey, one exact autofill origin, or a user-owned OSS bucket |

Click-to-fill does not need persistent site access. The `https://*/*` capability is optional
and is requested broadly only after the user explicitly enables Passkey on all HTTPS sites.
Autofill and OSS access otherwise remain scoped to the exact selected origin or bucket.

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

## Version 1.2.3 limitations

- No multi-device bidirectional sync, shared vaults, payment cards, or identity-profile autofill.
- A software passkey is not isolated as strongly as a TPM, Secure Enclave, or hardware key.
- Once a password is filled, scripts belonging to that page may read the input value.
  Fill credentials only on trusted sites whose domain is correct.
- The project has automated tests and a code-level security review, but it does not claim
  an independent third-party security audit.
- A previously approved Chrome Web Store version and the `1.2.3` update are separate review
  submissions. Google must review the update after it is uploaded.

## Privacy

The extension has no analytics or advertising, does not sell data, and sends no vault data
to DIYVM servers. Only after explicit opt-in is the complete encrypted backup sent to the
user-configured Alibaba Cloud OSS bucket. Uninstalling the extension does not delete backup
files from disk or OSS. See the [Privacy Policy](./docs/privacy-policy.md).

## License

[Apache License 2.0](./LICENSE)

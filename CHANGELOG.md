# Changelog

## 1.2.3 — 2026-08-07

### Added

- Added a first-install onboarding page that explains the local security model,
  vault creation, password filling, and optional all-HTTPS Passkey access.
- A user can enable generic Passkey support with one explicit click during
  onboarding or skip and enable it later from Settings.
- The onboarding page opens only for a fresh installation, never for updates.

## 1.2.2 — 2026-08-06

### Added

- Added an opt-in "keep unlocked for this Chrome session" mode.
- The preference is stored, but the master password is never stored. The
  unlocked Vault Key remains in `chrome.storage.session` and is cleared by
  manual locking, extension-data removal, or the end of the browser session.

## 1.2.1 — 2026-08-06

### Changed

- New and changed master passwords now require at least 8 Unicode characters.
- Existing vaults remain unlockable with their original password policy.
- Added 2-hour, 8-hour, and 24-hour auto-lock options. The unlocked Vault Key
  remains limited to Chrome session storage and is cleared when the browser
  session ends.

## 1.2.0 — 2026-08-06

### Changed

- Replaced the Amazon-specific passkey permission model with one generic, user-enabled
  all-HTTPS passkey mode.
- Removed install-time website access, Amazon marketplace settings, and static
  Amazon content-script injection.
- Reduced optional host declarations to `https://*/*`; exact HTTPS autofill and
  user-owned OSS permissions continue to be requested as runtime subsets.
- Legacy Amazon-region settings are ignored and legacy dynamically registered scripts
  are removed during the first access synchronization after updating.

## 1.1.2 — 2026-08-06

### Added

- Optional user-initiated Passkey support on all top-level HTTPS sites, with a separate
  Chrome host-permission prompt and per-ceremony local/system choice.
- Manual password capture, save, and fill on HTTP origins with an explicit warning before
  saving and every fill; persistent autofill remains HTTPS-only.

### Security

- Validates generic WebAuthn RP IDs against an offline public/private suffix list and falls
  back to Chrome/system for conditional UI, unsupported extensions, unsafe RP scopes,
  unavailable local vaults, and missing local credentials.
- Removes dynamic all-site bridge scripts and the broad HTTPS permission when the user turns
  off all-site Passkey mode.

## 1.1.1 — 2026-08-05

### Fixed

- Re-enabled the optional Amazon marketplace checkboxes after popup initialization while
  keeping the default `amazon.com` permission locked on.

## 1.1.0 — 2026-08-03

### Added

- Unified encrypted password and passkey vault.
- Manual password creation, editing, search, favorites, tags, notes, aliases, trash, restore,
  and permanent deletion.
- Cryptographically secure password generator and local weak, reused, and stale-password checks.
- User-initiated current-page capture and fill through `activeTab`, without automatic submission.
- Login-dialog targeting, open Shadow DOM discovery, same-origin iframe support, and username-first multi-step filling.
- Optional persistent autofill granted one exact HTTPS origin at a time.
- Optional support for 22 additional Amazon marketplaces, bringing the total to 23.
- Configurable 5, 15, 30, or 60 minute automatic locking.
- Encrypted local audit history.
- Backup structure verification and master-password change.
- Optional manual encrypted backup and restore through user-owned Alibaba Cloud OSS.

### Security

- New vaults use Argon2id to protect the random Vault Key.
- Existing PBKDF2 vaults migrate after a successful unlock without recreating credentials.
- Password filling requires an exact HTTPS Origin match.
- OSS AccessKey configuration is encrypted inside the vault; only the selected Bucket host
  receives a runtime permission.
- Store builds exclude source maps and continue to contain no remote code or Manifest `key`.

### Compatibility

- Existing `0.4.x` passkeys and version 1 encrypted backups remain readable.
- The Chrome Web Store update requires a new review because its permissions and data handling
  disclosures have expanded.

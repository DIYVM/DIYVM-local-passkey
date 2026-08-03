# Changelog

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

import { argon2idAsync } from "@noble/hashes/argon2.js";

import type {
  CredentialSummary,
  ExtensionErrorCode,
  PasswordAuditSummary,
  PasswordDetails,
  PasswordInput,
  PasswordSummary,
  OssConfigurationSummary,
  VaultSettings,
  VaultStatus
} from "./types";

import {
  IndexedDbVaultStore,
  VAULT_SCHEMA_VERSION,
  type EncryptedCredentialRecord,
  type VaultMetadataRecord
} from "./indexeddb-vault";
import {
  arrayBuffer,
  decodeBase64Url,
  encodeBase64Url,
  randomBytes
} from "./binary";
import {
  auditPasswords,
  normalizePasswordInput,
  normalizeTags,
  passwordStrength
} from "./password-model";
import {
  ChromeVaultSettingsStorage,
  MemoryVaultSettingsStorage,
  type VaultSettingsStorage,
  updateVaultSettings
} from "./vault-settings";
import {
  normalizeOssConfiguration,
  type OssConfiguration
} from "./oss-client";
import {
  isExistingMasterPassword,
  isNewMasterPassword
} from "./master-password";

const LEGACY_PBKDF2_ITERATIONS = 600_000;
const ARGON2_ITERATIONS = 2;
const ARGON2_MEMORY_KIB = 19 * 1024;
const ARGON2_PARALLELISM = 1;
const VAULT_KEY_BYTES = 32;
const WRAP_IV_BYTES = 12;
const RECORD_IV_BYTES = 12;
const VAULT_KEY_AAD = new TextEncoder().encode(
  "diyvm-local-passkey:vault-key:v1"
);
const RECORD_AAD_PREFIX = "diyvm-local-passkey:credential:v1:";
const SESSION_KEY = "pureVaultSession";
const MAX_PASSWORD_HISTORY = 10;
const AUDIT_LOG_ID = "DIYVM_AUDIT_LOG_V1";
const OSS_CONFIGURATION_ID = "DIYVM_OSS_CONFIG_V1";
const MAX_AUDIT_ENTRIES = 500;

export interface StoredSoftwareCredential {
  schemaVersion: 1;
  kind: "passkey";
  credentialId: string;
  rpId: string;
  userHandle: string;
  userName: string;
  displayName: string;
  privateKeyPkcs8: string;
  publicKeySpki: string;
  publicKeyCose: string;
  signCount: number;
  alias: string;
  favorite: boolean;
  tags: string[];
  createdAt: number;
  lastUsedAt: number | null;
  deletedAt: number | null;
}

export interface StoredPasswordCredential {
  schemaVersion: 1;
  kind: "password";
  credentialId: string;
  name: string;
  origin: string;
  username: string;
  password: string;
  notes: string;
  favorite: boolean;
  tags: string[];
  autoFill: boolean;
  passwordHistory: string[];
  createdAt: number;
  updatedAt: number;
  lastUsedAt: number | null;
  deletedAt: number | null;
}

export type AuditEventType =
  | "vault-created"
  | "vault-unlocked"
  | "vault-locked"
  | "master-password-changed"
  | "passkey-created"
  | "passkey-used"
  | "passkey-updated"
  | "password-created"
  | "password-used"
  | "password-updated"
  | "item-trashed"
  | "item-restored"
  | "item-deleted"
  | "backup-exported"
  | "backup-imported"
  | "oss-connected"
  | "oss-backup-uploaded"
  | "oss-disconnected";

export interface AuditEntry {
  id: string;
  type: AuditEventType;
  at: number;
  targetKind?: "passkey" | "password" | "vault";
  targetLabel?: string;
}

interface StoredAuditLog {
  schemaVersion: 1;
  kind: "audit-log";
  credentialId: typeof AUDIT_LOG_ID;
  entries: AuditEntry[];
  createdAt: number;
  updatedAt: number;
}

interface StoredOssConfiguration {
  schemaVersion: 1;
  kind: "oss-configuration";
  credentialId: typeof OSS_CONFIGURATION_ID;
  configuration: OssConfiguration;
  lastUploadedAt: number | null;
  lastEtag: string | null;
  createdAt: number;
  updatedAt: number;
}

type StoredVaultItem =
  | StoredSoftwareCredential
  | StoredPasswordCredential
  | StoredAuditLog
  | StoredOssConfiguration;

interface VaultSession {
  vaultKey: string;
  lastActivityAt: number;
  expiresAt: number;
}

export interface VaultSessionStorage {
  read(): Promise<VaultSession | undefined>;
  write(session: VaultSession): Promise<void>;
  clear(): Promise<void>;
}

export class ChromeVaultSessionStorage implements VaultSessionStorage {
  async read(): Promise<VaultSession | undefined> {
    const stored = await chrome.storage.session.get(SESSION_KEY);
    return isVaultSession(stored[SESSION_KEY])
      ? stored[SESSION_KEY]
      : undefined;
  }

  async write(session: VaultSession): Promise<void> {
    await chrome.storage.session.set({ [SESSION_KEY]: session });
  }

  async clear(): Promise<void> {
    await chrome.storage.session.remove(SESSION_KEY);
  }
}

export class MemoryVaultSessionStorage implements VaultSessionStorage {
  private session: VaultSession | undefined;

  async read(): Promise<VaultSession | undefined> {
    return this.session ? { ...this.session } : undefined;
  }

  async write(session: VaultSession): Promise<void> {
    this.session = { ...session };
  }

  async clear(): Promise<void> {
    this.session = undefined;
  }
}

export class PureExtensionError extends Error {
  constructor(
    readonly code: ExtensionErrorCode,
    message: string,
    options?: ErrorOptions
  ) {
    super(message, options);
    this.name = "PureExtensionError";
  }
}

export class PureVault {
  constructor(
    private readonly store: IndexedDbVaultStore,
    private readonly sessionStorage: VaultSessionStorage,
    private readonly now: () => number = Date.now,
    private readonly settingsStorage: VaultSettingsStorage =
      defaultSettingsStorage()
  ) {}

  async status(): Promise<VaultStatus & { credentialCount: number }> {
    const metadata = await this.store.readMetadata();
    const records = await this.store.listCredentials();
    const settings = await this.settingsStorage.read();
    if (!metadata) {
      await this.sessionStorage.clear();
      return {
        vaultState: "notInitialized",
        itemCount: records.length,
        credentialCount: records.length,
        passkeyCount: 0,
        passwordCount: 0,
        trashCount: 0,
        settings,
        passwordAudit: emptyPasswordAudit()
      };
    }

    const session = await this.readActiveSession();
    if (!session) {
      return {
        vaultState: "locked",
        itemCount: records.length,
        credentialCount: records.length,
        passkeyCount: 0,
        passwordCount: 0,
        trashCount: 0,
        settings,
        passwordAudit: emptyPasswordAudit()
      };
    }

    const items = await this.decryptAllItems(false);
    const passkeys = items.filter(isPasskey);
    const passwords = items.filter(isPassword);
    const audit = auditPasswords(passwords, this.now()).summary;
    return {
      vaultState: "unlocked",
      itemCount: passkeys.length + passwords.length,
      credentialCount: passkeys.length,
      passkeyCount: passkeys.filter((item) => item.deletedAt === null).length,
      passwordCount: passwords.filter((item) => item.deletedAt === null).length,
      trashCount: [...passkeys, ...passwords].filter(
        (item) => item.deletedAt !== null
      ).length,
      settings,
      passwordAudit: audit
    };
  }

  async initialize(masterPassword: string): Promise<void> {
    validateNewMasterPassword(masterPassword);
    if (await this.store.hasVault()) {
      throw new PureExtensionError(
        "INVALID_STATE",
        "本地凭据库已经创建"
      );
    }

    const salt = randomBytes(16);
    const vaultKeyBytes = randomBytes(VAULT_KEY_BYTES);
    const metadata = await createArgon2Metadata(
      masterPassword,
      vaultKeyBytes,
      salt,
      this.now(),
      this.now()
    );
    await this.store.writeMetadata(metadata);
    await this.writeSession(vaultKeyBytes);
    vaultKeyBytes.fill(0);
    await this.recordAudit("vault-created", "vault");
  }

  async unlock(masterPassword: string): Promise<void> {
    validateExistingMasterPassword(masterPassword);
    const metadata = await this.store.readMetadata();
    if (!metadata) {
      throw new PureExtensionError(
        "VAULT_NOT_INITIALIZED",
        "尚未创建本地凭据库"
      );
    }

    const vaultKeyBytes = await unwrapVaultKey(masterPassword, metadata);
    try {
      if (metadata.kdf.algorithm === "PBKDF2-SHA-256") {
        const migrated = await createArgon2Metadata(
          masterPassword,
          vaultKeyBytes,
          randomBytes(16),
          metadata.createdAt,
          this.now()
        );
        await this.store.writeMetadata(migrated);
      }
      await this.writeSession(vaultKeyBytes);
    } finally {
      vaultKeyBytes.fill(0);
    }
    await this.recordAudit("vault-unlocked", "vault");
  }

  async changeMasterPassword(
    currentPassword: string,
    newPassword: string
  ): Promise<void> {
    validateExistingMasterPassword(currentPassword);
    validateNewMasterPassword(newPassword);
    if (currentPassword === newPassword) {
      throw new PureExtensionError(
        "INVALID_PASSWORD",
        "新主密码不能与当前主密码相同"
      );
    }
    const metadata = await this.store.readMetadata();
    if (!metadata) {
      throw new PureExtensionError(
        "VAULT_NOT_INITIALIZED",
        "尚未创建本地凭据库"
      );
    }
    const vaultKeyBytes = await unwrapVaultKey(currentPassword, metadata);
    try {
      const updated = await createArgon2Metadata(
        newPassword,
        vaultKeyBytes,
        randomBytes(16),
        metadata.createdAt,
        this.now()
      );
      await this.store.writeMetadata(updated);
      await this.writeSession(vaultKeyBytes);
    } finally {
      vaultKeyBytes.fill(0);
    }
    await this.recordAudit("master-password-changed", "vault");
  }

  async lock(): Promise<void> {
    try {
      if (await this.readActiveSession()) {
        await this.recordAudit("vault-locked", "vault");
      }
    } catch {
      // Locking must still succeed if the audit record cannot be written.
    }
    await this.sessionStorage.clear();
  }

  async updateSettings(
    patch: Partial<VaultSettings>
  ): Promise<VaultSettings> {
    const settings = await updateVaultSettings(this.settingsStorage, patch);
    const session = await this.readActiveSession();
    if (session) {
      const rawKey = new Uint8Array(decodeBase64Url(
        session.vaultKey,
        VAULT_KEY_BYTES,
        VAULT_KEY_BYTES
      ));
      await this.writeSession(rawKey);
      rawKey.fill(0);
    }
    return settings;
  }

  async listCredentials(
    includeDeleted = false
  ): Promise<CredentialSummary[]> {
    const credentials = (await this.decryptAllItems()).filter(isPasskey);
    return credentials
      .filter((credential) => includeDeleted || credential.deletedAt === null)
      .map(toPasskeySummary)
      .sort((left, right) => {
        if (left.favorite !== right.favorite) {
          return left.favorite ? -1 : 1;
        }
        const site = left.rpId.localeCompare(right.rpId);
        return site !== 0
          ? site
          : (
              left.alias ??
              left.displayName ??
              left.userName ??
              ""
            ).localeCompare(
              right.alias ??
              right.displayName ??
              right.userName ??
              ""
            );
      });
  }

  async findCredentials(
    rpId: string,
    allowedCredentialIds?: ReadonlySet<string>
  ): Promise<StoredSoftwareCredential[]> {
    return (await this.decryptAllItems())
      .filter(isPasskey)
      .filter(
        (credential) =>
          credential.deletedAt === null &&
          credential.rpId === rpId &&
          (!allowedCredentialIds ||
            allowedCredentialIds.has(credential.credentialId))
      );
  }

  async readCredential(
    credentialId: string
  ): Promise<StoredSoftwareCredential | undefined> {
    const item = await this.readItem(credentialId);
    return item && isPasskey(item) ? item : undefined;
  }

  async saveCredential(
    credential: StoredSoftwareCredential
  ): Promise<void> {
    const normalized = normalizePasskey(credential);
    const key = await this.requireVaultKey();
    const existing = await this.store.readCredential(
      normalized.credentialId
    );
    if (existing) {
      throw new PureExtensionError(
        "INVALID_STATE",
        "凭据 ID 已经存在"
      );
    }
    await this.store.writeCredential(await encryptItem(key, normalized));
    await this.recordAudit(
      "passkey-created",
      "passkey",
      normalized.alias || normalized.rpId
    );
  }

  async updateCredential(
    credential: StoredSoftwareCredential
  ): Promise<void> {
    const normalized = normalizePasskey(credential);
    const key = await this.requireVaultKey();
    const existing = await this.store.readCredential(
      normalized.credentialId
    );
    if (!existing) {
      throw new PureExtensionError(
        "CREDENTIAL_NOT_FOUND",
        "找不到本地通行密钥"
      );
    }
    await this.store.writeCredential(await encryptItem(key, normalized));
    if (normalized.lastUsedAt !== null) {
      await this.recordAudit(
        "passkey-used",
        "passkey",
        normalized.alias || normalized.rpId
      );
    }
  }

  async updatePasskeyMetadata(
    credentialId: string,
    patch: {
      alias?: string;
      favorite?: boolean;
      tags?: string[];
    }
  ): Promise<void> {
    const credential = await this.readCredential(credentialId);
    if (!credential) {
      throw new PureExtensionError(
        "CREDENTIAL_NOT_FOUND",
        "找不到本地通行密钥"
      );
    }
    if (patch.alias !== undefined) {
      const alias = patch.alias.trim();
      if (alias.length > 128) {
        throw new TypeError("通行密钥别名不能超过 128 个字符");
      }
      credential.alias = alias;
    }
    if (patch.favorite !== undefined) {
      credential.favorite = patch.favorite;
    }
    if (patch.tags !== undefined) {
      credential.tags = normalizeTags(patch.tags);
    }
    const key = await this.requireVaultKey();
    await this.store.writeCredential(await encryptItem(key, credential));
    await this.recordAudit(
      "passkey-updated",
      "passkey",
      credential.alias || credential.rpId
    );
  }

  async deleteCredential(credentialId: string): Promise<boolean> {
    await this.requireVaultKey();
    return this.store.deleteCredential(credentialId);
  }

  async listPasswords(
    includeDeleted = false
  ): Promise<PasswordSummary[]> {
    const passwords = (await this.decryptAllItems()).filter(isPassword);
    const { reusedPasswords } = auditPasswords(passwords, this.now());
    return passwords
      .filter((item) => includeDeleted || item.deletedAt === null)
      .map((item) => toPasswordSummary(item, reusedPasswords.has(item.password)))
      .sort((left, right) => {
        if (left.favorite !== right.favorite) {
          return left.favorite ? -1 : 1;
        }
        return left.name.localeCompare(right.name);
      });
  }

  async readPassword(itemId: string): Promise<PasswordDetails | undefined> {
    const item = await this.readItem(itemId);
    return item && isPassword(item) ? toPasswordDetails(item) : undefined;
  }

  async savePassword(input: PasswordInput): Promise<PasswordDetails> {
    const normalized = normalizePasswordInput(input);
    const timestamp = this.now();
    const item: StoredPasswordCredential = {
      schemaVersion: 1,
      kind: "password",
      credentialId: encodeBase64Url(randomBytes(24)),
      name: normalized.name,
      origin: normalized.origin,
      username: normalized.username,
      password: normalized.password,
      notes: normalized.notes,
      favorite: normalized.favorite,
      tags: normalized.tags,
      autoFill: normalized.autoFill,
      passwordHistory: [],
      createdAt: timestamp,
      updatedAt: timestamp,
      lastUsedAt: null,
      deletedAt: null
    };
    const key = await this.requireVaultKey();
    await this.store.writeCredential(await encryptItem(key, item));
    await this.recordAudit(
      "password-created",
      "password",
      `${item.name} · ${new URL(item.origin).hostname}`
    );
    return toPasswordDetails(item);
  }

  async updatePassword(input: PasswordInput): Promise<PasswordDetails> {
    if (!input.itemId) {
      throw new TypeError("缺少要更新的密码条目 ID");
    }
    const normalized = normalizePasswordInput(input);
    const existing = await this.readItem(input.itemId);
    if (!existing || !isPassword(existing)) {
      throw new PureExtensionError(
        "CREDENTIAL_NOT_FOUND",
        "找不到密码条目"
      );
    }
    const history =
      normalized.password === existing.password
        ? existing.passwordHistory
        : [
            existing.password,
            ...existing.passwordHistory.filter(
              (password) => password !== existing.password
            )
          ].slice(0, MAX_PASSWORD_HISTORY);
    const updated: StoredPasswordCredential = {
      ...existing,
      name: normalized.name,
      origin: normalized.origin,
      username: normalized.username,
      password: normalized.password,
      notes: normalized.notes,
      favorite: normalized.favorite,
      tags: normalized.tags,
      autoFill: normalized.autoFill,
      passwordHistory: history,
      updatedAt: this.now()
    };
    const key = await this.requireVaultKey();
    await this.store.writeCredential(await encryptItem(key, updated));
    await this.recordAudit(
      "password-updated",
      "password",
      `${updated.name} · ${new URL(updated.origin).hostname}`
    );
    return toPasswordDetails(updated);
  }

  async usePassword(itemId: string): Promise<PasswordDetails> {
    const existing = await this.readItem(itemId);
    if (!existing || !isPassword(existing) || existing.deletedAt !== null) {
      throw new PureExtensionError(
        "CREDENTIAL_NOT_FOUND",
        "找不到可用的密码条目"
      );
    }
    existing.lastUsedAt = this.now();
    const key = await this.requireVaultKey();
    await this.store.writeCredential(await encryptItem(key, existing));
    await this.recordAudit(
      "password-used",
      "password",
      `${existing.name} · ${new URL(existing.origin).hostname}`
    );
    return toPasswordDetails(existing);
  }

  async passwordsForOrigin(origin: string): Promise<PasswordSummary[]> {
    return (await this.listPasswords()).filter((item) => item.origin === origin);
  }

  async passwordAudit(): Promise<PasswordAuditSummary> {
    const passwords = (await this.decryptAllItems()).filter(isPassword);
    return auditPasswords(passwords, this.now()).summary;
  }

  async trashItem(itemId: string): Promise<void> {
    const item = await this.readItem(itemId);
    if (!item || (!isPasskey(item) && !isPassword(item))) {
      throw new PureExtensionError(
        "CREDENTIAL_NOT_FOUND",
        "找不到凭据条目"
      );
    }
    item.deletedAt = this.now();
    const key = await this.requireVaultKey();
    await this.store.writeCredential(await encryptItem(key, item));
    await this.recordAudit(
      "item-trashed",
      item.kind,
      itemLabel(item)
    );
  }

  async restoreItem(itemId: string): Promise<void> {
    const item = await this.readItem(itemId);
    if (!item || (!isPasskey(item) && !isPassword(item))) {
      throw new PureExtensionError(
        "CREDENTIAL_NOT_FOUND",
        "找不到凭据条目"
      );
    }
    item.deletedAt = null;
    const key = await this.requireVaultKey();
    await this.store.writeCredential(await encryptItem(key, item));
    await this.recordAudit(
      "item-restored",
      item.kind,
      itemLabel(item)
    );
  }

  async deleteItemPermanently(itemId: string): Promise<boolean> {
    const item = await this.readItem(itemId);
    if (!item || (!isPasskey(item) && !isPassword(item))) {
      return false;
    }
    const deleted = await this.store.deleteCredential(itemId);
    if (deleted) {
      await this.recordAudit(
        "item-deleted",
        item.kind,
        itemLabel(item)
      );
    }
    return deleted;
  }

  async recordAudit(
    type: AuditEventType,
    targetKind?: "passkey" | "password" | "vault",
    targetLabel?: string
  ): Promise<void> {
    const key = await this.requireVaultKey(false);
    const record = await this.store.readCredential(AUDIT_LOG_ID);
    const timestamp = this.now();
    let log: StoredAuditLog;
    if (record) {
      const decrypted = await decryptItem(key, record);
      if (!isAuditLog(decrypted)) {
        throw new PureExtensionError(
          "INTERNAL_ERROR",
          "本地安全日志格式无效"
        );
      }
      log = decrypted;
    } else {
      log = {
        schemaVersion: 1,
        kind: "audit-log",
        credentialId: AUDIT_LOG_ID,
        entries: [],
        createdAt: timestamp,
        updatedAt: timestamp
      };
    }
    log.entries.push({
      id: encodeBase64Url(randomBytes(12)),
      type,
      at: timestamp,
      ...(targetKind ? { targetKind } : {}),
      ...(targetLabel ? { targetLabel: targetLabel.slice(0, 256) } : {})
    });
    log.entries = log.entries.slice(-MAX_AUDIT_ENTRIES);
    log.updatedAt = timestamp;
    await this.store.writeCredential(await encryptItem(key, log));
  }

  async listAuditEntries(): Promise<AuditEntry[]> {
    const item = await this.readItem(AUDIT_LOG_ID);
    return item && isAuditLog(item) ? [...item.entries].reverse() : [];
  }

  async readOssConfiguration(): Promise<OssConfiguration | undefined> {
    const item = await this.readItem(OSS_CONFIGURATION_ID);
    return item && isOssConfiguration(item)
      ? { ...item.configuration }
      : undefined;
  }

  async ossConfigurationSummary(): Promise<
    OssConfigurationSummary | undefined
  > {
    const item = await this.readItem(OSS_CONFIGURATION_ID);
    return item && isOssConfiguration(item)
      ? toOssConfigurationSummary(item)
      : undefined;
  }

  async saveOssConfiguration(
    configuration: OssConfiguration
  ): Promise<OssConfigurationSummary> {
    const normalized = normalizeOssConfiguration(configuration);
    const existing = await this.readItem(OSS_CONFIGURATION_ID);
    const timestamp = Math.max(
      this.now(),
      existing && isOssConfiguration(existing) ? existing.createdAt : 0
    );
    const preserveUpload =
      existing &&
      isOssConfiguration(existing) &&
      sameOssTarget(existing.configuration, normalized);
    const item: StoredOssConfiguration = {
      schemaVersion: 1,
      kind: "oss-configuration",
      credentialId: OSS_CONFIGURATION_ID,
      configuration: normalized,
      lastUploadedAt: preserveUpload ? existing.lastUploadedAt : null,
      lastEtag: preserveUpload ? existing.lastEtag : null,
      createdAt:
        existing && isOssConfiguration(existing)
          ? existing.createdAt
          : timestamp,
      updatedAt: timestamp
    };
    const key = await this.requireVaultKey();
    await this.store.writeCredential(await encryptItem(key, item));
    await this.recordAudit("oss-connected", "vault", normalized.bucket);
    return toOssConfigurationSummary(item);
  }

  async markOssBackupUploaded(
    uploadedAt: number,
    etag: string | null
  ): Promise<OssConfigurationSummary> {
    const item = await this.readItem(OSS_CONFIGURATION_ID);
    if (!item || !isOssConfiguration(item)) {
      throw new PureExtensionError(
        "INVALID_STATE",
        "尚未配置阿里云 OSS"
      );
    }
    if (
      !Number.isSafeInteger(uploadedAt) ||
      uploadedAt < 0
    ) {
      throw new TypeError("OSS 上传时间无效");
    }
    const timestamp = Math.max(uploadedAt, item.createdAt);
    item.lastUploadedAt = timestamp;
    item.lastEtag = normalizeNullableEtag(etag);
    item.updatedAt = timestamp;
    const key = await this.requireVaultKey();
    await this.store.writeCredential(await encryptItem(key, item));
    await this.recordAudit(
      "oss-backup-uploaded",
      "vault",
      item.configuration.bucket
    );
    return toOssConfigurationSummary(item);
  }

  async removeOssConfiguration(): Promise<boolean> {
    await this.requireVaultKey();
    const removed = await this.store.deleteCredential(OSS_CONFIGURATION_ID);
    if (removed) {
      await this.recordAudit("oss-disconnected", "vault");
    }
    return removed;
  }

  private async readItem(itemId: string): Promise<StoredVaultItem | undefined> {
    const key = await this.requireVaultKey();
    const record = await this.store.readCredential(itemId);
    return record ? await decryptItem(key, record) : undefined;
  }

  private async decryptAllItems(touch = true): Promise<StoredVaultItem[]> {
    const key = await this.requireVaultKey(touch);
    const records = await this.store.listCredentials();
    return Promise.all(records.map((record) => decryptItem(key, record)));
  }

  private async requireVaultKey(touch = true): Promise<CryptoKey> {
    const metadata = await this.store.readMetadata();
    if (!metadata) {
      throw new PureExtensionError(
        "VAULT_NOT_INITIALIZED",
        "尚未创建本地凭据库"
      );
    }
    const session = await this.readActiveSession();
    if (!session) {
      throw new PureExtensionError(
        "VAULT_LOCKED",
        "本地凭据库已锁定"
      );
    }
    const rawKey = new Uint8Array(decodeBase64Url(
      session.vaultKey,
      VAULT_KEY_BYTES,
      VAULT_KEY_BYTES
    ));
    if (touch) {
      await this.writeSession(rawKey);
    }
    const key = await crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
    rawKey.fill(0);
    return key;
  }

  private async readActiveSession(): Promise<VaultSession | undefined> {
    const session = await this.sessionStorage.read();
    if (!session) {
      return undefined;
    }
    try {
      decodeBase64Url(session.vaultKey, VAULT_KEY_BYTES, VAULT_KEY_BYTES);
      if (session.expiresAt <= this.now()) {
        await this.sessionStorage.clear();
        return undefined;
      }
      return session;
    } catch {
      await this.sessionStorage.clear();
      return undefined;
    }
  }

  private async writeSession(
    keyBytes: Uint8Array<ArrayBufferLike>
  ): Promise<void> {
    const settings = await this.settingsStorage.read();
    const timestamp = this.now();
    await this.sessionStorage.write({
      vaultKey: encodeBase64Url(keyBytes),
      lastActivityAt: timestamp,
      expiresAt: settings.rememberSession
        ? Number.MAX_SAFE_INTEGER
        : timestamp + settings.autoLockMinutes * 60 * 1_000
    });
  }
}

export async function openPureVault(): Promise<{
  vault: PureVault;
  store: IndexedDbVaultStore;
  close(): void;
}> {
  const store = await IndexedDbVaultStore.open();
  return {
    vault: new PureVault(
      store,
      new ChromeVaultSessionStorage(),
      Date.now,
      new ChromeVaultSettingsStorage()
    ),
    store,
    close: () => store.close()
  };
}

async function createArgon2Metadata(
  masterPassword: string,
  vaultKeyBytes: Uint8Array<ArrayBufferLike>,
  salt: Uint8Array<ArrayBufferLike>,
  createdAt: number,
  updatedAt: number
): Promise<VaultMetadataRecord> {
  const wrappingKey = await deriveArgon2WrappingKey(
    masterPassword,
    salt,
    ARGON2_ITERATIONS,
    ARGON2_MEMORY_KIB,
    ARGON2_PARALLELISM
  );
  const iv = randomBytes(WRAP_IV_BYTES);
  const wrappedVaultKey = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: VAULT_KEY_AAD
    },
    wrappingKey,
    arrayBuffer(vaultKeyBytes)
  );
  return {
    key: "vault",
    schemaVersion: VAULT_SCHEMA_VERSION,
    kdf: {
      algorithm: "ARGON2ID",
      iterations: ARGON2_ITERATIONS,
      memoryCostKib: ARGON2_MEMORY_KIB,
      parallelism: ARGON2_PARALLELISM,
      salt: arrayBuffer(salt)
    },
    wrappedVaultKey: {
      algorithm: "AES-256-GCM",
      iv: arrayBuffer(iv),
      ciphertext: wrappedVaultKey
    },
    createdAt,
    updatedAt
  };
}

async function unwrapVaultKey(
  masterPassword: string,
  metadata: VaultMetadataRecord
): Promise<Uint8Array<ArrayBuffer>> {
  let wrappingKey: CryptoKey;
  if (metadata.kdf.algorithm === "PBKDF2-SHA-256") {
    wrappingKey = await derivePbkdf2WrappingKey(
      masterPassword,
      metadata.kdf.salt,
      metadata.kdf.iterations
    );
  } else {
    wrappingKey = await deriveArgon2WrappingKey(
      masterPassword,
      new Uint8Array(metadata.kdf.salt),
      metadata.kdf.iterations,
      metadata.kdf.memoryCostKib ?? ARGON2_MEMORY_KIB,
      metadata.kdf.parallelism ?? ARGON2_PARALLELISM
    );
  }
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: metadata.wrappedVaultKey.iv,
        additionalData: VAULT_KEY_AAD
      },
      wrappingKey,
      metadata.wrappedVaultKey.ciphertext
    );
  } catch (error) {
    throw new PureExtensionError(
      "INVALID_PASSWORD",
      "主密码不正确",
      { cause: error }
    );
  }
  if (plaintext.byteLength !== VAULT_KEY_BYTES) {
    new Uint8Array(plaintext).fill(0);
    throw new PureExtensionError("INVALID_PASSWORD", "主密码不正确");
  }
  return new Uint8Array(plaintext);
}

async function derivePbkdf2WrappingKey(
  masterPassword: string,
  salt: ArrayBuffer,
  iterations = LEGACY_PBKDF2_ITERATIONS
): Promise<CryptoKey> {
  const passwordBytes = new TextEncoder().encode(masterPassword);
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    passwordBytes,
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  passwordBytes.fill(0);
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations
    },
    passwordKey,
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    ["encrypt", "decrypt"]
  );
}

async function deriveArgon2WrappingKey(
  masterPassword: string,
  salt: Uint8Array<ArrayBufferLike>,
  iterations: number,
  memoryCostKib: number,
  parallelism: number
): Promise<CryptoKey> {
  const passwordBytes = new TextEncoder().encode(masterPassword);
  let derived: Uint8Array;
  try {
    derived = await argon2idAsync(passwordBytes, salt, {
      t: iterations,
      m: memoryCostKib,
      p: parallelism,
      dkLen: VAULT_KEY_BYTES,
      asyncTick: 16,
      maxmem: (memoryCostKib + 1024) * 1024
    });
  } finally {
    passwordBytes.fill(0);
  }
  try {
    return await crypto.subtle.importKey(
      "raw",
      arrayBuffer(derived),
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
  } finally {
    derived.fill(0);
  }
}

async function encryptItem(
  key: CryptoKey,
  item: StoredVaultItem
): Promise<EncryptedCredentialRecord> {
  const normalized = normalizeStoredItem(item);
  const iv = randomBytes(RECORD_IV_BYTES);
  const plaintext = new TextEncoder().encode(JSON.stringify(normalized));
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: recordAad(normalized.credentialId)
    },
    key,
    plaintext
  );
  plaintext.fill(0);
  return {
    credentialId: normalized.credentialId,
    schemaVersion: VAULT_SCHEMA_VERSION,
    encryptedPayload: {
      algorithm: "AES-256-GCM",
      iv: arrayBuffer(iv),
      ciphertext
    },
    createdAt: normalized.createdAt,
    updatedAt: itemUpdatedAt(normalized)
  };
}

async function decryptItem(
  key: CryptoKey,
  record: EncryptedCredentialRecord
): Promise<StoredVaultItem> {
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: record.encryptedPayload.iv,
        additionalData: recordAad(record.credentialId)
      },
      key,
      record.encryptedPayload.ciphertext
    );
  } catch (error) {
    throw new PureExtensionError(
      "INTERNAL_ERROR",
      "本地凭据完整性校验失败",
      { cause: error }
    );
  }
  try {
    const value = JSON.parse(new TextDecoder().decode(plaintext)) as unknown;
    const normalized = normalizeStoredItem(value);
    if (normalized.credentialId !== record.credentialId) {
      throw new TypeError("Credential ID mismatch");
    }
    return normalized;
  } catch (error) {
    throw new PureExtensionError(
      "INTERNAL_ERROR",
      "本地加密凭据格式无效",
      { cause: error }
    );
  } finally {
    new Uint8Array(plaintext).fill(0);
  }
}

function normalizeStoredItem(value: unknown): StoredVaultItem {
  if (typeof value !== "object" || value === null) {
    throw new TypeError("Invalid vault item");
  }
  const candidate = value as Record<string, unknown>;
  if (candidate.kind === "password") {
    return normalizeStoredPassword(candidate);
  }
  if (candidate.kind === "audit-log") {
    return normalizeAuditLog(candidate);
  }
  if (candidate.kind === "oss-configuration") {
    return normalizeStoredOssConfiguration(candidate);
  }
  return normalizePasskey(candidate);
}

function normalizePasskey(value: unknown): StoredSoftwareCredential {
  if (typeof value !== "object" || value === null) {
    throw new TypeError("Invalid software credential");
  }
  const credential = value as Partial<StoredSoftwareCredential> & {
    kind?: unknown;
  };
  const lastUsedAt = credential.lastUsedAt;
  const deletedAt = credential.deletedAt ?? null;
  if (
    credential.schemaVersion !== 1 ||
    (credential.kind !== undefined && credential.kind !== "passkey") ||
    typeof credential.credentialId !== "string" ||
    typeof credential.rpId !== "string" ||
    typeof credential.userHandle !== "string" ||
    typeof credential.userName !== "string" ||
    typeof credential.displayName !== "string" ||
    typeof credential.privateKeyPkcs8 !== "string" ||
    typeof credential.publicKeySpki !== "string" ||
    typeof credential.publicKeyCose !== "string" ||
    !Number.isSafeInteger(credential.signCount) ||
    (credential.signCount ?? -1) < 0 ||
    (credential.signCount ?? 0) > 0xffffffff ||
    !Number.isSafeInteger(credential.createdAt) ||
    (credential.createdAt ?? -1) < 0 ||
    !validNullableTimestamp(lastUsedAt, credential.createdAt ?? 0) ||
    !validNullableTimestamp(deletedAt, credential.createdAt ?? 0)
  ) {
    throw new TypeError("Invalid software credential");
  }
  decodeBase64Url(credential.credentialId, 16, 1023);
  decodeBase64Url(credential.userHandle, 1, 64);
  decodeBase64Url(credential.privateKeyPkcs8, 64, 512);
  decodeBase64Url(credential.publicKeySpki, 64, 256);
  decodeBase64Url(credential.publicKeyCose, 32, 256);
  const alias = typeof credential.alias === "string" ? credential.alias.trim() : "";
  const tags = normalizeTags(Array.isArray(credential.tags) ? credential.tags : []);
  if (
    credential.rpId.length < 1 ||
    credential.rpId.length > 253 ||
    credential.userName.length > 256 ||
    credential.displayName.length > 256 ||
    alias.length > 128
  ) {
    throw new TypeError("Invalid software credential");
  }
  return {
    schemaVersion: 1,
    kind: "passkey",
    credentialId: credential.credentialId,
    rpId: credential.rpId,
    userHandle: credential.userHandle,
    userName: credential.userName,
    displayName: credential.displayName,
    privateKeyPkcs8: credential.privateKeyPkcs8,
    publicKeySpki: credential.publicKeySpki,
    publicKeyCose: credential.publicKeyCose,
    signCount: credential.signCount as number,
    alias,
    favorite: credential.favorite === true,
    tags,
    createdAt: credential.createdAt as number,
    lastUsedAt: lastUsedAt ?? null,
    deletedAt
  };
}

function normalizeStoredPassword(
  value: Record<string, unknown>
): StoredPasswordCredential {
  const normalized = normalizePasswordInput({
    itemId: typeof value.credentialId === "string" ? value.credentialId : "",
    name: typeof value.name === "string" ? value.name : "",
    origin: typeof value.origin === "string" ? value.origin : "",
    username: typeof value.username === "string" ? value.username : "",
    password: typeof value.password === "string" ? value.password : "",
    notes: typeof value.notes === "string" ? value.notes : "",
    favorite: value.favorite === true,
    tags: Array.isArray(value.tags)
      ? value.tags.filter((tag): tag is string => typeof tag === "string")
      : [],
    autoFill: value.autoFill === true
  });
  const createdAt = value.createdAt;
  const updatedAt = value.updatedAt;
  const lastUsedAt = value.lastUsedAt;
  const deletedAt = value.deletedAt;
  if (
    value.schemaVersion !== 1 ||
    value.kind !== "password" ||
    !normalized.itemId ||
    !/^[A-Za-z0-9_-]{16,1024}$/u.test(normalized.itemId) ||
    !Number.isSafeInteger(createdAt) ||
    (createdAt as number) < 0 ||
    !Number.isSafeInteger(updatedAt) ||
    (updatedAt as number) < (createdAt as number) ||
    !validNullableTimestamp(lastUsedAt, createdAt as number) ||
    !validNullableTimestamp(deletedAt, createdAt as number)
  ) {
    throw new TypeError("Invalid password credential");
  }
  const passwordHistory = Array.isArray(value.passwordHistory)
    ? value.passwordHistory.filter(
        (password): password is string =>
          typeof password === "string" &&
          new TextEncoder().encode(password).byteLength <= 16 * 1024
      ).slice(0, MAX_PASSWORD_HISTORY)
    : [];
  return {
    schemaVersion: 1,
    kind: "password",
    credentialId: normalized.itemId,
    name: normalized.name,
    origin: normalized.origin,
    username: normalized.username,
    password: normalized.password,
    notes: normalized.notes,
    favorite: normalized.favorite,
    tags: normalized.tags,
    autoFill: normalized.autoFill,
    passwordHistory,
    createdAt: createdAt as number,
    updatedAt: updatedAt as number,
    lastUsedAt: (lastUsedAt as number | null | undefined) ?? null,
    deletedAt: (deletedAt as number | null | undefined) ?? null
  };
}

function normalizeAuditLog(value: Record<string, unknown>): StoredAuditLog {
  if (
    value.schemaVersion !== 1 ||
    value.kind !== "audit-log" ||
    value.credentialId !== AUDIT_LOG_ID ||
    !Array.isArray(value.entries) ||
    value.entries.length > MAX_AUDIT_ENTRIES ||
    !Number.isSafeInteger(value.createdAt) ||
    !Number.isSafeInteger(value.updatedAt) ||
    (value.createdAt as number) < 0 ||
    (value.updatedAt as number) < (value.createdAt as number)
  ) {
    throw new TypeError("Invalid audit log");
  }
  const entries = value.entries.map(normalizeAuditEntry);
  return {
    schemaVersion: 1,
    kind: "audit-log",
    credentialId: AUDIT_LOG_ID,
    entries,
    createdAt: value.createdAt as number,
    updatedAt: value.updatedAt as number
  };
}

function normalizeStoredOssConfiguration(
  value: Record<string, unknown>
): StoredOssConfiguration {
  if (
    value.schemaVersion !== 1 ||
    value.kind !== "oss-configuration" ||
    value.credentialId !== OSS_CONFIGURATION_ID ||
    typeof value.configuration !== "object" ||
    value.configuration === null ||
    !Number.isSafeInteger(value.createdAt) ||
    !Number.isSafeInteger(value.updatedAt) ||
    (value.createdAt as number) < 0 ||
    (value.updatedAt as number) < (value.createdAt as number) ||
    !validNullableTimestamp(value.lastUploadedAt, value.createdAt as number)
  ) {
    throw new TypeError("Invalid encrypted OSS configuration");
  }
  return {
    schemaVersion: 1,
    kind: "oss-configuration",
    credentialId: OSS_CONFIGURATION_ID,
    configuration: normalizeOssConfiguration(
      value.configuration as OssConfiguration
    ),
    lastUploadedAt: (value.lastUploadedAt as number | null | undefined) ?? null,
    lastEtag: normalizeNullableEtag(value.lastEtag),
    createdAt: value.createdAt as number,
    updatedAt: value.updatedAt as number
  };
}

function normalizeAuditEntry(value: unknown): AuditEntry {
  if (typeof value !== "object" || value === null) {
    throw new TypeError("Invalid audit entry");
  }
  const entry = value as Partial<AuditEntry>;
  const allowedTypes = new Set<AuditEventType>([
    "vault-created",
    "vault-unlocked",
    "vault-locked",
    "master-password-changed",
    "passkey-created",
    "passkey-used",
    "passkey-updated",
    "password-created",
    "password-used",
    "password-updated",
    "item-trashed",
    "item-restored",
    "item-deleted",
    "backup-exported",
    "backup-imported",
    "oss-connected",
    "oss-backup-uploaded",
    "oss-disconnected"
  ]);
  if (
    typeof entry.id !== "string" ||
    !/^[A-Za-z0-9_-]{12,64}$/u.test(entry.id) ||
    !entry.type ||
    !allowedTypes.has(entry.type) ||
    !Number.isSafeInteger(entry.at) ||
    (entry.at ?? -1) < 0 ||
    (entry.targetKind !== undefined &&
      entry.targetKind !== "passkey" &&
      entry.targetKind !== "password" &&
      entry.targetKind !== "vault") ||
    (entry.targetLabel !== undefined &&
      (typeof entry.targetLabel !== "string" ||
        entry.targetLabel.length > 256))
  ) {
    throw new TypeError("Invalid audit entry");
  }
  return {
    id: entry.id,
    type: entry.type,
    at: entry.at as number,
    ...(entry.targetKind ? { targetKind: entry.targetKind } : {}),
    ...(entry.targetLabel ? { targetLabel: entry.targetLabel } : {})
  };
}

function recordAad(credentialId: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(`${RECORD_AAD_PREFIX}${credentialId}`);
}

function itemUpdatedAt(item: StoredVaultItem): number {
  if (
    isPassword(item) ||
    isAuditLog(item) ||
    isOssConfiguration(item)
  ) {
    return item.updatedAt;
  }
  return item.lastUsedAt ?? item.createdAt;
}

function itemLabel(item: StoredSoftwareCredential | StoredPasswordCredential): string {
  return isPassword(item)
    ? `${item.name} · ${new URL(item.origin).hostname}`
    : item.alias || item.rpId;
}

function isPasskey(item: StoredVaultItem): item is StoredSoftwareCredential {
  return item.kind === "passkey";
}

function isPassword(
  item: StoredVaultItem
): item is StoredPasswordCredential {
  return item.kind === "password";
}

function isAuditLog(item: StoredVaultItem): item is StoredAuditLog {
  return item.kind === "audit-log";
}

function isOssConfiguration(
  item: StoredVaultItem
): item is StoredOssConfiguration {
  return item.kind === "oss-configuration";
}

function toOssConfigurationSummary(
  item: StoredOssConfiguration
): OssConfigurationSummary {
  return {
    endpoint: item.configuration.endpoint,
    region: item.configuration.region,
    bucket: item.configuration.bucket,
    objectKey: item.configuration.objectKey,
    accessKeyId: item.configuration.accessKeyId,
    lastUploadedAt: item.lastUploadedAt,
    lastEtag: item.lastEtag,
    updatedAt: item.updatedAt
  };
}

function normalizeNullableEtag(value: unknown): string | null {
  if (value === null || value === undefined || value === "") {
    return null;
  }
  if (
    typeof value !== "string" ||
    value.length > 256 ||
    /[\r\n]/u.test(value)
  ) {
    throw new TypeError("Invalid OSS ETag");
  }
  return value;
}

function sameOssTarget(
  left: OssConfiguration,
  right: OssConfiguration
): boolean {
  return (
    left.endpoint === right.endpoint &&
    left.bucket === right.bucket &&
    left.objectKey === right.objectKey
  );
}

function validNullableTimestamp(
  value: unknown,
  minimum: number
): value is number | null | undefined {
  return (
    value === undefined ||
    value === null ||
    (Number.isSafeInteger(value) && (value as number) >= minimum)
  );
}

function validateExistingMasterPassword(masterPassword: string): void {
  if (!isExistingMasterPassword(masterPassword)) {
    throw new PureExtensionError(
      "INVALID_PASSWORD",
      "主密码格式无效"
    );
  }
}

function validateNewMasterPassword(masterPassword: string): void {
  if (!isNewMasterPassword(masterPassword)) {
    throw new PureExtensionError(
      "INVALID_PASSWORD",
      "新主密码至少需要 8 个字符"
    );
  }
}

function toPasskeySummary(
  credential: StoredSoftwareCredential
): CredentialSummary {
  return {
    credentialId: credential.credentialId,
    rpId: credential.rpId,
    userName: credential.userName,
    displayName: credential.displayName,
    alias: credential.alias || null,
    favorite: credential.favorite,
    tags: [...credential.tags],
    signCount: credential.signCount,
    createdAt: Math.floor(credential.createdAt / 1_000),
    lastUsedAt:
      credential.lastUsedAt === null
        ? null
        : Math.floor(credential.lastUsedAt / 1_000),
    deletedAt:
      credential.deletedAt === null
        ? null
        : Math.floor(credential.deletedAt / 1_000)
  };
}

function toPasswordSummary(
  item: StoredPasswordCredential,
  reused: boolean
): PasswordSummary {
  const strength = passwordStrength(item.password);
  return {
    itemId: item.credentialId,
    name: item.name,
    origin: item.origin,
    username: item.username,
    favorite: item.favorite,
    tags: [...item.tags],
    autoFill: item.autoFill,
    createdAt: Math.floor(item.createdAt / 1_000),
    updatedAt: Math.floor(item.updatedAt / 1_000),
    lastUsedAt:
      item.lastUsedAt === null
        ? null
        : Math.floor(item.lastUsedAt / 1_000),
    deletedAt:
      item.deletedAt === null
        ? null
        : Math.floor(item.deletedAt / 1_000),
    strengthScore: strength.score,
    weak: strength.weak,
    reused
  };
}

function toPasswordDetails(item: StoredPasswordCredential): PasswordDetails {
  return {
    itemId: item.credentialId,
    name: item.name,
    origin: item.origin,
    username: item.username,
    password: item.password,
    notes: item.notes,
    favorite: item.favorite,
    tags: [...item.tags],
    autoFill: item.autoFill,
    createdAt: Math.floor(item.createdAt / 1_000),
    updatedAt: Math.floor(item.updatedAt / 1_000),
    lastUsedAt:
      item.lastUsedAt === null
        ? null
        : Math.floor(item.lastUsedAt / 1_000),
    deletedAt:
      item.deletedAt === null
        ? null
        : Math.floor(item.deletedAt / 1_000)
  };
}

function emptyPasswordAudit(): PasswordAuditSummary {
  return {
    total: 0,
    weak: 0,
    reused: 0,
    stale: 0,
    insecureOrigins: 0
  };
}

function defaultSettingsStorage(): VaultSettingsStorage {
  return typeof chrome !== "undefined" && chrome.storage?.local
    ? new ChromeVaultSettingsStorage()
    : new MemoryVaultSettingsStorage();
}

function isVaultSession(value: unknown): value is VaultSession {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const session = value as Partial<VaultSession>;
  return (
    typeof session.vaultKey === "string" &&
    Number.isSafeInteger(session.lastActivityAt) &&
    (session.lastActivityAt ?? -1) >= 0 &&
    Number.isSafeInteger(session.expiresAt) &&
    (session.expiresAt ?? -1) >= (session.lastActivityAt ?? 0)
  );
}

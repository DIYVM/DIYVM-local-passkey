import type {
  CredentialSummary,
  ExtensionErrorCode,
  VaultState
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

const PBKDF2_ITERATIONS = 600_000;
const VAULT_KEY_BYTES = 32;
const WRAP_IV_BYTES = 12;
const RECORD_IV_BYTES = 12;
const VAULT_KEY_AAD = new TextEncoder().encode(
  "diyvm-local-passkey:vault-key:v1"
);
const RECORD_AAD_PREFIX = "diyvm-local-passkey:credential:v1:";
const SESSION_KEY = "pureVaultSession";

export interface StoredSoftwareCredential {
  schemaVersion: 1;
  credentialId: string;
  rpId: string;
  userHandle: string;
  userName: string;
  displayName: string;
  privateKeyPkcs8: string;
  publicKeySpki: string;
  publicKeyCose: string;
  signCount: number;
  createdAt: number;
  lastUsedAt: number | null;
}

interface VaultSession {
  vaultKey: string;
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
    private readonly now: () => number = Date.now
  ) {}

  async status(): Promise<{
    vaultState: VaultState;
    credentialCount: number;
  }> {
    const metadata = await this.store.readMetadata();
    const credentialCount = (await this.store.listCredentials()).length;
    if (!metadata) {
      await this.sessionStorage.clear();
      return { vaultState: "notInitialized", credentialCount };
    }
    const session = await this.readActiveSession();
    return {
      vaultState: session ? "unlocked" : "locked",
      credentialCount
    };
  }

  async initialize(masterPassword: string): Promise<void> {
    validateMasterPassword(masterPassword);
    if (await this.store.hasVault()) {
      throw new PureExtensionError(
        "INVALID_STATE",
        "纯插件凭据库已经创建"
      );
    }

    const salt = randomBytes(16);
    const vaultKeyBytes = randomBytes(VAULT_KEY_BYTES);
    const wrappingKey = await deriveWrappingKey(
      masterPassword,
      salt.buffer,
      PBKDF2_ITERATIONS
    );
    const iv = randomBytes(WRAP_IV_BYTES);
    const wrappedVaultKey = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: VAULT_KEY_AAD
      },
      wrappingKey,
      vaultKeyBytes
    );
    const timestamp = this.now();
    const metadata: VaultMetadataRecord = {
      key: "vault",
      schemaVersion: VAULT_SCHEMA_VERSION,
      kdf: {
        algorithm: "PBKDF2-SHA-256",
        iterations: PBKDF2_ITERATIONS,
        salt: salt.buffer
      },
      wrappedVaultKey: {
        algorithm: "AES-256-GCM",
        iv: iv.buffer,
        ciphertext: wrappedVaultKey
      },
      createdAt: timestamp,
      updatedAt: timestamp
    };
    await this.store.writeMetadata(metadata);
    await this.writeSession(vaultKeyBytes);
    vaultKeyBytes.fill(0);
  }

  async unlock(masterPassword: string): Promise<void> {
    validateMasterPassword(masterPassword);
    const metadata = await this.store.readMetadata();
    if (!metadata) {
      throw new PureExtensionError(
        "VAULT_NOT_INITIALIZED",
        "尚未创建纯插件凭据库"
      );
    }
    if (metadata.kdf.algorithm !== "PBKDF2-SHA-256") {
      throw new PureExtensionError(
        "NOT_SUPPORTED",
        "此凭据库使用当前纯插件不支持的密钥派生算法"
      );
    }

    const wrappingKey = await deriveWrappingKey(
      masterPassword,
      metadata.kdf.salt,
      metadata.kdf.iterations
    );
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
      throw new PureExtensionError(
        "INVALID_PASSWORD",
        "主密码不正确"
      );
    }
    const keyBytes = new Uint8Array(plaintext);
    await this.writeSession(keyBytes);
    keyBytes.fill(0);
  }

  async lock(): Promise<void> {
    await this.sessionStorage.clear();
  }

  async listCredentials(): Promise<CredentialSummary[]> {
    const credentials = await this.decryptAllCredentials();
    return credentials
      .map(toSummary)
      .sort((left, right) => {
        const site = left.rpId.localeCompare(right.rpId);
        return site !== 0
          ? site
          : (left.displayName ?? left.userName ?? "").localeCompare(
              right.displayName ?? right.userName ?? ""
            );
      });
  }

  async findCredentials(
    rpId: string,
    allowedCredentialIds?: ReadonlySet<string>
  ): Promise<StoredSoftwareCredential[]> {
    return (await this.decryptAllCredentials()).filter(
      (credential) =>
        credential.rpId === rpId &&
        (!allowedCredentialIds ||
          allowedCredentialIds.has(credential.credentialId))
    );
  }

  async readCredential(
    credentialId: string
  ): Promise<StoredSoftwareCredential | undefined> {
    const key = await this.requireVaultKey();
    const record = await this.store.readCredential(credentialId);
    return record ? await decryptCredential(key, record) : undefined;
  }

  async saveCredential(
    credential: StoredSoftwareCredential
  ): Promise<void> {
    validateStoredCredential(credential);
    const key = await this.requireVaultKey();
    const existing = await this.store.readCredential(
      credential.credentialId
    );
    if (existing) {
      throw new PureExtensionError(
        "INVALID_STATE",
        "凭据 ID 已经存在"
      );
    }
    await this.store.writeCredential(
      await encryptCredential(key, credential)
    );
  }

  async updateCredential(
    credential: StoredSoftwareCredential
  ): Promise<void> {
    validateStoredCredential(credential);
    const key = await this.requireVaultKey();
    const existing = await this.store.readCredential(
      credential.credentialId
    );
    if (!existing) {
      throw new PureExtensionError(
        "CREDENTIAL_NOT_FOUND",
        "找不到本地通行密钥"
      );
    }
    await this.store.writeCredential(
      await encryptCredential(key, credential)
    );
  }

  async deleteCredential(credentialId: string): Promise<boolean> {
    await this.requireVaultKey();
    return this.store.deleteCredential(credentialId);
  }

  private async decryptAllCredentials(): Promise<StoredSoftwareCredential[]> {
    const key = await this.requireVaultKey();
    const records = await this.store.listCredentials();
    return Promise.all(
      records.map((record) => decryptCredential(key, record))
    );
  }

  private async requireVaultKey(): Promise<CryptoKey> {
    const metadata = await this.store.readMetadata();
    if (!metadata) {
      throw new PureExtensionError(
        "VAULT_NOT_INITIALIZED",
        "尚未创建纯插件凭据库"
      );
    }
    const session = await this.readActiveSession();
    if (!session) {
      throw new PureExtensionError(
        "VAULT_LOCKED",
        "纯插件凭据库已锁定"
      );
    }
    const rawKey = decodeBase64Url(
      session.vaultKey,
      VAULT_KEY_BYTES,
      VAULT_KEY_BYTES
    );
    return crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
  }

  private async readActiveSession(): Promise<VaultSession | undefined> {
    const session = await this.sessionStorage.read();
    if (!session) {
      return undefined;
    }
    try {
      decodeBase64Url(session.vaultKey, VAULT_KEY_BYTES, VAULT_KEY_BYTES);
      return session;
    } catch {
      await this.sessionStorage.clear();
      return undefined;
    }
  }

  private async writeSession(keyBytes: Uint8Array<ArrayBufferLike>): Promise<void> {
    await this.sessionStorage.write({
      vaultKey: encodeBase64Url(keyBytes)
    });
  }
}

export async function openPureVault(): Promise<{
  vault: PureVault;
  close(): void;
}> {
  const store = await IndexedDbVaultStore.open();
  return {
    vault: new PureVault(store, new ChromeVaultSessionStorage()),
    close: () => store.close()
  };
}

async function deriveWrappingKey(
  masterPassword: string,
  salt: ArrayBuffer,
  iterations: number
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
    ["wrapKey", "unwrapKey", "encrypt", "decrypt"]
  );
}

async function encryptCredential(
  key: CryptoKey,
  credential: StoredSoftwareCredential
): Promise<EncryptedCredentialRecord> {
  const iv = randomBytes(RECORD_IV_BYTES);
  const plaintext = new TextEncoder().encode(JSON.stringify(credential));
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: recordAad(credential.credentialId)
    },
    key,
    plaintext
  );
  plaintext.fill(0);
  return {
    credentialId: credential.credentialId,
    schemaVersion: VAULT_SCHEMA_VERSION,
    encryptedPayload: {
      algorithm: "AES-256-GCM",
      iv: iv.buffer,
      ciphertext
    },
    createdAt: credential.createdAt,
    updatedAt: credential.lastUsedAt ?? credential.createdAt
  };
}

async function decryptCredential(
  key: CryptoKey,
  record: EncryptedCredentialRecord
): Promise<StoredSoftwareCredential> {
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
    validateStoredCredential(value);
    if (value.credentialId !== record.credentialId) {
      throw new TypeError("Credential ID mismatch");
    }
    return value;
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

function recordAad(credentialId: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(`${RECORD_AAD_PREFIX}${credentialId}`);
}

function validateStoredCredential(
  value: unknown
): asserts value is StoredSoftwareCredential {
  if (
    typeof value !== "object" ||
    value === null ||
    (value as Partial<StoredSoftwareCredential>).schemaVersion !== 1
  ) {
    throw new TypeError("Invalid software credential");
  }
  const credential = value as Partial<StoredSoftwareCredential>;
  const lastUsedAt = credential.lastUsedAt;
  if (
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
    !(
      lastUsedAt === null ||
      (typeof lastUsedAt === "number" &&
        Number.isSafeInteger(lastUsedAt) &&
        lastUsedAt >= (credential.createdAt ?? 0))
    )
  ) {
    throw new TypeError("Invalid software credential");
  }
  decodeBase64Url(credential.credentialId, 16, 1023);
  decodeBase64Url(credential.userHandle, 1, 64);
  decodeBase64Url(credential.privateKeyPkcs8, 64, 512);
  decodeBase64Url(credential.publicKeySpki, 64, 256);
  decodeBase64Url(credential.publicKeyCose, 32, 256);
  if (
    credential.rpId.length < 1 ||
    credential.rpId.length > 253 ||
    credential.userName.length > 256 ||
    credential.displayName.length > 256
  ) {
    throw new TypeError("Invalid software credential");
  }
}

function validateMasterPassword(masterPassword: string): void {
  const byteLength = new TextEncoder().encode(masterPassword).byteLength;
  if (byteLength < 12 || byteLength > 1024) {
    throw new PureExtensionError(
      "INVALID_PASSWORD",
      "主密码必须为 12 至 1024 个 UTF-8 字节"
    );
  }
}

function toSummary(credential: StoredSoftwareCredential): CredentialSummary {
  return {
    credentialId: credential.credentialId,
    rpId: credential.rpId,
    userName: credential.userName,
    displayName: credential.displayName,
    signCount: credential.signCount,
    createdAt: Math.floor(credential.createdAt / 1_000),
    lastUsedAt:
      credential.lastUsedAt === null
        ? null
        : Math.floor(credential.lastUsedAt / 1_000)
  };
}

function isVaultSession(value: unknown): value is VaultSession {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as Partial<VaultSession>).vaultKey === "string"
  );
}

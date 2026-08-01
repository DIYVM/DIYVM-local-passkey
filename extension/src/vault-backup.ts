import {
  VAULT_SCHEMA_VERSION,
  type EncryptedCredentialRecord,
  type IndexedDbVaultStore,
  type VaultMetadataRecord,
  type VaultSnapshot,
  validateSnapshot
} from "./indexeddb-vault";

export const VAULT_BACKUP_FORMAT = "diyvm-local-passkey-backup";
export const VAULT_BACKUP_VERSION = 1 as const;
export const MAX_VAULT_BACKUP_BYTES = 20 * 1024 * 1024;

interface SerializedVaultMetadata {
  schemaVersion: typeof VAULT_SCHEMA_VERSION;
  kdf: {
    algorithm: VaultMetadataRecord["kdf"]["algorithm"];
    iterations: number;
    salt: string;
  };
  wrappedVaultKey: {
    algorithm: "AES-256-GCM";
    iv: string;
    ciphertext: string;
  };
  createdAt: number;
  updatedAt: number;
}

interface SerializedCredential {
  credentialId: string;
  schemaVersion: typeof VAULT_SCHEMA_VERSION;
  encryptedPayload: {
    algorithm: "AES-256-GCM";
    iv: string;
    ciphertext: string;
  };
  createdAt: number;
  updatedAt: number;
}

interface BackupPayload {
  format: typeof VAULT_BACKUP_FORMAT;
  formatVersion: typeof VAULT_BACKUP_VERSION;
  exportedAt: string;
  vault: {
    metadata: SerializedVaultMetadata;
    credentials: SerializedCredential[];
  };
}

interface BackupDocument extends BackupPayload {
  checksum: {
    algorithm: "SHA-256";
    value: string;
  };
}

export async function exportVaultBackup(
  store: IndexedDbVaultStore,
  exportedAt = new Date()
): Promise<string> {
  const snapshot = await store.exportSnapshot();
  if (!snapshot) {
    throw new Error("尚未创建可导出的纯插件凭据库");
  }

  const payload = serializeSnapshot(snapshot, exportedAt.toISOString());
  const checksum = await sha256Base64Url(canonicalPayload(payload));
  const document: BackupDocument = {
    ...payload,
    checksum: {
      algorithm: "SHA-256",
      value: checksum
    }
  };
  return `${JSON.stringify(document, undefined, 2)}\n`;
}

export async function importVaultBackup(
  store: IndexedDbVaultStore,
  backupText: string
): Promise<{ credentialCount: number; exportedAt: string }> {
  const { snapshot, exportedAt } = await parseVaultBackup(backupText);
  await store.replaceAll(snapshot);
  return {
    credentialCount: snapshot.credentials.length,
    exportedAt
  };
}

export async function parseVaultBackup(
  backupText: string
): Promise<{ snapshot: VaultSnapshot; exportedAt: string }> {
  if (
    typeof backupText !== "string" ||
    new TextEncoder().encode(backupText).byteLength > MAX_VAULT_BACKUP_BYTES
  ) {
    throw new Error("备份文件为空或超过 20 MB 限制");
  }

  let value: unknown;
  try {
    value = JSON.parse(backupText);
  } catch (error) {
    throw new Error("备份文件不是有效的 JSON", { cause: error });
  }

  const document = parseBackupDocument(value);
  const snapshot = deserializeSnapshot(document);
  validateSnapshot(snapshot);
  const payload = serializeSnapshot(snapshot, document.exportedAt);
  const expectedChecksum = await sha256Base64Url(canonicalPayload(payload));
  if (!constantTimeEqual(expectedChecksum, document.checksum.value)) {
    throw new Error("备份文件完整性校验失败");
  }

  return { snapshot, exportedAt: document.exportedAt };
}

export function createBackupFileName(now = new Date()): string {
  const timestamp = now
    .toISOString()
    .replaceAll("-", "")
    .replaceAll(":", "")
    .replace(/\.\d{3}Z$/, "Z")
    .replace("T", "-");
  return `DIYVM-LocalPasskey-backup-${timestamp}.diyvmpasskey.json`;
}

function serializeSnapshot(
  snapshot: VaultSnapshot,
  exportedAt: string
): BackupPayload {
  validateSnapshot(snapshot);
  return {
    format: VAULT_BACKUP_FORMAT,
    formatVersion: VAULT_BACKUP_VERSION,
    exportedAt,
    vault: {
      metadata: {
        schemaVersion: VAULT_SCHEMA_VERSION,
        kdf: {
          algorithm: snapshot.metadata.kdf.algorithm,
          iterations: snapshot.metadata.kdf.iterations,
          salt: encodeBase64Url(snapshot.metadata.kdf.salt)
        },
        wrappedVaultKey: {
          algorithm: "AES-256-GCM",
          iv: encodeBase64Url(snapshot.metadata.wrappedVaultKey.iv),
          ciphertext: encodeBase64Url(
            snapshot.metadata.wrappedVaultKey.ciphertext
          )
        },
        createdAt: snapshot.metadata.createdAt,
        updatedAt: snapshot.metadata.updatedAt
      },
      credentials: [...snapshot.credentials]
        .sort((left, right) =>
          left.credentialId.localeCompare(right.credentialId)
        )
        .map((credential) => ({
          credentialId: credential.credentialId,
          schemaVersion: VAULT_SCHEMA_VERSION,
          encryptedPayload: {
            algorithm: "AES-256-GCM" as const,
            iv: encodeBase64Url(credential.encryptedPayload.iv),
            ciphertext: encodeBase64Url(
              credential.encryptedPayload.ciphertext
            )
          },
          createdAt: credential.createdAt,
          updatedAt: credential.updatedAt
        }))
    }
  };
}

function deserializeSnapshot(document: BackupDocument): VaultSnapshot {
  const metadata = document.vault.metadata;
  return {
    metadata: {
      key: "vault",
      schemaVersion: VAULT_SCHEMA_VERSION,
      kdf: {
        algorithm: metadata.kdf.algorithm,
        iterations: metadata.kdf.iterations,
        salt: decodeBase64Url(metadata.kdf.salt, 64)
      },
      wrappedVaultKey: {
        algorithm: "AES-256-GCM",
        iv: decodeBase64Url(metadata.wrappedVaultKey.iv, 12),
        ciphertext: decodeBase64Url(
          metadata.wrappedVaultKey.ciphertext,
          4 * 1024
        )
      },
      createdAt: metadata.createdAt,
      updatedAt: metadata.updatedAt
    },
    credentials: document.vault.credentials.map(deserializeCredential)
  };
}

function deserializeCredential(
  credential: SerializedCredential
): EncryptedCredentialRecord {
  return {
    credentialId: credential.credentialId,
    schemaVersion: VAULT_SCHEMA_VERSION,
    encryptedPayload: {
      algorithm: "AES-256-GCM",
      iv: decodeBase64Url(credential.encryptedPayload.iv, 12),
      ciphertext: decodeBase64Url(
        credential.encryptedPayload.ciphertext,
        256 * 1024
      )
    },
    createdAt: credential.createdAt,
    updatedAt: credential.updatedAt
  };
}

function parseBackupDocument(value: unknown): BackupDocument {
  if (!isRecord(value)) {
    throw new Error("备份文件结构无效");
  }
  if (
    value.format !== VAULT_BACKUP_FORMAT ||
    value.formatVersion !== VAULT_BACKUP_VERSION ||
    typeof value.exportedAt !== "string" ||
    !validIsoDate(value.exportedAt) ||
    !isRecord(value.vault) ||
    !isRecord(value.vault.metadata) ||
    !Array.isArray(value.vault.credentials) ||
    !isRecord(value.checksum) ||
    value.checksum.algorithm !== "SHA-256" ||
    typeof value.checksum.value !== "string"
  ) {
    throw new Error("备份文件版本或字段无效");
  }

  return {
    format: VAULT_BACKUP_FORMAT,
    formatVersion: VAULT_BACKUP_VERSION,
    exportedAt: value.exportedAt,
    vault: {
      metadata: parseMetadata(value.vault.metadata),
      credentials: value.vault.credentials.map(parseCredential)
    },
    checksum: {
      algorithm: "SHA-256",
      value: value.checksum.value
    }
  };
}

function parseMetadata(value: Record<string, unknown>): SerializedVaultMetadata {
  if (
    value.schemaVersion !== VAULT_SCHEMA_VERSION ||
    !isRecord(value.kdf) ||
    (value.kdf.algorithm !== "ARGON2ID" &&
      value.kdf.algorithm !== "PBKDF2-SHA-256") ||
    typeof value.kdf.iterations !== "number" ||
    typeof value.kdf.salt !== "string" ||
    !isRecord(value.wrappedVaultKey) ||
    value.wrappedVaultKey.algorithm !== "AES-256-GCM" ||
    typeof value.wrappedVaultKey.iv !== "string" ||
    typeof value.wrappedVaultKey.ciphertext !== "string" ||
    typeof value.createdAt !== "number" ||
    typeof value.updatedAt !== "number"
  ) {
    throw new Error("备份文件中的凭据库元数据无效");
  }
  return {
    schemaVersion: VAULT_SCHEMA_VERSION,
    kdf: {
      algorithm: value.kdf.algorithm,
      iterations: value.kdf.iterations,
      salt: value.kdf.salt
    },
    wrappedVaultKey: {
      algorithm: "AES-256-GCM",
      iv: value.wrappedVaultKey.iv,
      ciphertext: value.wrappedVaultKey.ciphertext
    },
    createdAt: value.createdAt,
    updatedAt: value.updatedAt
  };
}

function parseCredential(value: unknown): SerializedCredential {
  if (
    !isRecord(value) ||
    typeof value.credentialId !== "string" ||
    value.schemaVersion !== VAULT_SCHEMA_VERSION ||
    !isRecord(value.encryptedPayload) ||
    value.encryptedPayload.algorithm !== "AES-256-GCM" ||
    typeof value.encryptedPayload.iv !== "string" ||
    typeof value.encryptedPayload.ciphertext !== "string" ||
    typeof value.createdAt !== "number" ||
    typeof value.updatedAt !== "number"
  ) {
    throw new Error("备份文件中的加密凭据无效");
  }
  return {
    credentialId: value.credentialId,
    schemaVersion: VAULT_SCHEMA_VERSION,
    encryptedPayload: {
      algorithm: "AES-256-GCM",
      iv: value.encryptedPayload.iv,
      ciphertext: value.encryptedPayload.ciphertext
    },
    createdAt: value.createdAt,
    updatedAt: value.updatedAt
  };
}

function canonicalPayload(payload: BackupPayload): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(payload));
}

async function sha256Base64Url(value: Uint8Array): Promise<string> {
  const input = new Uint8Array(value.byteLength);
  input.set(value);
  const digest = await crypto.subtle.digest("SHA-256", input.buffer);
  return encodeBase64Url(digest);
}

function encodeBase64Url(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value);
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(
      ...bytes.subarray(offset, offset + chunkSize)
    );
  }
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function decodeBase64Url(value: string, maximumBytes: number): ArrayBuffer {
  if (
    value.length === 0 ||
    value.length > Math.ceil(maximumBytes * 4 / 3) + 4 ||
    !/^[A-Za-z0-9_-]+$/.test(value)
  ) {
    throw new Error("备份文件包含无效的二进制数据");
  }
  const normalized = value
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  let binary: string;
  try {
    binary = atob(normalized);
  } catch (error) {
    throw new Error("备份文件包含损坏的二进制数据", { cause: error });
  }
  if (binary.length > maximumBytes) {
    throw new Error("备份文件中的二进制字段过大");
  }
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes.buffer;
}

function constantTimeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

function validIsoDate(value: string): boolean {
  const parsed = new Date(value);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString() === value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

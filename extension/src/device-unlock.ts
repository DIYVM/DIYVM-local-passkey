import {
  arrayBuffer,
  encodeBase64Url,
  randomBytes
} from "./binary";
import type { VaultMetadataRecord } from "./indexeddb-vault";

const DEVICE_DATABASE_NAME = "diyvm-local-passkey-device-unlock";
const DEVICE_DATABASE_VERSION = 1;
const DEVICE_STORE = "device-unlock";
const DEVICE_RECORD_KEY = "trusted-device";
const DEVICE_AAD_PREFIX = "diyvm-local-passkey:device-unlock:v1:";
const DEVICE_IV_BYTES = 12;
const VAULT_KEY_BYTES = 32;

interface DeviceUnlockRecord {
  key: typeof DEVICE_RECORD_KEY;
  schemaVersion: 1;
  vaultId: string;
  wrappingKey: CryptoKey;
  iv: ArrayBuffer;
  ciphertext: ArrayBuffer;
}

export interface DeviceUnlockStorage {
  read(): Promise<DeviceUnlockRecord | undefined>;
  write(record: DeviceUnlockRecord): Promise<void>;
  clear(): Promise<void>;
}

export class ChromeDeviceUnlockStorage implements DeviceUnlockStorage {
  async read(): Promise<DeviceUnlockRecord | undefined> {
    const database = await openDeviceDatabase();
    try {
      const transaction = database.transaction(DEVICE_STORE, "readonly");
      const completed = transactionComplete(transaction);
      const record = await requestResult<DeviceUnlockRecord | undefined>(
        transaction.objectStore(DEVICE_STORE).get(DEVICE_RECORD_KEY),
        "Unable to read trusted-device unlock material"
      );
      await completed;
      return isDeviceUnlockRecord(record) ? cloneRecord(record) : undefined;
    } finally {
      database.close();
    }
  }

  async write(record: DeviceUnlockRecord): Promise<void> {
    if (!isDeviceUnlockRecord(record)) {
      throw new TypeError("Invalid trusted-device unlock material");
    }
    const database = await openDeviceDatabase();
    try {
      const transaction = database.transaction(DEVICE_STORE, "readwrite");
      const completed = transactionComplete(transaction);
      transaction.objectStore(DEVICE_STORE).put(cloneRecord(record));
      await completed;
    } finally {
      database.close();
    }
  }

  async clear(): Promise<void> {
    const database = await openDeviceDatabase();
    try {
      const transaction = database.transaction(DEVICE_STORE, "readwrite");
      const completed = transactionComplete(transaction);
      transaction.objectStore(DEVICE_STORE).delete(DEVICE_RECORD_KEY);
      await completed;
    } finally {
      database.close();
    }
  }
}

export class MemoryDeviceUnlockStorage implements DeviceUnlockStorage {
  private record: DeviceUnlockRecord | undefined;

  async read(): Promise<DeviceUnlockRecord | undefined> {
    return this.record ? cloneRecord(this.record) : undefined;
  }

  async write(record: DeviceUnlockRecord): Promise<void> {
    this.record = cloneRecord(record);
  }

  async clear(): Promise<void> {
    this.record = undefined;
  }
}

export async function rememberVaultKeyOnDevice(
  storage: DeviceUnlockStorage,
  metadata: VaultMetadataRecord,
  vaultKey: Uint8Array<ArrayBufferLike>
): Promise<void> {
  if (vaultKey.byteLength !== VAULT_KEY_BYTES) {
    throw new TypeError("Invalid Vault Key length");
  }
  const vaultId = await vaultIdentity(metadata);
  const wrappingKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  const iv = randomBytes(DEVICE_IV_BYTES);
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: new TextEncoder().encode(`${DEVICE_AAD_PREFIX}${vaultId}`)
    },
    wrappingKey,
    arrayBuffer(vaultKey)
  );
  await storage.write({
    key: DEVICE_RECORD_KEY,
    schemaVersion: 1,
    vaultId,
    wrappingKey,
    iv: arrayBuffer(iv),
    ciphertext
  });
}

export async function restoreVaultKeyFromDevice(
  storage: DeviceUnlockStorage,
  metadata: VaultMetadataRecord
): Promise<Uint8Array<ArrayBuffer> | undefined> {
  const record = await storage.read();
  if (!record || record.vaultId !== await vaultIdentity(metadata)) {
    return undefined;
  }
  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: record.iv,
        additionalData: new TextEncoder().encode(
          `${DEVICE_AAD_PREFIX}${record.vaultId}`
        )
      },
      record.wrappingKey,
      record.ciphertext
    );
    if (plaintext.byteLength !== VAULT_KEY_BYTES) {
      return undefined;
    }
    return new Uint8Array(plaintext);
  } catch {
    return undefined;
  }
}

async function vaultIdentity(metadata: VaultMetadataRecord): Promise<string> {
  const material = new Uint8Array(
    metadata.kdf.salt.byteLength + metadata.wrappedVaultKey.ciphertext.byteLength
  );
  material.set(new Uint8Array(metadata.kdf.salt), 0);
  material.set(
    new Uint8Array(metadata.wrappedVaultKey.ciphertext),
    metadata.kdf.salt.byteLength
  );
  return encodeBase64Url(await crypto.subtle.digest("SHA-256", material));
}

async function openDeviceDatabase(): Promise<IDBDatabase> {
  const request = indexedDB.open(DEVICE_DATABASE_NAME, DEVICE_DATABASE_VERSION);
  request.onupgradeneeded = () => {
    const database = request.result;
    if (!database.objectStoreNames.contains(DEVICE_STORE)) {
      database.createObjectStore(DEVICE_STORE, { keyPath: "key" });
    }
  };
  return requestResult(request, "Unable to open trusted-device database");
}

function isDeviceUnlockRecord(value: unknown): value is DeviceUnlockRecord {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const record = value as Partial<DeviceUnlockRecord>;
  return (
    record.key === DEVICE_RECORD_KEY &&
    record.schemaVersion === 1 &&
    typeof record.vaultId === "string" &&
    /^[A-Za-z0-9_-]{43}$/u.test(record.vaultId) &&
    record.wrappingKey instanceof CryptoKey &&
    record.wrappingKey.type === "secret" &&
    record.wrappingKey.extractable === false &&
    record.wrappingKey.algorithm.name === "AES-GCM" &&
    record.wrappingKey.usages.includes("encrypt") &&
    record.wrappingKey.usages.includes("decrypt") &&
    record.iv instanceof ArrayBuffer &&
    record.iv.byteLength === DEVICE_IV_BYTES &&
    record.ciphertext instanceof ArrayBuffer &&
    record.ciphertext.byteLength === VAULT_KEY_BYTES + 16
  );
}

function cloneRecord(record: DeviceUnlockRecord): DeviceUnlockRecord {
  return {
    ...record,
    iv: record.iv.slice(0),
    ciphertext: record.ciphertext.slice(0)
  };
}

function requestResult<T>(request: IDBRequest<T>, message: string): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error(message));
  });
}

function transactionComplete(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(
      transaction.error ?? new Error("Trusted-device transaction aborted")
    );
    transaction.onerror = () => reject(
      transaction.error ?? new Error("Trusted-device transaction failed")
    );
  });
}

export const VAULT_DATABASE_NAME = "diyvm-local-passkey-vault";
export const VAULT_DATABASE_VERSION = 1;
export const VAULT_SCHEMA_VERSION = 1 as const;

const METADATA_STORE = "metadata";
const CREDENTIAL_STORE = "credentials";
const VAULT_METADATA_KEY = "vault";
const MAX_CREDENTIALS = 10_000;
const MAX_ENCRYPTED_CREDENTIAL_BYTES = 256 * 1024;
const MAX_WRAPPED_KEY_BYTES = 4 * 1024;

export interface VaultMetadataRecord {
  key: typeof VAULT_METADATA_KEY;
  schemaVersion: typeof VAULT_SCHEMA_VERSION;
  kdf: {
    algorithm: "ARGON2ID" | "PBKDF2-SHA-256";
    iterations: number;
    salt: ArrayBuffer;
  };
  wrappedVaultKey: {
    algorithm: "AES-256-GCM";
    iv: ArrayBuffer;
    ciphertext: ArrayBuffer;
  };
  createdAt: number;
  updatedAt: number;
}

export interface EncryptedCredentialRecord {
  credentialId: string;
  schemaVersion: typeof VAULT_SCHEMA_VERSION;
  encryptedPayload: {
    algorithm: "AES-256-GCM";
    iv: ArrayBuffer;
    ciphertext: ArrayBuffer;
  };
  createdAt: number;
  updatedAt: number;
}

export interface VaultSnapshot {
  metadata: VaultMetadataRecord;
  credentials: EncryptedCredentialRecord[];
}

export interface OpenVaultDatabaseOptions {
  databaseName?: string;
  indexedDB?: IDBFactory;
}

export class IndexedDbVaultStore {
  private constructor(
    private readonly database: IDBDatabase
  ) {
    this.database.onversionchange = () => {
      this.database.close();
    };
  }

  static async open(
    options: OpenVaultDatabaseOptions = {}
  ): Promise<IndexedDbVaultStore> {
    const factory = options.indexedDB ?? globalThis.indexedDB;
    if (!factory) {
      throw new Error("IndexedDB is unavailable in this extension context");
    }

    const databaseName = options.databaseName ?? VAULT_DATABASE_NAME;
    const request = factory.open(databaseName, VAULT_DATABASE_VERSION);

    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(METADATA_STORE)) {
        database.createObjectStore(METADATA_STORE, { keyPath: "key" });
      }
      if (!database.objectStoreNames.contains(CREDENTIAL_STORE)) {
        database.createObjectStore(CREDENTIAL_STORE, {
          keyPath: "credentialId"
        });
      }
    };

    const database = await requestResult(request, "Unable to open IndexedDB vault");
    return new IndexedDbVaultStore(database);
  }

  close(): void {
    this.database.close();
  }

  async hasVault(): Promise<boolean> {
    return (await this.readMetadata()) !== undefined;
  }

  async readMetadata(): Promise<VaultMetadataRecord | undefined> {
    const transaction = this.database.transaction(METADATA_STORE, "readonly");
    const completed = transactionComplete(transaction);
    const request = transaction
      .objectStore(METADATA_STORE)
      .get(VAULT_METADATA_KEY) as IDBRequest<VaultMetadataRecord | undefined>;
    const record = await requestResult(request, "Unable to read vault metadata");
    await completed;
    return record ? cloneMetadata(record) : undefined;
  }

  async writeMetadata(record: VaultMetadataRecord): Promise<void> {
    validateMetadata(record);
    const transaction = this.database.transaction(METADATA_STORE, "readwrite");
    const completed = transactionComplete(transaction);
    transaction.objectStore(METADATA_STORE).put(cloneMetadata(record));
    await completed;
  }

  async readCredential(
    credentialId: string
  ): Promise<EncryptedCredentialRecord | undefined> {
    validateCredentialId(credentialId);
    const transaction = this.database.transaction(CREDENTIAL_STORE, "readonly");
    const completed = transactionComplete(transaction);
    const request = transaction
      .objectStore(CREDENTIAL_STORE)
      .get(credentialId) as IDBRequest<EncryptedCredentialRecord | undefined>;
    const record = await requestResult(request, "Unable to read credential");
    await completed;
    return record ? cloneCredential(record) : undefined;
  }

  async listCredentials(): Promise<EncryptedCredentialRecord[]> {
    const transaction = this.database.transaction(CREDENTIAL_STORE, "readonly");
    const completed = transactionComplete(transaction);
    const request = transaction
      .objectStore(CREDENTIAL_STORE)
      .getAll() as IDBRequest<EncryptedCredentialRecord[]>;
    const records = await requestResult(request, "Unable to list credentials");
    await completed;
    if (records.length > MAX_CREDENTIALS) {
      throw new Error("IndexedDB vault contains too many credentials");
    }
    records.forEach(validateCredential);
    return records.map(cloneCredential);
  }

  async writeCredential(record: EncryptedCredentialRecord): Promise<void> {
    validateCredential(record);
    const transaction = this.database.transaction(CREDENTIAL_STORE, "readwrite");
    const completed = transactionComplete(transaction);
    transaction.objectStore(CREDENTIAL_STORE).put(cloneCredential(record));
    await completed;
  }

  async deleteCredential(credentialId: string): Promise<boolean> {
    validateCredentialId(credentialId);
    const transaction = this.database.transaction(CREDENTIAL_STORE, "readwrite");
    const completed = transactionComplete(transaction);
    const store = transaction.objectStore(CREDENTIAL_STORE);
    const existing = await requestResult(
      store.getKey(credentialId),
      "Unable to inspect credential"
    );
    if (existing !== undefined) {
      store.delete(credentialId);
    }
    await completed;
    return existing !== undefined;
  }

  async exportSnapshot(): Promise<VaultSnapshot | undefined> {
    const transaction = this.database.transaction(
      [METADATA_STORE, CREDENTIAL_STORE],
      "readonly"
    );
    const completed = transactionComplete(transaction);
    const metadataRequest = transaction
      .objectStore(METADATA_STORE)
      .get(VAULT_METADATA_KEY) as IDBRequest<VaultMetadataRecord | undefined>;
    const credentialsRequest = transaction
      .objectStore(CREDENTIAL_STORE)
      .getAll() as IDBRequest<EncryptedCredentialRecord[]>;
    const [metadata, credentials] = await Promise.all([
      requestResult(metadataRequest, "Unable to export vault metadata"),
      requestResult(credentialsRequest, "Unable to export credentials")
    ]);
    await completed;

    if (!metadata) {
      if (credentials.length !== 0) {
        throw new Error("IndexedDB vault has credentials but no metadata");
      }
      return undefined;
    }

    const snapshot = {
      metadata: cloneMetadata(metadata),
      credentials: credentials.map(cloneCredential)
    };
    validateSnapshot(snapshot);
    return snapshot;
  }

  async replaceAll(snapshot: VaultSnapshot): Promise<void> {
    validateSnapshot(snapshot);
    const transaction = this.database.transaction(
      [METADATA_STORE, CREDENTIAL_STORE],
      "readwrite"
    );
    const completed = transactionComplete(transaction);
    const metadataStore = transaction.objectStore(METADATA_STORE);
    const credentialStore = transaction.objectStore(CREDENTIAL_STORE);

    metadataStore.clear();
    credentialStore.clear();
    metadataStore.put(cloneMetadata(snapshot.metadata));
    for (const credential of snapshot.credentials) {
      credentialStore.put(cloneCredential(credential));
    }

    await completed;
  }
}

export async function deleteIndexedDbVault(
  databaseName = VAULT_DATABASE_NAME,
  factory: IDBFactory = globalThis.indexedDB
): Promise<void> {
  if (!factory) {
    throw new Error("IndexedDB is unavailable in this extension context");
  }
  const request = factory.deleteDatabase(databaseName);
  await requestResult(request, "Unable to delete IndexedDB vault");
}

export function validateSnapshot(snapshot: VaultSnapshot): void {
  validateMetadata(snapshot.metadata);
  if (
    !Array.isArray(snapshot.credentials) ||
    snapshot.credentials.length > MAX_CREDENTIALS
  ) {
    throw new Error("Invalid credential collection");
  }

  const credentialIds = new Set<string>();
  for (const credential of snapshot.credentials) {
    validateCredential(credential);
    if (credentialIds.has(credential.credentialId)) {
      throw new Error("Backup contains duplicate credential IDs");
    }
    credentialIds.add(credential.credentialId);
  }
}

function validateMetadata(record: VaultMetadataRecord): void {
  if (
    record.key !== VAULT_METADATA_KEY ||
    record.schemaVersion !== VAULT_SCHEMA_VERSION ||
    (record.kdf.algorithm !== "ARGON2ID" &&
      record.kdf.algorithm !== "PBKDF2-SHA-256") ||
    !Number.isSafeInteger(record.kdf.iterations) ||
    record.kdf.iterations < 1 ||
    record.kdf.iterations > 10_000_000 ||
    !validBufferLength(record.kdf.salt, 16, 64) ||
    record.wrappedVaultKey.algorithm !== "AES-256-GCM" ||
    !validBufferLength(record.wrappedVaultKey.iv, 12, 12) ||
    !validBufferLength(
      record.wrappedVaultKey.ciphertext,
      16,
      MAX_WRAPPED_KEY_BYTES
    ) ||
    !validTimestamps(record.createdAt, record.updatedAt)
  ) {
    throw new Error("Invalid IndexedDB vault metadata");
  }
}

function validateCredential(record: EncryptedCredentialRecord): void {
  validateCredentialId(record.credentialId);
  if (
    record.schemaVersion !== VAULT_SCHEMA_VERSION ||
    record.encryptedPayload.algorithm !== "AES-256-GCM" ||
    !validBufferLength(record.encryptedPayload.iv, 12, 12) ||
    !validBufferLength(
      record.encryptedPayload.ciphertext,
      16,
      MAX_ENCRYPTED_CREDENTIAL_BYTES
    ) ||
    !validTimestamps(record.createdAt, record.updatedAt)
  ) {
    throw new Error("Invalid encrypted credential record");
  }
}

function validateCredentialId(credentialId: string): void {
  if (
    typeof credentialId !== "string" ||
    credentialId.length < 16 ||
    credentialId.length > 1024 ||
    !/^[A-Za-z0-9_-]+$/.test(credentialId)
  ) {
    throw new Error("Invalid credential ID");
  }
}

function validBufferLength(
  value: ArrayBuffer,
  minimum: number,
  maximum: number
): boolean {
  return (
    value instanceof ArrayBuffer &&
    value.byteLength >= minimum &&
    value.byteLength <= maximum
  );
}

function validTimestamps(createdAt: number, updatedAt: number): boolean {
  return (
    Number.isSafeInteger(createdAt) &&
    Number.isSafeInteger(updatedAt) &&
    createdAt >= 0 &&
    updatedAt >= createdAt
  );
}

function cloneMetadata(record: VaultMetadataRecord): VaultMetadataRecord {
  return {
    key: VAULT_METADATA_KEY,
    schemaVersion: VAULT_SCHEMA_VERSION,
    kdf: {
      algorithm: record.kdf.algorithm,
      iterations: record.kdf.iterations,
      salt: record.kdf.salt.slice(0)
    },
    wrappedVaultKey: {
      algorithm: "AES-256-GCM",
      iv: record.wrappedVaultKey.iv.slice(0),
      ciphertext: record.wrappedVaultKey.ciphertext.slice(0)
    },
    createdAt: record.createdAt,
    updatedAt: record.updatedAt
  };
}

function cloneCredential(
  record: EncryptedCredentialRecord
): EncryptedCredentialRecord {
  return {
    credentialId: record.credentialId,
    schemaVersion: VAULT_SCHEMA_VERSION,
    encryptedPayload: {
      algorithm: "AES-256-GCM",
      iv: record.encryptedPayload.iv.slice(0),
      ciphertext: record.encryptedPayload.ciphertext.slice(0)
    },
    createdAt: record.createdAt,
    updatedAt: record.updatedAt
  };
}

function requestResult<T>(
  request: IDBRequest<T>,
  failureMessage: string
): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => {
      reject(new Error(failureMessage, { cause: request.error }));
    };
    if ("onblocked" in request) {
      const blockableRequest = request as unknown as {
        onblocked: ((event: Event) => void) | null;
      };
      blockableRequest.onblocked = () => {
        reject(new Error(`${failureMessage}: database operation is blocked`));
      };
    }
  });
}

function transactionComplete(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => {
      reject(new Error("IndexedDB vault transaction was aborted", {
        cause: transaction.error
      }));
    };
    transaction.onerror = () => {
      // The abort event carries the final transaction error.
    };
  });
}

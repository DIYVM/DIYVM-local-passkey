import assert from "node:assert/strict";
import { afterEach, beforeEach, describe, it } from "node:test";

import "fake-indexeddb/auto";

import {
  IndexedDbVaultStore,
  deleteIndexedDbVault,
  type EncryptedCredentialRecord,
  type VaultMetadataRecord
} from "../src/indexeddb-vault";
import {
  createBackupFileName,
  exportVaultBackup,
  importVaultBackup
} from "../src/vault-backup";

describe("IndexedDbVaultStore", () => {
  let databaseName: string;
  let store: IndexedDbVaultStore;

  beforeEach(async () => {
    databaseName = `diyvm-test-${crypto.randomUUID()}`;
    store = await IndexedDbVaultStore.open({ databaseName });
  });

  afterEach(async () => {
    store.close();
    await deleteIndexedDbVault(databaseName);
  });

  it("round-trips encrypted metadata and credential envelopes", async () => {
    const metadata = makeMetadata();
    const credential = makeCredential("credential_0000000000000001", 7);

    await store.writeMetadata(metadata);
    await store.writeCredential(credential);

    const snapshot = await store.exportSnapshot();
    assert(snapshot);
    assert.deepEqual(
      Array.from(new Uint8Array(snapshot.metadata.kdf.salt)),
      Array.from(new Uint8Array(metadata.kdf.salt))
    );
    assert.equal(snapshot.credentials.length, 1);
    assert.equal(snapshot.credentials[0]?.credentialId, credential.credentialId);
    assert.deepEqual(
      Array.from(
        new Uint8Array(
          snapshot.credentials[0]?.encryptedPayload.ciphertext ?? new ArrayBuffer(0)
        )
      ),
      Array.from(new Uint8Array(credential.encryptedPayload.ciphertext))
    );

    assert.equal(await store.deleteCredential(credential.credentialId), true);
    assert.equal(await store.deleteCredential(credential.credentialId), false);
    assert.deepEqual(await store.listCredentials(), []);
  });

  it("replaces the entire vault in one transaction", async () => {
    await store.replaceAll({
      metadata: makeMetadata(),
      credentials: [
        makeCredential("credential_0000000000000001", 1),
        makeCredential("credential_0000000000000002", 2)
      ]
    });

    await store.replaceAll({
      metadata: makeMetadata(2_000),
      credentials: [makeCredential("credential_0000000000000003", 3)]
    });

    const snapshot = await store.exportSnapshot();
    assert(snapshot);
    assert.equal(snapshot.metadata.createdAt, 2_000);
    assert.deepEqual(
      snapshot.credentials.map((credential) => credential.credentialId),
      ["credential_0000000000000003"]
    );
  });
});

describe("encrypted vault backup", () => {
  let sourceName: string;
  let targetName: string;
  let source: IndexedDbVaultStore;
  let target: IndexedDbVaultStore;

  beforeEach(async () => {
    sourceName = `diyvm-source-${crypto.randomUUID()}`;
    targetName = `diyvm-target-${crypto.randomUUID()}`;
    [source, target] = await Promise.all([
      IndexedDbVaultStore.open({ databaseName: sourceName }),
      IndexedDbVaultStore.open({ databaseName: targetName })
    ]);
  });

  afterEach(async () => {
    source.close();
    target.close();
    await Promise.all([
      deleteIndexedDbVault(sourceName),
      deleteIndexedDbVault(targetName)
    ]);
  });

  it("exports and imports an encrypted, versioned backup", async () => {
    await source.replaceAll({
      metadata: makeMetadata(),
      credentials: [
        makeCredential("credential_0000000000000001", 1),
        makeCredential("credential_0000000000000002", 2)
      ]
    });

    const backup = await exportVaultBackup(
      source,
      new Date("2026-08-01T03:04:05.000Z")
    );
    assert.match(backup, /"format": "diyvm-local-passkey-backup"/);
    assert.doesNotMatch(backup, /privateKey|rpId|userName/);
    assert.equal(
      createBackupFileName(new Date("2026-08-01T03:04:05.000Z")),
      "DIYVM-LocalPasskey-backup-20260801-030405Z.diyvmpasskey.json"
    );

    const result = await importVaultBackup(target, backup);
    assert.equal(result.credentialCount, 2);
    assert.equal(result.exportedAt, "2026-08-01T03:04:05.000Z");

    const restored = await target.exportSnapshot();
    assert(restored);
    assert.deepEqual(
      restored.credentials.map((credential) => credential.credentialId),
      [
        "credential_0000000000000001",
        "credential_0000000000000002"
      ]
    );
  });

  it("rejects a modified backup before replacing existing data", async () => {
    await source.replaceAll({
      metadata: makeMetadata(),
      credentials: [makeCredential("credential_0000000000000001", 1)]
    });
    await target.replaceAll({
      metadata: makeMetadata(2_000),
      credentials: [makeCredential("credential_0000000000000009", 9)]
    });

    const backup = await exportVaultBackup(source);
    const modified = backup.replace(
      "credential_0000000000000001",
      "credential_0000000000000002"
    );
    await assert.rejects(
      () => importVaultBackup(target, modified),
      /完整性校验失败/
    );

    const unchanged = await target.exportSnapshot();
    assert(unchanged);
    assert.equal(
      unchanged.credentials[0]?.credentialId,
      "credential_0000000000000009"
    );
  });
});

function makeMetadata(createdAt = 1_000): VaultMetadataRecord {
  return {
    key: "vault",
    schemaVersion: 1,
    kdf: {
      algorithm: "PBKDF2-SHA-256",
      iterations: 600_000,
      salt: bytes(16, 1)
    },
    wrappedVaultKey: {
      algorithm: "AES-256-GCM",
      iv: bytes(12, 17),
      ciphertext: bytes(48, 33)
    },
    createdAt,
    updatedAt: createdAt
  };
}

function makeCredential(
  credentialId: string,
  seed: number
): EncryptedCredentialRecord {
  return {
    credentialId,
    schemaVersion: 1,
    encryptedPayload: {
      algorithm: "AES-256-GCM",
      iv: bytes(12, seed),
      ciphertext: bytes(96, seed + 12)
    },
    createdAt: 1_000 + seed,
    updatedAt: 1_000 + seed
  };
}

function bytes(length: number, seed: number): ArrayBuffer {
  return Uint8Array.from(
    { length },
    (_, index) => (seed + index) % 256
  ).buffer;
}

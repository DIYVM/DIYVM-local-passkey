import assert from "node:assert/strict";
import { afterEach, beforeEach, describe, it } from "node:test";

import "fake-indexeddb/auto";

import {
  IndexedDbVaultStore,
  deleteIndexedDbVault,
  type VaultMetadataRecord
} from "../src/indexeddb-vault";
import {
  MemoryVaultSessionStorage,
  PureExtensionError,
  PureVault
} from "../src/pure-vault";
import { MemoryVaultSettingsStorage } from "../src/vault-settings";
import {
  exportVaultBackup,
  verifyVaultBackup
} from "../src/vault-backup";

describe("unified password and passkey vault", () => {
  let databaseName: string;
  let store: IndexedDbVaultStore;
  let session: MemoryVaultSessionStorage;
  let settings: MemoryVaultSettingsStorage;
  let vault: PureVault;
  let now: number;

  beforeEach(async () => {
    databaseName = `diyvm-passwords-${crypto.randomUUID()}`;
    store = await IndexedDbVaultStore.open({ databaseName });
    session = new MemoryVaultSessionStorage();
    settings = new MemoryVaultSettingsStorage();
    now = 1_800_000_000_000;
    vault = new PureVault(store, session, () => now, settings);
    await vault.initialize("correct horse battery staple");
  });

  afterEach(async () => {
    store.close();
    await deleteIndexedDbVault(databaseName);
  });

  it("accepts an eight-character master password and rejects seven", async () => {
    const shortDatabaseName = `diyvm-password-policy-${crypto.randomUUID()}`;
    const shortStore = await IndexedDbVaultStore.open({
      databaseName: shortDatabaseName
    });
    const shortVault = new PureVault(
      shortStore,
      new MemoryVaultSessionStorage(),
      () => now,
      new MemoryVaultSettingsStorage()
    );
    try {
      await assert.rejects(
        () => shortVault.initialize("1234567"),
        (error) =>
          error instanceof PureExtensionError &&
          error.code === "INVALID_PASSWORD"
      );
      await shortVault.initialize("12345678");
      assert.equal((await shortVault.status()).vaultState, "unlocked");
    } finally {
      shortStore.close();
      await deleteIndexedDbVault(shortDatabaseName);
    }
  });

  it("creates, updates, audits, trashes, restores, and fills passwords", async () => {
    const created = await vault.savePassword({
      name: "Example",
      origin: "https://example.com/login",
      username: "alice@example.com",
      password: "password",
      tags: ["work"],
      autoFill: true
    });
    assert.equal(created.origin, "https://example.com");
    assert.equal((await vault.status()).passwordCount, 1);

    const summaries = await vault.listPasswords();
    assert.equal(summaries.length, 1);
    assert.equal(summaries[0]?.weak, true);

    now += 1_000;
    const updated = await vault.updatePassword({
      itemId: created.itemId,
      name: "Example account",
      origin: created.origin,
      username: created.username,
      password: "Correct-Horse-Battery-Staple-2026!",
      notes: "encrypted note",
      favorite: true,
      tags: ["work", "primary"],
      autoFill: true
    });
    assert.equal(updated.favorite, true);
    assert.equal((await vault.passwordAudit()).weak, 0);

    now += 1_000;
    const used = await vault.usePassword(created.itemId);
    assert.equal(used.password, "Correct-Horse-Battery-Staple-2026!");
    assert.equal(used.lastUsedAt, Math.floor(now / 1_000));

    await vault.trashItem(created.itemId);
    assert.equal((await vault.listPasswords()).length, 0);
    assert.equal((await vault.listPasswords(true))[0]?.deletedAt !== null, true);
    await vault.restoreItem(created.itemId);
    assert.equal((await vault.listPasswords()).length, 1);
    assert((await vault.listAuditEntries()).length >= 5);
  });

  it("changes the master password and enforces inactivity expiry", async () => {
    await vault.changeMasterPassword(
      "correct horse battery staple",
      "new correct horse battery staple"
    );
    await vault.lock();
    await assert.rejects(
      () => vault.unlock("correct horse battery staple"),
      (error) =>
        error instanceof PureExtensionError &&
        error.code === "INVALID_PASSWORD"
    );
    await vault.unlock("new correct horse battery staple");
    now += 16 * 60 * 1_000;
    assert.equal((await vault.status()).vaultState, "locked");
  });

  it("keeps the vault unlocked only for the active browser session", async () => {
    await vault.updateSettings({ rememberSession: true });
    now += 30 * 24 * 60 * 60 * 1_000;
    assert.equal((await vault.status()).vaultState, "unlocked");
    await vault.lock();
    assert.equal((await vault.status()).vaultState, "locked");
  });

  it("encrypts OSS configuration inside the vault and removes it on disconnect", async () => {
    const configuration = {
      endpoint: "https://oss-cn-hangzhou.aliyuncs.com",
      region: "cn-hangzhou",
      bucket: "diyvm-backup",
      objectKey: "diyvm-local-passkey/vault.json",
      accessKeyId: "LTAIExampleAccessKey",
      accessKeySecret: "exampleAccessKeySecret123456"
    };
    const summary = await vault.saveOssConfiguration(configuration);
    assert.equal(summary.bucket, "diyvm-backup");
    assert.equal(
      (await vault.readOssConfiguration())?.accessKeySecret,
      configuration.accessKeySecret
    );

    const snapshot = await store.exportSnapshot();
    assert(snapshot);
    assert(
      snapshot.credentials.some(
        (record) => record.credentialId === "DIYVM_OSS_CONFIG_V1"
      )
    );
    assert.doesNotMatch(
      JSON.stringify(snapshot),
      /exampleAccessKeySecret123456/u
    );
    const backup = await exportVaultBackup(store);
    assert.doesNotMatch(backup, /exampleAccessKeySecret123456/u);
    assert.equal((await verifyVaultBackup(backup)).itemCount, 0);

    now += 1_000;
    const uploaded = await vault.markOssBackupUploaded(now, "\"etag-value\"");
    assert.equal(uploaded.lastUploadedAt, now);
    assert.equal(uploaded.lastEtag, "\"etag-value\"");
    assert.equal(await vault.removeOssConfiguration(), true);
    assert.equal(await vault.readOssConfiguration(), undefined);
  });
});

describe("legacy PBKDF2 vault migration", () => {
  it("migrates 0.4.x metadata to Argon2id after a successful unlock", async () => {
    const databaseName = `diyvm-legacy-${crypto.randomUUID()}`;
    const store = await IndexedDbVaultStore.open({ databaseName });
    const password = "legacy correct horse battery staple";
    const vaultKey = crypto.getRandomValues(new Uint8Array(32));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const passwordKey = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    const wrappingKey = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt,
        iterations: 600_000
      },
      passwordKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"]
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const wrappedVaultKey = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: new TextEncoder().encode(
          "diyvm-local-passkey:vault-key:v1"
        )
      },
      wrappingKey,
      vaultKey
    );
    const metadata: VaultMetadataRecord = {
      key: "vault",
      schemaVersion: 1,
      kdf: {
        algorithm: "PBKDF2-SHA-256",
        iterations: 600_000,
        salt: salt.buffer
      },
      wrappedVaultKey: {
        algorithm: "AES-256-GCM",
        iv: iv.buffer,
        ciphertext: wrappedVaultKey
      },
      createdAt: 1_700_000_000_000,
      updatedAt: 1_700_000_000_000
    };
    await store.writeMetadata(metadata);
    const vault = new PureVault(
      store,
      new MemoryVaultSessionStorage(),
      () => 1_800_000_000_000,
      new MemoryVaultSettingsStorage()
    );
    try {
      await vault.unlock(password);
      const migrated = await store.readMetadata();
      assert.equal(migrated?.kdf.algorithm, "ARGON2ID");
      assert.equal(migrated?.kdf.memoryCostKib, 19 * 1024);
      assert.equal((await vault.status()).vaultState, "unlocked");
    } finally {
      vaultKey.fill(0);
      store.close();
      await deleteIndexedDbVault(databaseName);
    }
  });
});

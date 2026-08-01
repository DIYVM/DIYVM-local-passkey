import assert from "node:assert/strict";
import { afterEach, beforeEach, describe, it } from "node:test";

import "fake-indexeddb/auto";

import type {
  SerializedCreationOptions,
  SerializedRequestOptions
} from "../src/types";

import {
  IndexedDbVaultStore,
  deleteIndexedDbVault
} from "../src/indexeddb-vault";
import {
  exportVaultBackup,
  importVaultBackup
} from "../src/vault-backup";
import {
  MemoryVaultSessionStorage,
  PureExtensionError,
  PureVault
} from "../src/pure-vault";
import { SoftwareAuthenticator } from "../src/software-authenticator";
import {
  concatenateBytes,
  decodeBase64Url,
  encodeBase64Url,
  sha256
} from "../src/binary";

describe("pure extension WebAuthn for webauthn.io", () => {
  let databaseName: string;
  let store: IndexedDbVaultStore;
  let session: MemoryVaultSessionStorage;
  let vault: PureVault;
  let authenticator: SoftwareAuthenticator;
  let now: number;

  beforeEach(async () => {
    databaseName = `diyvm-webauthn-${crypto.randomUUID()}`;
    store = await IndexedDbVaultStore.open({ databaseName });
    session = new MemoryVaultSessionStorage();
    now = 1_785_554_400_000;
    vault = new PureVault(store, session, () => now);
    authenticator = new SoftwareAuthenticator(vault, () => now);
    await vault.initialize("correct horse battery staple");
  });

  afterEach(async () => {
    store.close();
    await deleteIndexedDbVault(databaseName);
  });

  it("registers and authenticates a discoverable ES256 credential", async () => {
    const creation = creationOptions();
    const created = await authenticator.makeCredential(
      "https://webauthn.io",
      creation
    );

    assert.equal(created.type, "public-key");
    assert.equal(created.authenticatorAttachment, "platform");
    assert.equal(created.response.publicKeyAlgorithm, -7);
    assert.deepEqual(created.response.transports, ["internal"]);
    assert.deepEqual(created.clientExtensionResults, {
      credProps: { rk: true }
    });

    const clientData = decodeJson(created.response.clientDataJSON);
    assert.deepEqual(clientData, {
      type: "webauthn.create",
      challenge: creation.challenge,
      origin: "https://webauthn.io",
      crossOrigin: false
    });

    const registrationAuthData = new Uint8Array(
      decodeBase64Url(created.response.authenticatorData)
    );
    assert.deepEqual(
      registrationAuthData.slice(0, 32),
      new Uint8Array(await sha256(new TextEncoder().encode("webauthn.io")))
    );
    assert.equal(registrationAuthData[32], 0x45);
    assert.equal(new DataView(registrationAuthData.buffer).getUint32(33), 0);
    const credentialIdLength = new DataView(
      registrationAuthData.buffer
    ).getUint16(53);
    assert.equal(credentialIdLength, 32);
    assert.deepEqual(
      registrationAuthData.slice(55, 55 + credentialIdLength),
      new Uint8Array(decodeBase64Url(created.rawId))
    );

    const decodedAttestation = decodeCbor(
      new Uint8Array(decodeBase64Url(created.response.attestationObject))
    );
    assert(decodedAttestation instanceof Map);
    assert.equal(decodedAttestation.get("fmt"), "none");
    assert(decodedAttestation.get("attStmt") instanceof Map);
    assert.deepEqual(
      decodedAttestation.get("authData"),
      registrationAuthData
    );

    now += 1_000;
    const request: SerializedRequestOptions = {
      challenge: encodeBase64Url(bytes(32, 90)),
      rpId: "webauthn.io",
      userVerification: "required"
    };
    const assertion = await authenticator.getAssertion(
      "https://webauthn.io",
      request
    );

    assert.equal(assertion.id, created.id);
    assert.equal(assertion.response.userHandle, creation.user.id);
    const assertionClientData = decodeJson(
      assertion.response.clientDataJSON
    );
    assert.deepEqual(assertionClientData, {
      type: "webauthn.get",
      challenge: request.challenge,
      origin: "https://webauthn.io",
      crossOrigin: false
    });
    const assertionAuthData = new Uint8Array(
      decodeBase64Url(assertion.response.authenticatorData)
    );
    assert.equal(assertionAuthData.byteLength, 37);
    assert.equal(assertionAuthData[32], 0x05);
    assert.equal(new DataView(assertionAuthData.buffer).getUint32(33), 1);

    const clientDataJsonBytes = decodeBase64Url(
      assertion.response.clientDataJSON
    );
    const signedData = concatenateBytes(
      assertionAuthData,
      await sha256(clientDataJsonBytes)
    );
    const publicKey = await crypto.subtle.importKey(
      "spki",
      decodeBase64Url(created.response.publicKey ?? ""),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      derToRaw(decodeBase64Url(assertion.response.signature)),
      signedData
    );
    assert.equal(valid, true);

    now += 1_000;
    const second = await authenticator.getAssertion(
      "https://webauthn.io",
      {
        ...request,
        challenge: encodeBase64Url(bytes(32, 120)),
        allowCredentials: [
          {
            type: "public-key",
            id: created.id,
            transports: ["internal"]
          }
        ]
      }
    );
    const secondAuthData = new Uint8Array(
      decodeBase64Url(second.response.authenticatorData)
    );
    assert.equal(new DataView(secondAuthData.buffer).getUint32(33), 2);

    const summaries = await vault.listCredentials();
    assert.equal(summaries.length, 1);
    assert.equal(summaries[0]?.rpId, "webauthn.io");
    assert.equal(summaries[0]?.signCount, 2);
  });

  it("encrypts records, stays unlocked, and rejects a wrong password", async () => {
    await authenticator.makeCredential(
      "https://webauthn.io",
      creationOptions()
    );
    const records = await store.listCredentials();
    assert.equal(records.length, 1);
    const ciphertextText = new TextDecoder().decode(
      records[0]?.encryptedPayload.ciphertext
    );
    assert.doesNotMatch(ciphertextText, /webauthn\.io|tester@example\.com/);

    now += 24 * 60 * 60 * 1_000;
    assert.equal((await vault.status()).vaultState, "unlocked");

    await vault.lock();
    assert.equal((await vault.status()).vaultState, "locked");
    await assert.rejects(
      () => vault.unlock("wrong password"),
      (error) =>
        error instanceof PureExtensionError &&
        error.code === "INVALID_PASSWORD"
    );
    await vault.unlock("correct horse battery staple");
    assert.equal((await vault.status()).vaultState, "unlocked");
  });

  it("rejects duplicate and out-of-scope registration requests", async () => {
    const creation = creationOptions();
    const created = await authenticator.makeCredential(
      "https://webauthn.io",
      creation
    );
    await assert.rejects(
      () =>
        authenticator.makeCredential("https://webauthn.io", {
          ...creation,
          challenge: encodeBase64Url(bytes(32, 200)),
          excludeCredentials: [
            {
              type: "public-key",
              id: created.id
            }
          ]
        }),
      (error) =>
        error instanceof PureExtensionError &&
        error.code === "INVALID_STATE"
    );
    await assert.rejects(
      () =>
        authenticator.makeCredential("https://webauthn.io", {
          ...creation,
          rp: { id: "evil.example", name: "Lookalike" }
        }),
      (error) =>
        error instanceof PureExtensionError &&
        error.code === "SECURITY_ERROR"
    );
  });

  it("exports and restores a real encrypted passkey", async () => {
    const created = await authenticator.makeCredential(
      "https://webauthn.io",
      creationOptions()
    );
    const backup = await exportVaultBackup(store);
    assert.doesNotMatch(
      backup,
      /webauthn\.io|tester@example\.com|privateKeyPkcs8/
    );

    const targetName = `diyvm-restored-${crypto.randomUUID()}`;
    const targetStore = await IndexedDbVaultStore.open({
      databaseName: targetName
    });
    try {
      await importVaultBackup(targetStore, backup);
      const targetVault = new PureVault(
        targetStore,
        new MemoryVaultSessionStorage(),
        () => now
      );
      assert.equal((await targetVault.status()).vaultState, "locked");
      await targetVault.unlock("correct horse battery staple");
      const targetAuthenticator = new SoftwareAuthenticator(
        targetVault,
        () => now
      );
      const assertion = await targetAuthenticator.getAssertion(
        "https://webauthn.io",
        {
          challenge: encodeBase64Url(bytes(32, 220)),
          rpId: "webauthn.io",
          allowCredentials: [
            {
              type: "public-key",
              id: created.id,
              transports: ["internal"]
            }
          ]
        }
      );
      assert.equal(assertion.id, created.id);
    } finally {
      targetStore.close();
      await deleteIndexedDbVault(targetName);
    }
  });
});

function creationOptions(): SerializedCreationOptions {
  return {
    rp: {
      id: "webauthn.io",
      name: "webauthn.io"
    },
    user: {
      id: encodeBase64Url(bytes(16, 1)),
      name: "tester@example.com",
      displayName: "DIYVM Tester"
    },
    challenge: encodeBase64Url(bytes(32, 32)),
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },
      { type: "public-key", alg: -257 }
    ],
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      residentKey: "required",
      requireResidentKey: true,
      userVerification: "required"
    },
    attestation: "none",
    extensions: {
      credProps: true
    }
  };
}

function bytes(length: number, seed: number): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(
    { length },
    (_, index) => (seed + index) % 256
  );
}

function decodeJson(value: string): unknown {
  return JSON.parse(
    new TextDecoder().decode(decodeBase64Url(value))
  ) as unknown;
}

function derToRaw(signature: ArrayBuffer): ArrayBuffer {
  const bytes = new Uint8Array(signature);
  assert.equal(bytes[0], 0x30);
  let offset = 2;
  const r = readDerInteger(bytes, offset);
  offset = r.next;
  const s = readDerInteger(bytes, offset);
  const raw = new Uint8Array(64);
  raw.set(r.value.slice(-32), 32 - Math.min(32, r.value.length));
  raw.set(s.value.slice(-32), 64 - Math.min(32, s.value.length));
  return raw.buffer;
}

function readDerInteger(
  bytesValue: Uint8Array<ArrayBuffer>,
  offset: number
): { value: Uint8Array<ArrayBuffer>; next: number } {
  assert.equal(bytesValue[offset], 0x02);
  const length = bytesValue[offset + 1] ?? 0;
  const start = offset + 2;
  return {
    value: bytesValue.slice(start, start + length),
    next: start + length
  };
}

function decodeCbor(
  bytesValue: Uint8Array<ArrayBuffer>
): unknown {
  const decoded = decodeCborAt(bytesValue, 0);
  assert.equal(decoded.next, bytesValue.length);
  return decoded.value;
}

function decodeCborAt(
  bytesValue: Uint8Array<ArrayBuffer>,
  offset: number
): { value: unknown; next: number } {
  const initial = bytesValue[offset];
  assert.notEqual(initial, undefined);
  const major = (initial ?? 0) >>> 5;
  const additional = (initial ?? 0) & 0x1f;
  const length = decodeCborLength(bytesValue, offset + 1, additional);
  let cursor = length.next;

  if (major === 0) {
    return { value: length.value, next: cursor };
  }
  if (major === 1) {
    return { value: -1 - length.value, next: cursor };
  }
  if (major === 2) {
    const end = cursor + length.value;
    return { value: bytesValue.slice(cursor, end), next: end };
  }
  if (major === 3) {
    const end = cursor + length.value;
    return {
      value: new TextDecoder().decode(bytesValue.slice(cursor, end)),
      next: end
    };
  }
  if (major === 4) {
    const values: unknown[] = [];
    for (let index = 0; index < length.value; index += 1) {
      const item = decodeCborAt(bytesValue, cursor);
      values.push(item.value);
      cursor = item.next;
    }
    return { value: values, next: cursor };
  }
  if (major === 5) {
    const map = new Map<unknown, unknown>();
    for (let index = 0; index < length.value; index += 1) {
      const key = decodeCborAt(bytesValue, cursor);
      const value = decodeCborAt(bytesValue, key.next);
      map.set(key.value, value.value);
      cursor = value.next;
    }
    return { value: map, next: cursor };
  }
  throw new Error(`Unsupported CBOR major type ${major}`);
}

function decodeCborLength(
  bytesValue: Uint8Array<ArrayBuffer>,
  offset: number,
  additional: number
): { value: number; next: number } {
  if (additional < 24) {
    return { value: additional, next: offset };
  }
  if (additional === 24) {
    return { value: bytesValue[offset] ?? 0, next: offset + 1 };
  }
  if (additional === 25) {
    return {
      value: new DataView(bytesValue.buffer).getUint16(offset),
      next: offset + 2
    };
  }
  if (additional === 26) {
    return {
      value: new DataView(bytesValue.buffer).getUint32(offset),
      next: offset + 4
    };
  }
  throw new Error("Unsupported CBOR length");
}

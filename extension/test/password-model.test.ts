import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  auditPasswords,
  generatePassword,
  normalizeCredentialOrigin,
  passwordStrength
} from "../src/password-model";

describe("password model", () => {
  it("normalizes HTTPS origins and rejects unsafe addresses", () => {
    assert.equal(
      normalizeCredentialOrigin("example.com/login"),
      "https://example.com"
    );
    assert.equal(
      normalizeCredentialOrigin("https://EXAMPLE.com:8443/path"),
      "https://example.com:8443"
    );
    assert.throws(
      () => normalizeCredentialOrigin("http://example.com"),
      /HTTPS/
    );
    assert.throws(
      () => normalizeCredentialOrigin("https://user:pass@example.com"),
      /HTTPS/
    );
  });

  it("generates passwords with selected character groups", () => {
    const generated = generatePassword({
      length: 32,
      uppercase: true,
      lowercase: true,
      numbers: true,
      symbols: true
    });
    assert.equal(generated.length, 32);
    assert.match(generated, /[a-z]/u);
    assert.match(generated, /[A-Z]/u);
    assert.match(generated, /\d/u);
    assert.match(generated, /[^A-Za-z0-9]/u);
    assert.equal(passwordStrength(generated).weak, false);
  });

  it("detects weak, reused, and stale passwords locally", () => {
    const now = 1_800_000_000_000;
    const result = auditPasswords([
      {
        password: "password",
        origin: "https://one.example",
        updatedAt: now,
        deletedAt: null
      },
      {
        password: "password",
        origin: "https://two.example",
        updatedAt: now - 400 * 24 * 60 * 60 * 1_000,
        deletedAt: null
      },
      {
        password: "ignored-in-trash",
        origin: "https://trash.example",
        updatedAt: now,
        deletedAt: now
      }
    ], now);
    assert.deepEqual(result.summary, {
      total: 2,
      weak: 2,
      reused: 2,
      stale: 1,
      insecureOrigins: 0
    });
  });
});

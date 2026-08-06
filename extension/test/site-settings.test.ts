import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  DEFAULT_VAULT_SETTINGS,
  parseVaultSettings
} from "../src/vault-settings";

describe("vault settings parser", () => {
  it("deduplicates origins, rejects unsafe values, and drops legacy site lists", () => {
    const parsed = parseVaultSettings({
      autoLockMinutes: 999,
      lastBackupAt: -1,
      passkeyAllHttps: true,
      enabledAmazonRegions: [
        "amazon.co.jp",
        "amazon.co.jp",
        "amazon.com",
        "amazon.evil",
        "evil.example"
      ],
      autoFillOrigins: [
        "https://example.com",
        "https://example.com",
        "http://example.com",
        "https://user:pass@example.com"
      ]
    });
    assert.deepEqual(parsed, {
      ...DEFAULT_VAULT_SETTINGS,
      passkeyAllHttps: true,
      autoFillOrigins: ["https://example.com"]
    });
    assert.equal("enabledAmazonRegions" in parsed, false);
  });
});

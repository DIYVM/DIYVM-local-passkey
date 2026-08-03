import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  AMAZON_MARKETPLACES,
  amazonMarketplaceForHostname,
  amazonMatchPatterns,
  isAmazonMarketplaceDomain
} from "../src/amazon-sites";
import {
  DEFAULT_VAULT_SETTINGS,
  parseVaultSettings
} from "../src/vault-settings";

describe("Amazon marketplace policy", () => {
  it("recognizes every declared marketplace and its subdomains", () => {
    assert.equal(AMAZON_MARKETPLACES.length, 23);
    for (const marketplace of AMAZON_MARKETPLACES) {
      assert.equal(isAmazonMarketplaceDomain(marketplace.domain), true);
      assert.equal(
        amazonMarketplaceForHostname(`sellercentral.${marketplace.domain}`)
          ?.domain,
        marketplace.domain
      );
      assert.deepEqual(amazonMatchPatterns(marketplace.domain), [
        `https://${marketplace.domain}/*`,
        `https://*.${marketplace.domain}/*`
      ]);
    }
    assert.equal(isAmazonMarketplaceDomain("amazon.example"), false);
    assert.equal(
      amazonMarketplaceForHostname("amazon.co.jp.evil.example"),
      undefined
    );
  });
});

describe("vault settings parser", () => {
  it("deduplicates and rejects unsafe permissions and invalid lock values", () => {
    assert.deepEqual(parseVaultSettings({
      autoLockMinutes: 999,
      lastBackupAt: -1,
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
    }), {
      ...DEFAULT_VAULT_SETTINGS,
      enabledAmazonRegions: ["amazon.co.jp"],
      autoFillOrigins: ["https://example.com"]
    });
  });
});

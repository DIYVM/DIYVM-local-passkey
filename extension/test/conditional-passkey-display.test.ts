import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  conditionalAccountLabel,
  formatConditionalLastUsed,
  maskAccountIdentifier
} from "../src/conditional-passkey-display";

describe("conditional passkey account display", () => {
  it("prefers a user alias without exposing a duplicate account identifier", () => {
    assert.equal(
      conditionalAccountLabel("工作账户", "Ultraman", "user@example.com"),
      "工作账户"
    );
    assert.equal(
      conditionalAccountLabel("", "user@example.com", "user@example.com"),
      "本地账户"
    );
    assert.equal(
      conditionalAccountLabel("\u202E账户", "", "user@example.com"),
      "账户"
    );
  });

  it("masks email, phone, and generic account identifiers", () => {
    assert.equal(maskAccountIdentifier("ultraman@diyvm.com"), "ul***@diyvm.com");
    assert.equal(maskAccountIdentifier("+86 138-0013-8000"), "***8000");
    assert.equal(maskAccountIdentifier("personal-account"), "pe***nt");
  });

  it("formats recent usage without exposing an exact timestamp", () => {
    const now = Date.UTC(2026, 7, 27, 12);
    assert.equal(formatConditionalLastUsed(null, now), "尚未使用");
    assert.equal(formatConditionalLastUsed(now - 60_000, now), "今天使用过");
    assert.equal(
      formatConditionalLastUsed(now - 2 * 24 * 60 * 60 * 1_000, now),
      "2 天前使用"
    );
  });
});

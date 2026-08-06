import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  isExistingMasterPassword,
  isNewMasterPassword,
  masterPasswordCharacterCount
} from "../src/master-password";

describe("master password policy", () => {
  it("requires at least eight Unicode characters for new passwords", () => {
    assert.equal(isNewMasterPassword("1234567"), false);
    assert.equal(isNewMasterPassword("12345678"), true);
    assert.equal(isNewMasterPassword("密码安全可靠足够"), true);
    assert.equal(masterPasswordCharacterCount("🔐🔐🔐🔐🔐🔐🔐🔐"), 8);
  });

  it("accepts shorter legacy passwords only for existing vault unlock", () => {
    assert.equal(isExistingMasterPassword("旧密码"), true);
    assert.equal(isNewMasterPassword("旧密码"), false);
    assert.equal(isExistingMasterPassword(""), false);
  });
});

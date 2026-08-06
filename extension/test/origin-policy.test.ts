import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { allowedPageOrigin } from "../src/origin-policy";

describe("allowedPageOrigin", () => {
  it("accepts normalized HTTPS origins", () => {
    assert.equal(
      allowedPageOrigin("https://example.com/passkey"),
      "https://example.com"
    );
    assert.equal(
      allowedPageOrigin("https://login.example.com/account"),
      "https://login.example.com"
    );
    assert.equal(
      allowedPageOrigin("https://passkeys.dev/demo"),
      "https://passkeys.dev"
    );
    assert.equal(
      allowedPageOrigin("https://accounts.example.co.jp/signin"),
      "https://accounts.example.co.jp"
    );
    assert.equal(
      allowedPageOrigin("https://portal.example.com.au/home"),
      "https://portal.example.com.au"
    );
    assert.equal(
      allowedPageOrigin("https://webauthn.io/"),
      "https://webauthn.io"
    );
    assert.equal(
      allowedPageOrigin("https://login.example.co.uk:8443/passkey"),
      "https://login.example.co.uk:8443"
    );
  });

  it("rejects credentialed, malformed, and insecure URLs", () => {
    assert.equal(allowedPageOrigin("http://example.com/"), undefined);
    assert.equal(allowedPageOrigin("not a URL"), undefined);
    assert.equal(
      allowedPageOrigin("https://user:password@example.com/"),
      undefined
    );
  });
});

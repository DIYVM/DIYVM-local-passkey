import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { allowedPageOrigin } from "../src/origin-policy";

describe("allowedPageOrigin", () => {
  it("accepts the prototype and amazon.com HTTPS origins", () => {
    assert.equal(
      allowedPageOrigin("https://webauthn.io/registration"),
      "https://webauthn.io"
    );
    assert.equal(
      allowedPageOrigin("https://www.amazon.com/ap/signin"),
      "https://www.amazon.com"
    );
    assert.equal(
      allowedPageOrigin("https://amazon.com/"),
      "https://amazon.com"
    );
  });

  it("rejects lookalikes, credentials, ports, and insecure URLs", () => {
    assert.equal(allowedPageOrigin("http://webauthn.io/"), undefined);
    assert.equal(allowedPageOrigin("https://webauthn.io:8443/"), undefined);
    assert.equal(
      allowedPageOrigin("https://amazon.com.evil.example/"),
      undefined
    );
    assert.equal(
      allowedPageOrigin("https://user:password@amazon.com/"),
      undefined
    );
  });
});

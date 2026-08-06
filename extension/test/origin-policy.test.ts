import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { allowedPageOrigin } from "../src/origin-policy";

describe("allowedPageOrigin", () => {
  it("accepts normalized HTTPS origins", () => {
    assert.equal(
      allowedPageOrigin("https://amazon.com/ap/signin"),
      "https://amazon.com"
    );
    assert.equal(
      allowedPageOrigin("https://www.amazon.com/ap/signin"),
      "https://www.amazon.com"
    );
    assert.equal(
      allowedPageOrigin("https://sellercentral.amazon.com/home"),
      "https://sellercentral.amazon.com"
    );
    assert.equal(
      allowedPageOrigin("https://www.amazon.co.jp/ap/signin"),
      "https://www.amazon.co.jp"
    );
    assert.equal(
      allowedPageOrigin("https://sellercentral.amazon.com.au/home"),
      "https://sellercentral.amazon.com.au"
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
    assert.equal(allowedPageOrigin("http://amazon.com/"), undefined);
    assert.equal(allowedPageOrigin("not a URL"), undefined);
    assert.equal(
      allowedPageOrigin("https://user:password@amazon.com/"),
      undefined
    );
  });
});

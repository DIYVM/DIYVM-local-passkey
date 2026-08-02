import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { allowedPageOrigin } from "../src/origin-policy";

describe("allowedPageOrigin", () => {
  it("accepts amazon.com and its HTTPS subdomains", () => {
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
  });

  it("rejects non-Amazon, lookalike, credentialed, and insecure URLs", () => {
    assert.equal(allowedPageOrigin("http://amazon.com/"), undefined);
    assert.equal(allowedPageOrigin("https://amazon.com.evil.example/"), undefined);
    assert.equal(allowedPageOrigin("https://example.com/"), undefined);
    assert.equal(
      allowedPageOrigin("https://user:password@amazon.com/"),
      undefined
    );
  });
});

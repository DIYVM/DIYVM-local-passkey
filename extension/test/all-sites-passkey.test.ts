import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

const sourceRoot = new URL("../src/", import.meta.url);

async function source(name: string): Promise<string> {
  return readFile(new URL(name, sourceRoot), "utf8");
}

describe("optional all-HTTPS passkey mode", () => {
  it("requests the broad host permission only after a user-facing opt-in", async () => {
    const popup = await source("popup.ts");
    const siteAccess = await source("site-access.ts");
    assert.match(popup, /requestAllHttpsPasskeys\(\)/u);
    assert.match(popup, /是否继续申请全站权限/u);
    assert.match(
      siteAccess,
      /chrome\.permissions\.request\(\{\s*origins: \[ALL_HTTPS_MATCH_PATTERN\]/u
    );
  });

  it("registers early top-frame bridges and excludes Amazon duplicate injection", async () => {
    const siteAccess = await source("site-access.ts");
    assert.match(siteAccess, /id: ALL_HTTPS_MAIN_SCRIPT_ID/u);
    assert.match(siteAccess, /id: ALL_HTTPS_ISOLATED_SCRIPT_ID/u);
    assert.match(siteAccess, /excludeMatches: excludedAmazonMatches/u);
    assert.match(siteAccess, /runAt: "document_start"/u);
    assert.match(siteAccess, /world: "MAIN"/u);
    assert.match(siteAccess, /world: "ISOLATED"/u);
    assert.match(siteAccess, /allFrames: false/u);
  });

  it("keeps conditional mediation native and falls back on unsupported requests", async () => {
    const pageBridge = await source("page-bridge.ts");
    const background = await source("background.ts");
    assert.match(pageBridge, /options\.mediation === "conditional"/u);
    assert.match(pageBridge, /request\.fallback\(\)/u);
    assert.match(background, /error\.code === "NOT_SUPPORTED"/u);
    assert.match(background, /error\.code === "SECURITY_ERROR"/u);
    assert.match(background, /"USE_NATIVE_AUTHENTICATOR"/u);
  });
});

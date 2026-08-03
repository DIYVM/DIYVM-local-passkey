import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

const manifestUrl = new URL("../manifest.json", import.meta.url);

interface ExtensionManifest {
  key?: string;
  name?: string;
  version?: string;
  permissions?: string[];
  host_permissions?: string[];
  optional_host_permissions?: string[];
  content_scripts?: Array<{
    all_frames?: boolean;
    js?: string[];
    matches?: string[];
    run_at?: string;
    world?: string;
  }>;
}

async function readManifest(): Promise<ExtensionManifest> {
  return JSON.parse(await readFile(manifestUrl, "utf8")) as ExtensionManifest;
}

describe("pure extension manifest", () => {
  it("uses the production identity and required local-vault permissions", async () => {
    const manifest = await readManifest();
    assert.equal(manifest.name, "DIYVM Local Passkey");
    assert.equal(manifest.version, "1.1.0");
    assert.equal(manifest.key, undefined);
    assert.deepEqual(manifest.permissions, [
      "storage",
      "activeTab",
      "scripting",
      "alarms"
    ]);
  });

  it("limits WebAuthn page access to amazon.com", async () => {
    const manifest = await readManifest();
    assert.deepEqual(manifest.host_permissions, [
      "https://amazon.com/*",
      "https://*.amazon.com/*"
    ]);
  });

  it("keeps global Amazon, autofill, and user-owned OSS access optional", async () => {
    const manifest = await readManifest();
    assert(manifest.optional_host_permissions?.includes(
      "https://amazon.co.jp/*"
    ));
    assert(manifest.optional_host_permissions?.includes(
      "https://amazon.co.uk/*"
    ));
    assert(manifest.optional_host_permissions?.includes("https://*/*"));
  });

  it("injects the direct page bridge before site WebAuthn code", async () => {
    const manifest = await readManifest();
    assert.deepEqual(manifest.content_scripts, [
      {
        matches: [
          "https://amazon.com/*",
          "https://*.amazon.com/*"
        ],
        js: ["page-bridge.js"],
        run_at: "document_start",
        world: "MAIN",
        all_frames: false
      },
      {
        matches: [
          "https://amazon.com/*",
          "https://*.amazon.com/*"
        ],
        js: ["content-script.js"],
        run_at: "document_start",
        world: "ISOLATED",
        all_frames: false
      }
    ]);
  });
});

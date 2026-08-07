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
    assert.equal(manifest.version, "1.2.3");
    assert.equal(manifest.key, undefined);
    assert.deepEqual(manifest.permissions, [
      "storage",
      "activeTab",
      "scripting",
      "alarms"
    ]);
  });

  it("requests no install-time website access", async () => {
    const manifest = await readManifest();
    assert.equal(manifest.host_permissions, undefined);
  });

  it("declares one generic optional HTTPS capability", async () => {
    const manifest = await readManifest();
    assert.deepEqual(manifest.optional_host_permissions, ["https://*/*"]);
  });

  it("does not statically inject scripts into any website", async () => {
    const manifest = await readManifest();
    assert.equal(manifest.content_scripts, undefined);
  });
});

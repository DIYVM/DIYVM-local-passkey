import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

const repositoryRoot = new URL("../../", import.meta.url);
const workflowUrl = new URL(
  ".github/workflows/build-extension.yml",
  repositoryRoot
);

async function workflow(): Promise<string> {
  return readFile(workflowUrl, "utf8");
}

describe("release workflow", () => {
  it("builds the source-map-free Chrome Web Store target", async () => {
    const contents = await workflow();
    assert.match(contents, /run: npm run build:store/u);
    assert.doesNotMatch(contents, /^\s*run: npm run build\s*$/mu);
    assert.match(contents, /Chrome Web Store build contains source maps/u);
  });

  it("uses the Local Passkey product identity for artifacts and releases", async () => {
    const contents = await workflow();
    assert.match(
      contents,
      /DIYVM-Local-Passkey-Chrome-Web-Store-\$\{VERSION\}\.zip/u
    );
    assert.match(contents, /DIYVM Local Passkey \$\{VERSION\}/u);
    assert.doesNotMatch(contents, /Local-Vault-Chrome/u);
  });

  it("validates metadata, archive layout, checksums, and forbidden files", async () => {
    const contents = await workflow();
    assert.match(contents, /Version mismatch/u);
    assert.match(contents, /Store manifest must not contain a key/u);
    assert.match(contents, /grep -cx "manifest\.json"/u);
    assert.match(contents, /sha256sum -c/u);
    assert.match(contents, /node_modules\|src\|test/u);
    assert.match(contents, /key\|pem\|pfx\|p12\|db\|sqlite\|sqlite3/u);
  });
});

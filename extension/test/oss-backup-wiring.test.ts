import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

const sourceRoot = new URL("../src/", import.meta.url);
const extensionRoot = new URL("../", import.meta.url);

async function source(name: string): Promise<string> {
  return readFile(new URL(name, sourceRoot), "utf8");
}

describe("user-owned OSS backup wiring", () => {
  it("requests one exact OSS host only after prominent user consent", async () => {
    const [popup, html, manifestText] = await Promise.all([
      source("popup.ts"),
      source("popup.html"),
      readFile(new URL("manifest.json", extensionRoot), "utf8")
    ]);
    const manifest = JSON.parse(manifestText) as {
      optional_host_permissions?: string[];
    };
    assert(manifest.optional_host_permissions?.includes("https://*/*"));
    assert.match(html, /id="oss-consent"[\s\S]*我确认扩展会把加密备份发送/u);
    assert.match(
      popup,
      /chrome\.permissions\.request\(\{[\s\S]*ossPermissionPattern\(configuration\)/u
    );
  });

  it("keeps the AccessKey secret encrypted and out of popup status", async () => {
    const [vault, types] = await Promise.all([
      source("pure-vault.ts"),
      source("types.ts")
    ]);
    assert.match(
      vault,
      /kind: "oss-configuration"[\s\S]*writeCredential\(await encryptItem/u
    );
    const summary = types.slice(types.indexOf("interface OssConfigurationSummary"));
    assert.doesNotMatch(summary.split("}")[0] ?? "", /accessKeySecret/u);
  });

  it("verifies a bounded remote backup before replacing the local vault", async () => {
    const background = await source("background.ts");
    assert.match(
      background,
      /getObject\(\s*MAX_VAULT_BACKUP_BYTES\s*\)[\s\S]*verifyVaultBackup/u
    );
    assert.match(
      background,
      /downloadAndVerifyOssBackup\(configuration\)[\s\S]*importVaultBackup/u
    );
    assert.match(background, /await opened\.vault\.lock\(\)/u);
  });
});

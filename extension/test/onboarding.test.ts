import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

const sourceRoot = new URL("../src/", import.meta.url);
const backgroundUrl = new URL("../src/background.ts", import.meta.url);
const buildUrl = new URL("../scripts/build.mjs", import.meta.url);

async function source(name: string): Promise<string> {
  return readFile(new URL(name, sourceRoot), "utf8");
}

describe("first-install onboarding", () => {
  it("opens only for a fresh installation, not extension updates", async () => {
    const background = await readFile(backgroundUrl, "utf8");
    assert.match(background, /details\.reason === "install"/u);
    assert.match(
      background,
      /chrome\.tabs\.create\(\{\s*url: chrome\.runtime\.getURL\("onboarding\.html"\)/u
    );
  });

  it("requests optional HTTPS access from the onboarding button", async () => {
    const onboarding = await source("onboarding.ts");
    assert.match(onboarding, /enableButton\.addEventListener\("click"/u);
    assert.match(onboarding, /requestAllHttpsPasskeys\(\)/u);
    assert.match(onboarding, /passkeyAllHttps: true/u);
    assert.match(onboarding, /syncRegisteredContentScripts\(settings\)/u);
    assert.match(onboarding, /chrome\.tabs\.remove\(tab\.id\)/u);
    assert.doesNotMatch(onboarding, /masterPassword/u);
  });

  it("ships the onboarding page and assets in production builds", async () => {
    const build = await readFile(buildUrl, "utf8");
    assert.match(build, /onboarding: "src\/onboarding\.ts"/u);
    assert.match(build, /"src\/onboarding\.html"/u);
    assert.match(build, /"src\/onboarding\.css"/u);
    const html = await source("onboarding.html");
    assert.match(html, /id="enable-passkeys"/u);
    assert.match(html, /暂时跳过/u);
    assert.match(html, /不会保存主密码/u);
  });
});

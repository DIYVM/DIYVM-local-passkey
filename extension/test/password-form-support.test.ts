import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

const sourceRoot = new URL("../src/", import.meta.url);

async function source(name: string): Promise<string> {
  return readFile(new URL(name, sourceRoot), "utf8");
}

describe("password form compatibility wiring", () => {
  it("discovers modal and open shadow-root login fields", async () => {
    const pageActions = await source("page-password-actions.ts");
    assert.match(pageActions, /shadowRoot/u);
    assert.match(pageActions, /aria-modal/u);
    assert.match(pageActions, /role="dialog"/u);
    assert.match(pageActions, /focusedTarget/u);
    assert.match(pageActions, /进入下一步后请再次点击填充密码/u);
  });

  it("inspects frames without secrets before filling one selected frame", async () => {
    const background = await source("background.ts");
    assert.match(background, /allFrames: true/u);
    assert.match(
      background,
      /args: \["", "", expectedOrigin, true, allowInsecureHttp\]/u
    );
    assert.match(
      background,
      /frameIds: \[target\.frameId\][\s\S]*credential\.password/u
    );
  });

  it("requires explicit confirmation for HTTP capture, save, and fill", async () => {
    const background = await source("background.ts");
    assert.match(background, /requireInsecureHttpConfirmation/u);
    assert.match(
      background,
      /HTTP 页面连接未加密，请确认风险后再手动填充/u
    );
    assert.match(
      background,
      /HTTP 页面连接未加密，请确认风险后再读取登录表单/u
    );

    const popup = await source("popup.ts");
    assert.match(popup, /confirmInsecureHttp: insecureHttp/u);
    assert.match(popup, /每次填充都会再次提醒风险/u);
  });

  it("runs persistent autofill in matching child frames", async () => {
    const siteAccess = await source("site-access.ts");
    const autoFillRegistration = siteAccess.slice(
      siteAccess.indexOf("id: autoFillScriptId(origin)")
    );
    assert.match(autoFillRegistration, /allFrames: true/u);

    const autoFill = await source("password-autofill.ts");
    assert.doesNotMatch(autoFill, /window\.top === window/u);
  });
});

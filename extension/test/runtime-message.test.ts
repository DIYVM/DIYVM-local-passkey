import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";

import { sendRuntimeMessage } from "../src/runtime-message.js";

const originalChrome = Object.getOwnPropertyDescriptor(globalThis, "chrome");

afterEach(() => {
  if (originalChrome) {
    Object.defineProperty(globalThis, "chrome", originalChrome);
  } else {
    Reflect.deleteProperty(globalThis, "chrome");
  }
});

describe("extension runtime messaging", () => {
  it("returns successful background responses", async () => {
    installChrome(async () => ({ ok: true }));
    assert.deepEqual(
      await sendRuntimeMessage<{ ok: boolean }>({ type: "test" }),
      { ok: true }
    );
  });

  it("turns a synchronously invalidated extension context into a rejection", async () => {
    installChrome(() => {
      throw new Error("Extension context invalidated.");
    });
    await assert.rejects(
      () => sendRuntimeMessage({ type: "test" }),
      /Extension context invalidated/u
    );
  });

  it("rejects before sending when the runtime context has no extension ID", async () => {
    installChrome(async () => ({ ok: true }), "");
    await assert.rejects(
      () => sendRuntimeMessage({ type: "test" }),
      /扩展环境已更新或失效/u
    );
  });
});

function installChrome(
  sendMessage: (message: unknown) => unknown,
  id = "test-extension-id"
): void {
  Object.defineProperty(globalThis, "chrome", {
    configurable: true,
    value: {
      runtime: {
        id,
        sendMessage
      }
    }
  });
}

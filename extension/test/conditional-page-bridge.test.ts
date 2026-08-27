import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";

import type { ExtensionBridgeResponse } from "../src/bridge-messages";

const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
const originalNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
const originalLocation = Object.getOwnPropertyDescriptor(globalThis, "location");

afterEach(() => {
  restoreGlobal("window", originalWindow);
  restoreGlobal("navigator", originalNavigator);
  restoreGlobal("location", originalLocation);
});

describe("conditional page bridge", () => {
  it("starts native Conditional UI and lets a local assertion win", async () => {
    const harness = await installHarness();
    const result = harness.credentials.get(conditionalOptions());
    const request = harness.webAuthnRequest();

    assert.equal(request.mediation, "conditional");
    assert.equal(harness.nativeSignal?.aborted, false);

    harness.dispatchExtension(localAssertion(request.requestId));
    const credential = await result;
    assert.equal((credential as PublicKeyCredential).id, "local-credential");
    assert.equal(harness.nativeSignal?.aborted, true);
  });

  it("keeps waiting for Chrome when the local path falls back", async () => {
    const harness = await installHarness();
    const result = harness.credentials.get(conditionalOptions());
    const request = harness.webAuthnRequest();
    const nativeCredential = { id: "native-credential" } as Credential;

    harness.dispatchExtension({
      channel: "local-passkey:webauthn:v1",
      source: "extension",
      kind: "response",
      requestId: request.requestId,
      ok: false,
      error: {
        code: "USE_NATIVE_AUTHENTICATOR",
        message: "Use Chrome"
      }
    });
    harness.resolveNative(nativeCredential);

    assert.equal(await result, nativeCredential);
    assert.equal(harness.nativeSignal?.aborted, false);
  });

  it("cancels the local candidate when native Conditional UI wins", async () => {
    const harness = await installHarness();
    const result = harness.credentials.get(conditionalOptions());
    const request = harness.webAuthnRequest();
    const nativeCredential = { id: "native-first" } as Credential;

    harness.resolveNative(nativeCredential);

    assert.equal(await result, nativeCredential);
    assert(
      harness.messages.some(
        (message) =>
          message.kind === "cancel" &&
          message.requestId === request.requestId
      )
    );
  });
});

type PostedMessage = {
  kind?: string;
  requestId?: string;
  mediation?: string;
  [key: string]: unknown;
};

async function installHarness(): Promise<{
  credentials: CredentialsContainer;
  messages: PostedMessage[];
  nativeSignal: AbortSignal | undefined;
  resolveNative: (credential: Credential | null) => void;
  dispatchExtension: (response: ExtensionBridgeResponse) => void;
  webAuthnRequest: () => PostedMessage & { requestId: string };
}> {
  const fakeWindow = new FakeWindow();
  let resolveNative: (credential: Credential | null) => void = () => undefined;
  let rejectNative: (error: unknown) => void = () => undefined;
  let nativeSignal: AbortSignal | undefined;
  const nativeRequest = new Promise<Credential | null>((resolve, reject) => {
    resolveNative = resolve;
    rejectNative = reject;
  });
  const credentials = {
    create: async () => null,
    get: (options?: CredentialRequestOptions) => {
      nativeSignal = options?.signal;
      nativeSignal?.addEventListener(
        "abort",
        () => rejectNative(new DOMException("Aborted", "AbortError")),
        { once: true }
      );
      return nativeRequest;
    }
  } as unknown as CredentialsContainer;

  defineGlobal("window", fakeWindow);
  defineGlobal("navigator", { credentials });
  defineGlobal("location", { origin: "https://example.com" });

  await import(
    `${new URL("../src/page-bridge.ts", import.meta.url).href}?test=${crypto.randomUUID()}`
  );

  return {
    credentials,
    messages: fakeWindow.messages,
    get nativeSignal() {
      return nativeSignal;
    },
    resolveNative,
    dispatchExtension: (response) => fakeWindow.dispatch(response),
    webAuthnRequest: () => {
      const request = fakeWindow.messages.find(
        (message) => message.kind === "request"
      );
      assert(request && typeof request.requestId === "string");
      return request as PostedMessage & { requestId: string };
    }
  };
}

class FakeWindow {
  readonly messages: PostedMessage[] = [];
  private readonly messageListeners: Array<(event: MessageEvent<unknown>) => void> = [];

  addEventListener(
    type: string,
    listener: EventListenerOrEventListenerObject
  ): void {
    if (type !== "message" || typeof listener !== "function") {
      return;
    }
    this.messageListeners.push(
      listener as (event: MessageEvent<unknown>) => void
    );
  }

  postMessage(message: PostedMessage): void {
    this.messages.push(message);
  }

  dispatch(data: ExtensionBridgeResponse): void {
    const event = {
      source: this,
      origin: "https://example.com",
      data
    } as unknown as MessageEvent<unknown>;
    for (const listener of this.messageListeners) {
      listener(event);
    }
  }
}

function conditionalOptions(): CredentialRequestOptions {
  return {
    mediation: "conditional",
    publicKey: {
      challenge: Uint8Array.from({ length: 32 }, (_, index) => index).buffer,
      rpId: "example.com",
      allowCredentials: [],
      userVerification: "required"
    }
  };
}

function localAssertion(requestId: string): ExtensionBridgeResponse {
  return {
    channel: "local-passkey:webauthn:v1",
    source: "extension",
    kind: "response",
    requestId,
    ok: true,
    operation: "get",
    credential: {
      id: "local-credential",
      rawId: "AA",
      type: "public-key",
      authenticatorAttachment: "platform",
      response: {
        clientDataJSON: "e30",
        authenticatorData: "AA",
        signature: "AA",
        userHandle: null
      },
      clientExtensionResults: {}
    }
  };
}

function defineGlobal(name: string, value: unknown): void {
  Object.defineProperty(globalThis, name, {
    configurable: true,
    value
  });
}

function restoreGlobal(
  name: string,
  descriptor: PropertyDescriptor | undefined
): void {
  if (descriptor) {
    Object.defineProperty(globalThis, name, descriptor);
  } else {
    Reflect.deleteProperty(globalThis, name);
  }
}

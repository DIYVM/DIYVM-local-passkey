import type { ExtensionErrorCode } from "./types";

import {
  BRIDGE_CHANNEL,
  type BackgroundCancelRequest,
  type BackgroundWebAuthnRequest,
  type ExtensionBridgeResponse,
  type PageBridgeMessage
} from "./bridge-messages";
import { sendRuntimeMessage } from "./runtime-message";

const MAX_BRIDGE_MESSAGE_BYTES = 512 * 1024;
const REQUEST_ID_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
const activeRequests = new Set<string>();

if (window.top === window && location.protocol === "https:") {
  window.addEventListener("message", handlePageMessage);
}

function handlePageMessage(event: MessageEvent<unknown>): void {
  if (
    event.source !== window ||
    event.origin !== location.origin ||
    !isPageBridgeMessage(event.data)
  ) {
    return;
  }

  const message = event.data;

  if (message.kind === "cancel") {
    if (activeRequests.delete(message.requestId)) {
      const cancel: BackgroundCancelRequest = {
        kind: "localPasskeyCancel",
        requestId: message.requestId
      };
      void sendRuntimeMessage(cancel).catch(() => undefined);
    }
    return;
  }

  if (
    activeRequests.has(message.requestId) ||
    !isBoundedPublicKey(message.publicKey)
  ) {
    postError(message.requestId, "INVALID_MESSAGE", "请求格式无效");
    return;
  }

  activeRequests.add(message.requestId);
  const request: BackgroundWebAuthnRequest = {
    kind: "localPasskeyWebAuthn",
    requestId: message.requestId,
    operation: message.operation,
    publicKey: message.publicKey
  };

  void sendRuntimeMessage<ExtensionBridgeResponse>(request)
    .then((response: ExtensionBridgeResponse) => {
      if (activeRequests.delete(message.requestId)) {
        window.postMessage(response, location.origin);
      }
    })
    .catch((error: unknown) => {
      if (activeRequests.delete(message.requestId)) {
        postError(
          message.requestId,
          "INTERNAL_ERROR",
          runtimeFailureMessage(error)
        );
      }
    });
}

function runtimeFailureMessage(error: unknown): string {
  const detail =
    error instanceof Error
      ? error.message
      : typeof error === "string"
        ? error
        : "未知通信错误";
  return `DIYVM Local Passkey 后台通信失败：${detail}。请刷新网页后重试`;
}

function postError(
  requestId: string,
  code: ExtensionErrorCode,
  message: string
): void {
  const response: ExtensionBridgeResponse = {
    channel: BRIDGE_CHANNEL,
    source: "extension",
    kind: "response",
    requestId,
    ok: false,
    error: { code, message }
  };
  window.postMessage(response, location.origin);
}

function isPageBridgeMessage(value: unknown): value is PageBridgeMessage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const message = value as Partial<PageBridgeMessage>;
  if (
    message.channel !== BRIDGE_CHANNEL ||
    message.source !== "page" ||
    !REQUEST_ID_PATTERN.test(message.requestId ?? "")
  ) {
    return false;
  }
  if (message.kind === "cancel") {
    return true;
  }
  return (
    message.kind === "request" &&
    (message.operation === "create" || message.operation === "get") &&
    typeof message.publicKey === "object" &&
    message.publicKey !== null
  );
}

function isBoundedPublicKey(value: unknown): boolean {
  try {
    const serialized = JSON.stringify(value);
    return (
      serialized.length > 0 &&
      new TextEncoder().encode(serialized).byteLength <= MAX_BRIDGE_MESSAGE_BYTES
    );
  } catch {
    return false;
  }
}

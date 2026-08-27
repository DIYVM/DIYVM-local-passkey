import type { ExtensionErrorCode } from "./types";

import {
  BRIDGE_CHANNEL,
  type BackgroundCancelRequest,
  type BackgroundConditionalProbeRequest,
  type BackgroundConditionalProbeResponse,
  type BackgroundWebAuthnRequest,
  type ExtensionBridgeResponse,
  type PageBridgeMessage,
  type PageBridgeRequest
} from "./bridge-messages";
import { sendRuntimeMessage } from "./runtime-message";

const MAX_BRIDGE_MESSAGE_BYTES = 512 * 1024;
const REQUEST_ID_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
const activeRequests = new Set<string>();
const conditionalRequests = new Map<string, ConditionalRequest>();

type ConditionalRequest = {
  message: Extract<PageBridgeRequest, { operation: "get" }>;
  activated: boolean;
  disposePrompt?: () => void;
};

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
      disposeConditionalRequest(message.requestId);
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
  if (
    message.operation === "get" &&
    message.mediation === "conditional"
  ) {
    startConditionalRequest(message);
    return;
  }

  sendWebAuthnRequest(message);
}

function sendWebAuthnRequest(message: PageBridgeRequest): void {
  const request: BackgroundWebAuthnRequest = {
    kind: "localPasskeyWebAuthn",
    requestId: message.requestId,
    operation: message.operation,
    publicKey: message.publicKey
  };

  void sendRuntimeMessage<ExtensionBridgeResponse>(request)
    .then((response: ExtensionBridgeResponse) => {
      if (activeRequests.delete(message.requestId)) {
        disposeConditionalRequest(message.requestId);
        window.postMessage(response, location.origin);
      }
    })
    .catch((error: unknown) => {
      if (activeRequests.delete(message.requestId)) {
        disposeConditionalRequest(message.requestId);
        postError(
          message.requestId,
          "INTERNAL_ERROR",
          runtimeFailureMessage(error)
        );
      }
    });
}

function startConditionalRequest(
  message: Extract<PageBridgeRequest, { operation: "get" }>
): void {
  for (const [requestId, request] of conditionalRequests) {
    if (requestId === message.requestId) {
      continue;
    }
    if (request.activated) {
      const cancel: BackgroundCancelRequest = {
        kind: "localPasskeyCancel",
        requestId
      };
      void sendRuntimeMessage(cancel).catch(() => undefined);
    }
    activeRequests.delete(requestId);
    disposeConditionalRequest(requestId);
    postError(
      requestId,
      "USE_NATIVE_AUTHENTICATOR",
      "页面发起了新的条件式请求，继续使用 Chrome 或系统验证器"
    );
  }

  const state: ConditionalRequest = {
    message,
    activated: false
  };
  conditionalRequests.set(message.requestId, state);
  void probeConditionalRequest(state);
}

async function probeConditionalRequest(
  state: ConditionalRequest
): Promise<void> {
  const request: BackgroundConditionalProbeRequest = {
    kind: "localPasskeyConditionalProbe",
    requestId: state.message.requestId,
    publicKey: state.message.publicKey
  };
  try {
    const response = await sendRuntimeMessage<BackgroundConditionalProbeResponse>(
      request
    );
    if (
      conditionalRequests.get(state.message.requestId) !== state ||
      !activeRequests.has(state.message.requestId)
    ) {
      return;
    }
    if (!response.ok || !response.available) {
      finishConditionalWithNative(
        state,
        response.ok
          ? "当前 RP ID 没有可用的 DIYVM Passkey"
          : response.error
      );
      return;
    }
    state.disposePrompt = showConditionalPasskeyPrompt(() => {
      activateConditionalRequest(state);
    });
  } catch (error) {
    if (conditionalRequests.get(state.message.requestId) === state) {
      finishConditionalWithNative(state, runtimeFailureMessage(error));
    }
  }
}

function activateConditionalRequest(state: ConditionalRequest): void {
  if (
    state.activated ||
    conditionalRequests.get(state.message.requestId) !== state ||
    !activeRequests.has(state.message.requestId)
  ) {
    return;
  }
  state.activated = true;
  state.disposePrompt?.();
  delete state.disposePrompt;
  sendWebAuthnRequest(state.message);
}

function finishConditionalWithNative(
  state: ConditionalRequest,
  message: string
): void {
  if (conditionalRequests.get(state.message.requestId) !== state) {
    return;
  }
  activeRequests.delete(state.message.requestId);
  disposeConditionalRequest(state.message.requestId);
  postError(
    state.message.requestId,
    "USE_NATIVE_AUTHENTICATOR",
    `${message}；继续使用 Chrome 或系统验证器`
  );
}

function disposeConditionalRequest(requestId: string): void {
  const request = conditionalRequests.get(requestId);
  if (!request) {
    return;
  }
  conditionalRequests.delete(requestId);
  request.disposePrompt?.();
}

function showConditionalPasskeyPrompt(onActivate: () => void): () => void {
  const host = document.createElement("div");
  host.setAttribute("aria-hidden", "false");
  host.style.setProperty("position", "fixed", "important");
  host.style.setProperty("z-index", "2147483647", "important");
  host.style.setProperty("margin", "0", "important");
  host.style.setProperty("padding", "0", "important");
  host.style.setProperty("border", "0", "important");
  host.style.setProperty("width", "auto", "important");
  host.style.setProperty("height", "auto", "important");
  host.style.setProperty("pointer-events", "auto", "important");

  const shadow = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = `
    :host { all: initial; color-scheme: light dark; }
    button {
      all: initial;
      box-sizing: border-box;
      display: inline-flex;
      align-items: center;
      justify-content: flex-start;
      gap: 8px;
      width: 100%;
      min-height: 36px;
      padding: 6px 11px 6px 7px;
      border: 1px solid rgba(72, 126, 218, .58);
      border-radius: 9px;
      background: color-mix(in srgb, Canvas 94%, #1d5fc4 6%);
      color: CanvasText;
      box-shadow: 0 8px 24px rgba(8, 32, 74, .18), 0 2px 6px rgba(8, 32, 74, .12);
      font: 600 12px/1.2 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      letter-spacing: .01em;
      cursor: pointer;
      white-space: nowrap;
      user-select: none;
    }
    button:hover { border-color: #2873db; background: color-mix(in srgb, Canvas 88%, #2873db 12%); }
    button:focus-visible { outline: 3px solid rgba(45, 126, 235, .34); outline-offset: 2px; }
    .mark {
      display: grid;
      place-items: center;
      width: 23px;
      height: 23px;
      border-radius: 7px;
      background: linear-gradient(145deg, #153d83, #2f83df);
      color: white;
      font: 800 14px/1 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
  `;
  const button = document.createElement("button");
  button.type = "button";
  button.setAttribute("aria-label", "使用 DIYVM 本地通行密钥登录");
  button.title = "使用 DIYVM 本地通行密钥登录";
  const mark = document.createElement("span");
  mark.className = "mark";
  mark.textContent = "D";
  const label = document.createElement("span");
  label.textContent = "使用 DIYVM Passkey";
  button.append(mark, label);
  shadow.append(style, button);

  let disposed = false;
  let frame = 0;
  let focusedInput: HTMLInputElement | undefined;
  const observer = new MutationObserver((records) => {
    if (
      records.some(
        (record) => record.target !== host && !host.contains(record.target)
      )
    ) {
      schedulePosition();
    }
  });

  const stopPageHandling = (event: Event): void => {
    event.stopPropagation();
  };
  button.addEventListener("pointerdown", stopPageHandling);
  button.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    onActivate();
  });

  const onFocus = (event: FocusEvent): void => {
    const input = event.composedPath().find(
      (item): item is HTMLInputElement => item instanceof HTMLInputElement
    );
    if (input && scoreLoginInput(input) > 0) {
      focusedInput = input;
      schedulePosition();
    }
  };
  const onViewportChange = (): void => schedulePosition();

  document.addEventListener("focusin", onFocus, true);
  window.addEventListener("resize", onViewportChange);
  window.addEventListener("scroll", onViewportChange, true);
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ["autocomplete", "class", "hidden", "style", "type"]
  });
  document.documentElement.append(host);
  schedulePosition();

  function schedulePosition(): void {
    if (disposed || frame !== 0) {
      return;
    }
    frame = requestAnimationFrame(() => {
      frame = 0;
      positionPrompt();
    });
  }

  function positionPrompt(): void {
    const input =
      focusedInput && isVisibleInput(focusedInput)
        ? focusedInput
        : findBestLoginInput();
    if (!input) {
      host.style.setProperty("width", "190px", "important");
      host.style.setProperty("right", "18px", "important");
      host.style.setProperty("bottom", "18px", "important");
      host.style.removeProperty("left");
      host.style.removeProperty("top");
      return;
    }

    const rect = input.getBoundingClientRect();
    const promptWidth = Math.min(
      Math.max(rect.width, 178),
      Math.max(178, window.innerWidth - 16)
    );
    const promptHeight = 38;
    const left = Math.min(
      window.innerWidth - promptWidth - 8,
      Math.max(8, rect.left)
    );
    let top = rect.bottom + 6;
    if (top + promptHeight > window.innerHeight - 8) {
      top = Math.max(8, rect.top - promptHeight - 6);
    }
    host.style.setProperty("width", `${Math.round(promptWidth)}px`, "important");
    host.style.setProperty("left", `${Math.round(left)}px`, "important");
    host.style.setProperty("top", `${Math.round(top)}px`, "important");
    host.style.removeProperty("right");
    host.style.removeProperty("bottom");
  }

  return () => {
    if (disposed) {
      return;
    }
    disposed = true;
    if (frame !== 0) {
      cancelAnimationFrame(frame);
    }
    observer.disconnect();
    document.removeEventListener("focusin", onFocus, true);
    window.removeEventListener("resize", onViewportChange);
    window.removeEventListener("scroll", onViewportChange, true);
    host.remove();
  };
}

function findBestLoginInput(): HTMLInputElement | undefined {
  return Array.from(document.querySelectorAll<HTMLInputElement>("input"))
    .filter(isVisibleInput)
    .map((input) => ({ input, score: scoreLoginInput(input) }))
    .filter(({ score }) => score > 0)
    .sort((left, right) => right.score - left.score)[0]?.input;
}

function scoreLoginInput(input: HTMLInputElement): number {
  const autocomplete = input.autocomplete.toLowerCase().split(/\s+/u);
  let score = autocomplete.includes("webauthn") ? 100 : 0;
  if (autocomplete.includes("username")) {
    score += 60;
  }
  if (autocomplete.includes("email")) {
    score += 50;
  }
  if (autocomplete.includes("current-password")) {
    score += 35;
  }
  if (input.type === "email") {
    score += 30;
  } else if (input.type === "password") {
    score += 20;
  } else if (input.type === "text" || input.type === "") {
    score += 10;
  }
  return score;
}

function isVisibleInput(input: HTMLInputElement): boolean {
  if (
    !input.isConnected ||
    input.disabled ||
    input.type === "hidden" ||
    input.hidden
  ) {
    return false;
  }
  const rect = input.getBoundingClientRect();
  const style = getComputedStyle(input);
  return (
    rect.width >= 80 &&
    rect.height >= 20 &&
    style.display !== "none" &&
    style.visibility !== "hidden"
  );
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
  const mediation = (message as { mediation?: unknown }).mediation;
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
    (mediation === undefined ||
      (message.operation === "get" && mediation === "conditional")) &&
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

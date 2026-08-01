import type {
  CredentialSummary,
  ExtensionErrorCode,
  SerializedAssertionCredential,
  SerializedCreatedCredential,
  SerializedCreationOptions,
  SerializedRequestOptions,
  VaultState
} from "./types";

import {
  BRIDGE_CHANNEL,
  type BackgroundCancelRequest,
  type BackgroundWebAuthnRequest,
  type ExtensionBridgeResponse
} from "./bridge-messages";
import {
  isConfirmationId,
  type ConfirmationDetails,
  type ConfirmationMessage,
  type ConfirmationResponse
} from "./confirmation-messages";
import { allowedPageOrigin } from "./origin-policy";
import { PureExtensionError, openPureVault } from "./pure-vault";
import { SoftwareAuthenticator } from "./software-authenticator";

const extensionVersion = chrome.runtime.getManifest().version;
const CONFIRMATION_TIMEOUT_MS = 120_000;

interface ExtensionStatus {
  extensionVersion: string;
  platform: "Chrome Extension";
  vaultState: VaultState;
  credentialCount: number;
}

type PopupRequest =
  | {
      type: "getExtensionStatus" | "lockVault";
    }
  | {
      type: "initializeVault" | "unlockVault";
      masterPassword: string;
    }
  | {
      type: "deleteCredential";
      credentialId: string;
    };

type PopupResponse =
  | {
      ok: true;
      status: ExtensionStatus;
      credentials: CredentialSummary[];
    }
  | {
      ok: false;
      error: string;
      status?: ExtensionStatus;
      credentials?: CredentialSummary[];
    };

type ConfirmationResult = {
  decision: "local" | "fallback" | "cancel";
  credentialId?: string;
};

type PendingConfirmation = {
  bridgeRequestId: string;
  details: ConfirmationDetails;
  resolve: (result: ConfirmationResult) => void;
  timeout: ReturnType<typeof setTimeout>;
  windowId?: number;
};

const activeCeremonies = new Set<string>();
const canceledCeremonies = new Set<string>();
const pendingConfirmations = new Map<string, PendingConfirmation>();
const confirmationWindows = new Map<number, string>();

chrome.windows.onRemoved.addListener((windowId) => {
  const confirmationId = confirmationWindows.get(windowId);
  if (confirmationId) {
    finishConfirmation(confirmationId, { decision: "cancel" }, false);
  }
});

chrome.runtime.onInstalled.addListener(() => {
  void chrome.storage.session
    .setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" })
    .catch(() => undefined);
});

chrome.runtime.onMessage.addListener(
  (
    message: unknown,
    sender: chrome.runtime.MessageSender,
    sendResponse: (response: unknown) => void
  ) => {
    if (sender.id !== chrome.runtime.id) {
      return false;
    }

    if (
      isConfirmationMessage(message) &&
      isTrustedConfirmationSender(sender)
    ) {
      void handleConfirmationMessage(message).then(sendResponse);
      return true;
    }

    if (isPopupRequest(message) && isTrustedPopupSender(sender)) {
      void handlePopupRequest(message).then(sendResponse);
      return true;
    }

    if (isWebAuthnRequest(message)) {
      void handleWebAuthnRequest(message, sender).then(sendResponse);
      return true;
    }

    if (isCancelRequest(message)) {
      markCanceled(message, sender);
      sendResponse({ ok: true });
      return false;
    }

    return false;
  }
);

async function handlePopupRequest(message: PopupRequest): Promise<PopupResponse> {
  const opened = await openPureVault();
  try {
    if (message.type === "initializeVault") {
      await opened.vault.initialize(message.masterPassword);
    } else if (message.type === "unlockVault") {
      await opened.vault.unlock(message.masterPassword);
    } else if (message.type === "lockVault") {
      await opened.vault.lock();
    } else if (message.type === "deleteCredential") {
      await opened.vault.deleteCredential(message.credentialId);
    }

    const status = await extensionStatus(opened.vault);
    const credentials =
      status.vaultState === "unlocked"
        ? await opened.vault.listCredentials()
        : [];
    return { ok: true, status, credentials };
  } catch (error) {
    const status = await extensionStatus(opened.vault).catch(() => undefined);
    const credentials =
      status?.vaultState === "unlocked"
        ? await opened.vault.listCredentials().catch(() => [])
        : [];
    return {
      ok: false,
      error: errorMessage(error),
      ...(status ? { status } : {}),
      credentials
    };
  } finally {
    opened.close();
  }
}

async function extensionStatus(
  vault: Awaited<ReturnType<typeof openPureVault>>["vault"]
): Promise<ExtensionStatus> {
  const status = await vault.status();
  return {
    extensionVersion,
    platform: "Chrome Extension",
    ...status
  };
}

async function handleWebAuthnRequest(
  message: BackgroundWebAuthnRequest,
  sender: chrome.runtime.MessageSender
): Promise<ExtensionBridgeResponse> {
  const origin = allowedSenderOrigin(sender);
  const ceremonyKey = requestKey(sender, message.requestId);
  if (!origin || !ceremonyKey || activeCeremonies.has(ceremonyKey)) {
    return bridgeError(message.requestId, "SECURITY_ERROR", "请求来源不受信任");
  }

  activeCeremonies.add(ceremonyKey);
  try {
    const credential = await performCeremony(
      message.requestId,
      message.operation,
      origin,
      message.publicKey
    );
    if (canceledCeremonies.has(ceremonyKey)) {
      return bridgeError(message.requestId, "ABORTED", "请求已取消");
    }
    return message.operation === "create"
      ? {
          channel: BRIDGE_CHANNEL,
          source: "extension",
          kind: "response",
          requestId: message.requestId,
          ok: true,
          operation: "create",
          credential: credential as SerializedCreatedCredential
        }
      : {
          channel: BRIDGE_CHANNEL,
          source: "extension",
          kind: "response",
          requestId: message.requestId,
          ok: true,
          operation: "get",
          credential: credential as SerializedAssertionCredential
        };
  } catch (error) {
    return bridgeErrorFromException(message.requestId, error);
  } finally {
    activeCeremonies.delete(ceremonyKey);
    canceledCeremonies.delete(ceremonyKey);
  }
}

async function performCeremony(
  bridgeRequestId: string,
  operation: "create" | "get",
  origin: string,
  publicKey: SerializedCreationOptions | SerializedRequestOptions
): Promise<SerializedCreatedCredential | SerializedAssertionCredential> {
  const opened = await openPureVault();
  try {
    const status = await opened.vault.status();
    if (status.vaultState === "notInitialized") {
      throw new PureExtensionError(
        "VAULT_NOT_INITIALIZED",
        "尚未创建纯插件凭据库"
      );
    }
    if (status.vaultState !== "unlocked") {
      throw new PureExtensionError(
        "VAULT_LOCKED",
        "纯插件凭据库已锁定，请先点击插件图标解锁"
      );
    }

    const authenticator = new SoftwareAuthenticator(opened.vault);
    const details =
      operation === "create"
        ? await authenticator.creationDetails(
            origin,
            publicKey as SerializedCreationOptions
          )
        : await authenticator.assertionDetails(
            origin,
            publicKey as SerializedRequestOptions
          );
    const confirmation = await requestConfirmation(
      bridgeRequestId,
      details
    );
    if (confirmation.decision === "fallback") {
      throw new PureExtensionError(
        "USE_NATIVE_AUTHENTICATOR",
        "用户选择使用 Chrome 或系统验证器"
      );
    }
    if (confirmation.decision !== "local") {
      throw new PureExtensionError("ABORTED", "用户取消了本次操作");
    }

    const credential =
      operation === "create"
        ? await authenticator.makeCredential(
            origin,
            publicKey as SerializedCreationOptions
          )
        : await authenticator.getAssertion(
            origin,
            publicKey as SerializedRequestOptions,
            confirmation.credentialId
          );
    return credential;
  } finally {
    // Do not close IndexedDB until credential generation and persistence finish.
    opened.close();
  }
}

async function requestConfirmation(
  bridgeRequestId: string,
  details: ConfirmationDetails
): Promise<ConfirmationResult> {
  const confirmationId = crypto.randomUUID().replaceAll("-", "");
  const result = new Promise<ConfirmationResult>((resolve) => {
    const timeout = setTimeout(() => {
      finishConfirmation(confirmationId, { decision: "cancel" });
    }, CONFIRMATION_TIMEOUT_MS);
    pendingConfirmations.set(confirmationId, {
      bridgeRequestId,
      details,
      resolve,
      timeout
    });
  });

  try {
    const created = await chrome.windows.create({
      url: chrome.runtime.getURL(
        `confirmation.html?id=${encodeURIComponent(confirmationId)}`
      ),
      type: "popup",
      focused: true,
      width: 460,
      height: 620
    });
    const pending = pendingConfirmations.get(confirmationId);
    if (!pending || created.id === undefined) {
      finishConfirmation(confirmationId, { decision: "cancel" });
    } else {
      pending.windowId = created.id;
      confirmationWindows.set(created.id, confirmationId);
    }
  } catch {
    finishConfirmation(confirmationId, { decision: "cancel" }, false);
  }

  return result;
}

async function handleConfirmationMessage(
  message: ConfirmationMessage
): Promise<ConfirmationResponse> {
  const pending = pendingConfirmations.get(message.confirmationId);
  if (!pending) {
    return { ok: false, error: "确认请求不存在或已经结束" };
  }
  if (message.type === "getConfirmation") {
    return { ok: true, details: pending.details };
  }

  if (
    message.decision === "local" &&
    pending.details.operation === "get" &&
    !pending.details.credentials.some(
      (credential) => credential.credentialId === message.credentialId
    )
  ) {
    return { ok: false, error: "所选凭据不属于当前确认请求" };
  }

  finishConfirmation(message.confirmationId, {
    decision: message.decision,
    ...(message.credentialId
      ? { credentialId: message.credentialId }
      : {})
  });
  return { ok: true };
}

function finishConfirmation(
  confirmationId: string,
  result: ConfirmationResult,
  closeWindow = true
): void {
  const pending = pendingConfirmations.get(confirmationId);
  if (!pending) {
    return;
  }
  pendingConfirmations.delete(confirmationId);
  clearTimeout(pending.timeout);
  if (pending.windowId !== undefined) {
    confirmationWindows.delete(pending.windowId);
    if (closeWindow) {
      void chrome.windows.remove(pending.windowId).catch(() => undefined);
    }
  }
  pending.resolve(result);
}

function cancelConfirmation(bridgeRequestId: string): void {
  for (const [confirmationId, pending] of pendingConfirmations) {
    if (pending.bridgeRequestId === bridgeRequestId) {
      finishConfirmation(confirmationId, { decision: "cancel" });
    }
  }
}

function markCanceled(
  message: BackgroundCancelRequest,
  sender: chrome.runtime.MessageSender
): void {
  const ceremonyKey = requestKey(sender, message.requestId);
  if (ceremonyKey && activeCeremonies.has(ceremonyKey)) {
    canceledCeremonies.add(ceremonyKey);
    cancelConfirmation(message.requestId);
  }
}

function bridgeErrorFromException(
  requestId: string,
  error: unknown
): ExtensionBridgeResponse {
  if (error instanceof PureExtensionError) {
    if (
      error.code === "VAULT_LOCKED" ||
      error.code === "VAULT_NOT_INITIALIZED" ||
      error.code === "CREDENTIAL_NOT_FOUND"
    ) {
      return bridgeError(
        requestId,
        "USE_NATIVE_AUTHENTICATOR",
        `${error.message}；将改用 Chrome 或系统验证器`
      );
    }
    return bridgeError(requestId, error.code, error.message);
  }
  return bridgeError(
    requestId,
    "INTERNAL_ERROR",
    `DIYVM Local Passkey 生成凭据失败：${errorMessage(error)}`
  );
}

function bridgeError(
  requestId: string,
  code: ExtensionErrorCode,
  message: string
): ExtensionBridgeResponse {
  return {
    channel: BRIDGE_CHANNEL,
    source: "extension",
    kind: "response",
    requestId,
    ok: false,
    error: { code, message }
  };
}

function allowedSenderOrigin(
  sender: chrome.runtime.MessageSender
): string | undefined {
  if (sender.frameId !== 0 || !sender.tab || !sender.url) {
    return undefined;
  }
  return allowedPageOrigin(sender.url);
}

function requestKey(
  sender: chrome.runtime.MessageSender,
  requestId: string
): string | undefined {
  if (
    sender.tab?.id === undefined ||
    !/^[A-Za-z0-9_-]{16,128}$/u.test(requestId)
  ) {
    return undefined;
  }
  return `${sender.tab.id}:${sender.frameId ?? 0}:${requestId}`;
}

function isPopupRequest(value: unknown): value is PopupRequest {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const message = value as {
    type?: unknown;
    masterPassword?: unknown;
    credentialId?: unknown;
  };
  if (message.type === "getExtensionStatus" || message.type === "lockVault") {
    return true;
  }
  if (message.type === "initializeVault" || message.type === "unlockVault") {
    const passwordBytes =
      typeof message.masterPassword === "string"
        ? new TextEncoder().encode(message.masterPassword).byteLength
        : 0;
    return passwordBytes >= 12 && passwordBytes <= 1024;
  }
  return (
    message.type === "deleteCredential" &&
    typeof message.credentialId === "string" &&
    /^[A-Za-z0-9_-]{16,136}$/u.test(message.credentialId)
  );
}

function isConfirmationMessage(
  value: unknown
): value is ConfirmationMessage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const message = value as Partial<ConfirmationMessage>;
  if (!isConfirmationId(message.confirmationId)) {
    return false;
  }
  if (message.type === "getConfirmation") {
    return true;
  }
  return (
    message.type === "resolveConfirmation" &&
    (message.decision === "local" ||
      message.decision === "fallback" ||
      message.decision === "cancel") &&
    (message.credentialId === undefined ||
      (typeof message.credentialId === "string" &&
        /^[A-Za-z0-9_-]{16,136}$/u.test(message.credentialId)))
  );
}

function isTrustedPopupSender(sender: chrome.runtime.MessageSender): boolean {
  return (
    sender.id === chrome.runtime.id &&
    sender.tab === undefined &&
    sender.url === chrome.runtime.getURL("popup.html")
  );
}

function isTrustedConfirmationSender(
  sender: chrome.runtime.MessageSender
): boolean {
  return (
    sender.id === chrome.runtime.id &&
    typeof sender.url === "string" &&
    sender.url.startsWith(chrome.runtime.getURL("confirmation.html?"))
  );
}

function isWebAuthnRequest(
  value: unknown
): value is BackgroundWebAuthnRequest {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const message = value as Partial<BackgroundWebAuthnRequest>;
  return (
    message.kind === "localPasskeyWebAuthn" &&
    typeof message.requestId === "string" &&
    (message.operation === "create" || message.operation === "get") &&
    typeof message.publicKey === "object" &&
    message.publicKey !== null
  );
}

function isCancelRequest(value: unknown): value is BackgroundCancelRequest {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const message = value as Partial<BackgroundCancelRequest>;
  return (
    message.kind === "localPasskeyCancel" &&
    typeof message.requestId === "string"
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

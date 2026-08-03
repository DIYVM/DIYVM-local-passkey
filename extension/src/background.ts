import type {
  CredentialSummary,
  ExtensionErrorCode,
  PasswordDetails,
  PasswordInput,
  PasswordSummary,
  SerializedAssertionCredential,
  SerializedCreatedCredential,
  SerializedCreationOptions,
  SerializedRequestOptions,
  VaultSettings,
  VaultStatus
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
import {
  type AuditEntry,
  PureExtensionError,
  openPureVault
} from "./pure-vault";
import {
  captureLoginFormInPage,
  fillPasswordInPage,
  type CapturedLoginForm,
  type PasswordFillResult
} from "./page-password-actions";
import { syncRegisteredContentScripts } from "./site-access";
import { SoftwareAuthenticator } from "./software-authenticator";
import { ChromeVaultSettingsStorage } from "./vault-settings";

const extensionVersion = chrome.runtime.getManifest().version;
const CONFIRMATION_TIMEOUT_MS = 120_000;
const AUTO_LOCK_ALARM = "diyvm-local-vault-auto-lock";

interface ExtensionStatus extends VaultStatus {
  extensionVersion: string;
  platform: "Chrome Extension";
  credentialCount: number;
  currentOrigin: string | null;
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
    }
  | {
      type: "changeMasterPassword";
      currentPassword: string;
      newPassword: string;
    }
  | {
      type: "savePassword" | "updatePassword";
      password: PasswordInput;
    }
  | {
      type: "getPasswordDetails" | "fillPassword";
      itemId: string;
    }
  | {
      type: "updatePasskeyMetadata";
      credentialId: string;
      alias?: string;
      favorite?: boolean;
      tags?: string[];
    }
  | {
      type: "trashItem" | "restoreItem" | "deleteItemPermanently";
      itemId: string;
    }
  | {
      type: "updateSettings";
      settings: Partial<VaultSettings>;
    }
  | {
      type: "captureLoginForm" | "syncSiteAccess" | "recordBackupExport";
    };

type PopupResponse =
  | {
      ok: true;
      status: ExtensionStatus;
      credentials: CredentialSummary[];
      passwords: PasswordSummary[];
      auditEntries: AuditEntry[];
      passwordDetails?: PasswordDetails;
      capturedLogin?: CapturedLoginForm;
      fillResult?: PasswordFillResult;
    }
  | {
      ok: false;
      error: string;
      status?: ExtensionStatus;
      credentials?: CredentialSummary[];
      passwords?: PasswordSummary[];
      auditEntries?: AuditEntry[];
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
  void syncSiteAccessFromSettings();
});

chrome.runtime.onStartup.addListener(() => {
  void syncSiteAccessFromSettings();
});

chrome.permissions.onAdded.addListener(() => {
  void syncSiteAccessFromSettings();
});

chrome.permissions.onRemoved.addListener(() => {
  void pruneAndSyncSiteAccess();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === AUTO_LOCK_ALARM) {
    void lockVaultFromAlarm();
  }
});

void syncSiteAccessFromSettings();

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

    if (
      isAutoFillRequest(message) &&
      isTrustedAutoFillSender(sender)
    ) {
      void handleAutoFillRequest(sender).then(sendResponse);
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
    let passwordDetails: PasswordDetails | undefined;
    let capturedLogin: CapturedLoginForm | undefined;
    let fillResult: PasswordFillResult | undefined;

    if (message.type === "initializeVault") {
      await opened.vault.initialize(message.masterPassword);
      await scheduleAutoLock();
    } else if (message.type === "unlockVault") {
      await opened.vault.unlock(message.masterPassword);
      await scheduleAutoLock();
    } else if (message.type === "lockVault") {
      await opened.vault.lock();
      await chrome.alarms.clear(AUTO_LOCK_ALARM);
    } else if (message.type === "deleteCredential") {
      await opened.vault.deleteCredential(message.credentialId);
    } else if (message.type === "changeMasterPassword") {
      await opened.vault.changeMasterPassword(
        message.currentPassword,
        message.newPassword
      );
      await scheduleAutoLock();
    } else if (message.type === "savePassword") {
      passwordDetails = await opened.vault.savePassword(message.password);
      await scheduleAutoLock();
    } else if (message.type === "updatePassword") {
      passwordDetails = await opened.vault.updatePassword(message.password);
      await scheduleAutoLock();
    } else if (message.type === "getPasswordDetails") {
      passwordDetails = await opened.vault.readPassword(message.itemId);
      if (!passwordDetails) {
        throw new PureExtensionError(
          "CREDENTIAL_NOT_FOUND",
          "找不到密码条目"
        );
      }
      await scheduleAutoLock();
    } else if (message.type === "fillPassword") {
      const credential = await opened.vault.readPassword(message.itemId);
      if (!credential || credential.deletedAt !== null) {
        throw new PureExtensionError(
          "CREDENTIAL_NOT_FOUND",
          "找不到可用的密码条目"
        );
      }
      fillResult = await fillPasswordInActiveTab(credential);
      await opened.vault.usePassword(message.itemId);
    } else if (message.type === "captureLoginForm") {
      capturedLogin = await captureLoginFromActiveTab();
    } else if (message.type === "updatePasskeyMetadata") {
      await opened.vault.updatePasskeyMetadata(
        message.credentialId,
        {
          ...(message.alias === undefined ? {} : { alias: message.alias }),
          ...(message.favorite === undefined
            ? {}
            : { favorite: message.favorite }),
          ...(message.tags === undefined ? {} : { tags: message.tags })
        }
      );
      await scheduleAutoLock();
    } else if (message.type === "trashItem") {
      await opened.vault.trashItem(message.itemId);
    } else if (message.type === "restoreItem") {
      await opened.vault.restoreItem(message.itemId);
    } else if (message.type === "deleteItemPermanently") {
      await opened.vault.deleteItemPermanently(message.itemId);
    } else if (message.type === "updateSettings") {
      const settings = await opened.vault.updateSettings(message.settings);
      await syncRegisteredContentScripts(settings);
      await scheduleAutoLock();
    } else if (message.type === "syncSiteAccess") {
      await syncSiteAccessFromSettings();
    } else if (message.type === "recordBackupExport") {
      const settings = await opened.vault.updateSettings({
        lastBackupAt: Date.now()
      });
      if ((await opened.vault.status()).vaultState === "unlocked") {
        await opened.vault.recordAudit("backup-exported", "vault");
      }
      await syncRegisteredContentScripts(settings);
    }

    const status = await extensionStatus(opened.vault);
    const snapshot = await popupSnapshot(opened.vault, status);
    if (status.vaultState === "unlocked") {
      await scheduleAutoLock();
    }
    return {
      ok: true,
      status,
      ...snapshot,
      ...(passwordDetails ? { passwordDetails } : {}),
      ...(capturedLogin ? { capturedLogin } : {}),
      ...(fillResult ? { fillResult } : {})
    };
  } catch (error) {
    const status = await extensionStatus(opened.vault).catch(() => undefined);
    const snapshot = status
      ? await popupSnapshot(opened.vault, status).catch(() => ({
          credentials: [],
          passwords: [],
          auditEntries: []
        }))
      : undefined;
    return {
      ok: false,
      error: errorMessage(error),
      ...(status ? { status } : {}),
      ...(snapshot ?? {})
    };
  } finally {
    opened.close();
  }
}

async function extensionStatus(
  vault: Awaited<ReturnType<typeof openPureVault>>["vault"]
): Promise<ExtensionStatus> {
  const status = await vault.status();
  const currentOrigin = await activeTabOrigin();
  return {
    extensionVersion,
    platform: "Chrome Extension",
    ...status,
    currentOrigin
  };
}

async function popupSnapshot(
  vault: Awaited<ReturnType<typeof openPureVault>>["vault"],
  status: ExtensionStatus
): Promise<{
  credentials: CredentialSummary[];
  passwords: PasswordSummary[];
  auditEntries: AuditEntry[];
}> {
  if (status.vaultState !== "unlocked") {
    return { credentials: [], passwords: [], auditEntries: [] };
  }
  const [credentials, passwords, auditEntries] = await Promise.all([
    vault.listCredentials(true),
    vault.listPasswords(true),
    vault.listAuditEntries()
  ]);
  return { credentials, passwords, auditEntries };
}

async function fillPasswordInActiveTab(
  credential: PasswordDetails
): Promise<PasswordFillResult> {
  const tab = await activeTab();
  if (tab.id === undefined || !tab.url) {
    throw new PureExtensionError(
      "NOT_ALLOWED",
      "无法访问当前标签页"
    );
  }
  let origin: string;
  try {
    origin = new URL(tab.url).origin;
  } catch {
    throw new PureExtensionError("SECURITY_ERROR", "当前页面地址无效");
  }
  if (origin !== credential.origin) {
    throw new PureExtensionError(
      "SECURITY_ERROR",
      `该密码只允许填入 ${credential.origin}`
    );
  }
  const inspections = await inspectLoginFrames(tab.id, credential.origin);
  const target = inspections
    .filter(
      (inspection) =>
        inspection.result?.ok &&
        inspection.result.targetScore !== undefined
    )
    .sort((left, right) => {
      const focusDifference =
        Number(right.result?.focusedTarget) -
        Number(left.result?.focusedTarget);
      if (focusDifference !== 0) {
        return focusDifference;
      }
      return (
        (right.result?.targetScore ?? Number.NEGATIVE_INFINITY) -
        (left.result?.targetScore ?? Number.NEGATIVE_INFINITY)
      );
    })[0];
  if (!target) {
    const message =
      inspections.find((inspection) => inspection.frameId === 0)?.result
        ?.message ?? "当前页面没有可填写的登录输入框";
    throw new PureExtensionError("NOT_ALLOWED", message);
  }
  const results = await chrome.scripting.executeScript({
    target: { tabId: tab.id, frameIds: [target.frameId] },
    func: fillPasswordInPage,
    args: [
      credential.username,
      credential.password,
      credential.origin,
      false
    ]
  });
  const result = results[0]?.result as PasswordFillResult | undefined;
  if (!result) {
    throw new PureExtensionError("INTERNAL_ERROR", "页面未返回填充结果");
  }
  if (!result.ok) {
    throw new PureExtensionError("NOT_ALLOWED", result.message);
  }
  return result;
}

async function inspectLoginFrames(
  tabId: number,
  expectedOrigin: string
): Promise<Array<chrome.scripting.InjectionResult<PasswordFillResult>>> {
  try {
    return await chrome.scripting.executeScript({
      target: { tabId, allFrames: true },
      func: fillPasswordInPage,
      args: ["", "", expectedOrigin, true]
    });
  } catch {
    return chrome.scripting.executeScript({
      target: { tabId, frameIds: [0] },
      func: fillPasswordInPage,
      args: ["", "", expectedOrigin, true]
    });
  }
}

async function captureLoginFromActiveTab(): Promise<CapturedLoginForm> {
  const tab = await activeTab();
  if (tab.id === undefined || !tab.url) {
    throw new PureExtensionError(
      "NOT_ALLOWED",
      "无法访问当前标签页"
    );
  }
  const url = new URL(tab.url);
  if (url.protocol !== "https:") {
    throw new PureExtensionError(
      "SECURITY_ERROR",
      "只允许从 HTTPS 页面读取用户主动选择的登录表单"
    );
  }
  let results: Array<chrome.scripting.InjectionResult<
    CapturedLoginForm | undefined
  >>;
  try {
    results = await chrome.scripting.executeScript({
      target: { tabId: tab.id, allFrames: true },
      func: captureLoginFormInPage,
      args: [url.origin]
    });
  } catch {
    results = await chrome.scripting.executeScript({
      target: { tabId: tab.id, frameIds: [0] },
      func: captureLoginFormInPage,
      args: [url.origin]
    });
  }
  const captured = results
    .filter((result) => result.result?.origin === url.origin)
    .sort((left, right) => {
      const focusDifference =
        Number(right.result?.focusedTarget) -
        Number(left.result?.focusedTarget);
      if (focusDifference !== 0) {
        return focusDifference;
      }
      return (
        (right.result?.targetScore ?? Number.NEGATIVE_INFINITY) -
        (left.result?.targetScore ?? Number.NEGATIVE_INFINITY)
      );
    })[0]?.result;
  if (!captured) {
    throw new PureExtensionError(
      "NOT_ALLOWED",
      "当前页面没有已填写的登录表单"
    );
  }
  return captured;
}

async function activeTab(): Promise<chrome.tabs.Tab> {
  const tabs = await chrome.tabs.query({
    active: true,
    lastFocusedWindow: true
  });
  const tab = tabs[0];
  if (!tab) {
    throw new PureExtensionError("NOT_ALLOWED", "找不到当前标签页");
  }
  return tab;
}

async function activeTabOrigin(): Promise<string | null> {
  try {
    const tab = await activeTab();
    if (!tab.url) {
      return null;
    }
    const url = new URL(tab.url);
    return url.protocol === "https:" ? url.origin : null;
  } catch {
    return null;
  }
}

async function handleAutoFillRequest(
  sender: chrome.runtime.MessageSender
): Promise<
  | { ok: true; credential?: PasswordDetails }
  | { ok: false; error: string }
> {
  const origin = sender.url ? new URL(sender.url).origin : undefined;
  if (!origin) {
    return { ok: false, error: "无法验证自动填充来源" };
  }
  const settingsStorage = new ChromeVaultSettingsStorage();
  const settings = await settingsStorage.read();
  if (!settings.autoFillOrigins.includes(origin)) {
    return { ok: false, error: "当前网站没有自动填充授权" };
  }

  const opened = await openPureVault();
  try {
    if ((await opened.vault.status()).vaultState !== "unlocked") {
      return { ok: true };
    }
    const candidates = (await opened.vault.passwordsForOrigin(origin)).filter(
      (credential) => credential.autoFill
    );
    if (candidates.length !== 1) {
      return { ok: true };
    }
    const credential = await opened.vault.usePassword(candidates[0]!.itemId);
    await scheduleAutoLock();
    return { ok: true, credential };
  } catch (error) {
    return { ok: false, error: errorMessage(error) };
  } finally {
    opened.close();
  }
}

async function scheduleAutoLock(): Promise<void> {
  const settings = await new ChromeVaultSettingsStorage().read();
  await chrome.alarms.create(AUTO_LOCK_ALARM, {
    when: Date.now() + settings.autoLockMinutes * 60 * 1_000
  });
}

async function lockVaultFromAlarm(): Promise<void> {
  const opened = await openPureVault();
  try {
    const status = await opened.vault.status();
    if (status.vaultState === "unlocked") {
      await opened.vault.lock();
    }
  } finally {
    opened.close();
    await chrome.alarms.clear(AUTO_LOCK_ALARM);
  }
}

async function syncSiteAccessFromSettings(): Promise<void> {
  const storage = new ChromeVaultSettingsStorage();
  await syncRegisteredContentScripts(await storage.read());
}

async function pruneAndSyncSiteAccess(): Promise<void> {
  const storage = new ChromeVaultSettingsStorage();
  const settings = await storage.read();
  const enabledAmazonRegions: string[] = [];
  for (const domain of settings.enabledAmazonRegions) {
    if (
      await chrome.permissions.contains({
        origins: [`https://${domain}/*`, `https://*.${domain}/*`]
      })
    ) {
      enabledAmazonRegions.push(domain);
    }
  }
  const autoFillOrigins: string[] = [];
  for (const origin of settings.autoFillOrigins) {
    if (
      await chrome.permissions.contains({
        origins: [`${origin}/*`]
      })
    ) {
      autoFillOrigins.push(origin);
    }
  }
  const updated: VaultSettings = {
    ...settings,
    enabledAmazonRegions,
    autoFillOrigins
  };
  await storage.write(updated);
  await syncRegisteredContentScripts(updated);
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
        "尚未创建本地 Vault"
      );
    }
    if (status.vaultState !== "unlocked") {
      throw new PureExtensionError(
        "VAULT_LOCKED",
        "本地 Vault 已锁定，请先点击插件图标解锁"
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
    await scheduleAutoLock();
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
    `DIYVM Local Vault 生成凭据失败：${errorMessage(error)}`
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
  const message = value as Record<string, unknown>;
  if (
    message.type === "getExtensionStatus" ||
    message.type === "lockVault" ||
    message.type === "captureLoginForm" ||
    message.type === "syncSiteAccess" ||
    message.type === "recordBackupExport"
  ) {
    return true;
  }
  if (message.type === "initializeVault" || message.type === "unlockVault") {
    return boundedMasterPassword(message.masterPassword);
  }
  if (message.type === "changeMasterPassword") {
    return (
      boundedMasterPassword(message.currentPassword) &&
      boundedMasterPassword(message.newPassword)
    );
  }
  if (message.type === "savePassword" || message.type === "updatePassword") {
    return isPasswordInput(message.password);
  }
  if (
    message.type === "getPasswordDetails" ||
    message.type === "fillPassword" ||
    message.type === "trashItem" ||
    message.type === "restoreItem" ||
    message.type === "deleteItemPermanently"
  ) {
    return isVaultItemId(message.itemId);
  }
  if (message.type === "deleteCredential") {
    return isVaultItemId(message.credentialId);
  }
  if (message.type === "updatePasskeyMetadata") {
    return (
      isVaultItemId(message.credentialId) &&
      (message.alias === undefined ||
        (typeof message.alias === "string" && message.alias.length <= 128)) &&
      (message.favorite === undefined ||
        typeof message.favorite === "boolean") &&
      (message.tags === undefined ||
        (Array.isArray(message.tags) &&
          message.tags.length <= 20 &&
          message.tags.every(
            (tag) => typeof tag === "string" && tag.length <= 32
          )))
    );
  }
  return (
    message.type === "updateSettings" &&
    typeof message.settings === "object" &&
    message.settings !== null
  );
}

function boundedMasterPassword(value: unknown): value is string {
  const passwordBytes =
    typeof value === "string"
      ? new TextEncoder().encode(value).byteLength
      : 0;
  return passwordBytes >= 12 && passwordBytes <= 1024;
}

function isVaultItemId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^[A-Za-z0-9_-]{16,1024}$/u.test(value)
  );
}

function isPasswordInput(value: unknown): value is PasswordInput {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const input = value as Record<string, unknown>;
  return (
    (input.itemId === undefined || isVaultItemId(input.itemId)) &&
    typeof input.name === "string" &&
    input.name.length <= 128 &&
    typeof input.origin === "string" &&
    input.origin.length <= 2048 &&
    typeof input.username === "string" &&
    input.username.length <= 512 &&
    typeof input.password === "string" &&
    new TextEncoder().encode(input.password).byteLength <= 16 * 1024 &&
    (input.notes === undefined ||
      (typeof input.notes === "string" &&
        new TextEncoder().encode(input.notes).byteLength <= 64 * 1024)) &&
    (input.favorite === undefined || typeof input.favorite === "boolean") &&
    (input.autoFill === undefined || typeof input.autoFill === "boolean") &&
    (input.tags === undefined ||
      (Array.isArray(input.tags) &&
        input.tags.length <= 20 &&
        input.tags.every(
          (tag) => typeof tag === "string" && tag.length <= 32
        )))
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

function isAutoFillRequest(
  value: unknown
): value is { type: "getAutoFillCredential" } {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as { type?: unknown }).type === "getAutoFillCredential"
  );
}

function isTrustedAutoFillSender(
  sender: chrome.runtime.MessageSender
): boolean {
  if (
    sender.id !== chrome.runtime.id ||
    sender.frameId !== 0 ||
    !sender.tab ||
    typeof sender.url !== "string"
  ) {
    return false;
  }
  try {
    const url = new URL(sender.url);
    return (
      url.protocol === "https:" &&
      url.username === "" &&
      url.password === ""
    );
  } catch {
    return false;
  }
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

import type {
  CredentialSummary,
  VaultState
} from "./types";

import { IndexedDbVaultStore } from "./indexeddb-vault";
import {
  MAX_VAULT_BACKUP_BYTES,
  createBackupFileName,
  exportVaultBackup,
  importVaultBackup
} from "./vault-backup";

type PopupRequest =
  | { type: "getExtensionStatus" | "lockVault" }
  | {
      type: "initializeVault" | "unlockVault";
      masterPassword: string;
    }
  | {
      type: "deleteCredential";
      credentialId: string;
    };

interface ExtensionStatus {
  extensionVersion: string;
  platform: "Chrome Extension";
  vaultState: VaultState;
  credentialCount: number;
}

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

const elements = {
  dot: requireElement("status-dot"),
  title: requireElement("status-title"),
  detail: requireElement("status-detail"),
  themeMode: requireElement("theme-mode"),
  extensionVersion: requireElement("extension-version"),
  storageEngine: requireElement("storage-engine"),
  protocolVersion: requireElement("protocol-version"),
  vaultState: requireElement("vault-state"),
  vaultOrbit: requireElement("vault-orbit"),
  vaultOrbitSymbol: requireElement("vault-orbit-symbol"),
  credentialCount: requireElement("credential-count"),
  refresh: requireButton("refresh"),
  vaultForm: requireForm("vault-form"),
  password: requireInput("master-password"),
  vaultAction: requireButton("vault-action"),
  lockVault: requireButton("lock-vault"),
  credentialSection: requireElement("credential-section"),
  credentialList: requireElement("credential-list"),
  credentialEmpty: requireElement("credential-empty"),
  exportBackup: requireButton("export-backup"),
  importBackup: requireButton("import-backup"),
  importBackupFile: requireInput("import-backup-file"),
  backupStatus: requireElement("backup-status")
};

let currentVaultState: VaultState = "notInitialized";
const darkColorScheme = window.matchMedia("(prefers-color-scheme: dark)");

elements.extensionVersion.textContent = chrome.runtime.getManifest().version;
elements.storageEngine.textContent = "IndexedDB";
elements.protocolVersion.textContent = "WebAuthn";
applyColorScheme(darkColorScheme.matches);
darkColorScheme.addEventListener("change", (event) => {
  applyColorScheme(event.matches);
});

elements.refresh.addEventListener("click", () => {
  void sendPopupRequest({ type: "getExtensionStatus" }, "正在刷新状态");
});
elements.vaultForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const masterPassword = elements.password.value;
  if (new TextEncoder().encode(masterPassword).byteLength < 12) {
    showOperationError("主密码至少需要 12 个 UTF-8 字节");
    return;
  }
  const type =
    currentVaultState === "notInitialized" ? "initializeVault" : "unlockVault";
  void sendPopupRequest(
    { type, masterPassword },
    type === "initializeVault"
      ? "正在创建纯插件加密库"
      : "正在解锁纯插件加密库"
  );
});
elements.lockVault.addEventListener("click", () => {
  void sendPopupRequest({ type: "lockVault" }, "正在锁定凭据库");
});
elements.exportBackup.addEventListener("click", () => {
  void exportBackupFile();
});
elements.importBackup.addEventListener("click", () => {
  elements.importBackupFile.value = "";
  elements.importBackupFile.click();
});
elements.importBackupFile.addEventListener("change", () => {
  const file = elements.importBackupFile.files?.[0];
  if (file) {
    void importBackupFile(file);
  }
});

void sendPopupRequest(
  { type: "getExtensionStatus" },
  "正在读取纯插件状态"
);

async function sendPopupRequest(
  request: PopupRequest,
  pendingMessage: string
): Promise<void> {
  setControlsDisabled(true);
  renderPending(pendingMessage);

  try {
    const response = (await chrome.runtime.sendMessage(request)) as PopupResponse;
    if (response.ok) {
      renderStatus(response.status, response.credentials);
    } else {
      if (response.status) {
        renderStatus(response.status, response.credentials ?? []);
      }
      showOperationError(response.error);
    }
  } catch (error) {
    elements.dot.className = "status-dot error";
    elements.title.textContent = "纯插件后台不可用";
    elements.detail.textContent = errorMessage(error);
    renderVaultControls("locked");
    renderCredentials([]);
  } finally {
    elements.password.value = "";
    setControlsDisabled(false);
  }
}

function renderPending(message: string): void {
  elements.dot.className = "status-dot pending";
  elements.title.textContent = message;
  elements.detail.textContent = "请稍候…";
}

function renderStatus(
  status: ExtensionStatus,
  credentials: CredentialSummary[]
): void {
  currentVaultState = status.vaultState;
  elements.dot.className = "status-dot connected";
  elements.title.textContent =
    status.vaultState === "unlocked"
      ? "纯插件已就绪"
      : status.vaultState === "locked"
        ? "纯插件凭据库已锁定"
        : "纯插件等待初始化";
  elements.detail.textContent =
    "密钥运算和加密数据均保留在 Chrome 扩展中";
  elements.vaultState.textContent = vaultLabel(status.vaultState);
  elements.credentialCount.textContent = String(status.credentialCount);
  renderVaultControls(status.vaultState);
  renderCredentials(credentials);
}

function renderVaultControls(state: VaultState): void {
  const isUnlocked = state === "unlocked";
  elements.vaultForm.hidden = isUnlocked;
  elements.lockVault.hidden = !isUnlocked;
  elements.credentialSection.hidden = !isUnlocked;
  elements.vaultOrbit.classList.toggle("is-unlocked", isUnlocked);
  elements.vaultOrbitSymbol.textContent = isUnlocked ? "✓" : "●";
  elements.vaultAction.textContent =
    state === "notInitialized" ? "创建纯插件凭据库" : "解锁凭据库";
  elements.password.autocomplete =
    state === "notInitialized" ? "new-password" : "current-password";
}

function applyColorScheme(isDark: boolean): void {
  document.documentElement.dataset.theme = isDark ? "dark" : "light";
  elements.themeMode.textContent = isDark ? "AUTO / C" : "AUTO / A";
  elements.themeMode.setAttribute(
    "aria-label",
    isDark ? "已自动启用夜间方案 C" : "已自动启用日间方案 A"
  );
}

function renderCredentials(credentials: CredentialSummary[]): void {
  elements.credentialList.replaceChildren();
  elements.credentialEmpty.hidden = credentials.length !== 0;

  for (const credential of credentials) {
    const item = document.createElement("li");
    const details = document.createElement("div");
    const site = document.createElement("strong");
    const account = document.createElement("span");
    const metadata = document.createElement("small");
    const remove = document.createElement("button");

    site.textContent = credential.rpId;
    account.textContent =
      credential.displayName ?? credential.userName ?? "未命名账户";
    metadata.textContent = `使用 ${credential.signCount} 次 · ${formatDate(
      credential.lastUsedAt ?? credential.createdAt
    )}`;
    remove.type = "button";
    remove.className = "delete-credential";
    remove.textContent = "删除";
    remove.setAttribute("aria-label", `删除 ${account.textContent} 的本地凭据`);
    remove.addEventListener("click", () => {
      const confirmed = window.confirm(
        `确定删除 ${credential.rpId} / ${account.textContent} 的本地凭据吗？此操作无法撤销。`
      );
      if (confirmed) {
        void sendPopupRequest(
          {
            type: "deleteCredential",
            credentialId: credential.credentialId
          },
          "正在删除凭据"
        );
      }
    });

    details.append(site, account, metadata);
    item.append(details, remove);
    elements.credentialList.append(item);
  }
}

function setControlsDisabled(disabled: boolean): void {
  for (const button of [
    elements.refresh,
    elements.vaultAction,
    elements.lockVault,
    elements.exportBackup,
    elements.importBackup
  ]) {
    button.disabled = disabled;
  }
  elements.password.disabled = disabled;
  elements.credentialList
    .querySelectorAll<HTMLButtonElement>("button")
    .forEach((button) => {
      button.disabled = disabled;
    });
}

async function exportBackupFile(): Promise<void> {
  setControlsDisabled(true);
  setBackupStatus("正在生成加密备份…");

  let store: IndexedDbVaultStore | undefined;
  try {
    store = await IndexedDbVaultStore.open();
    const backup = await exportVaultBackup(store);
    const downloadUrl = URL.createObjectURL(
      new Blob([backup], { type: "application/json" })
    );
    const link = document.createElement("a");
    link.href = downloadUrl;
    link.download = createBackupFileName();
    link.hidden = true;
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(downloadUrl), 1_000);
    setBackupStatus("加密备份已导出，请将文件保存到安全位置。", "success");
  } catch (error) {
    setBackupStatus(errorMessage(error), "error");
  } finally {
    store?.close();
    setControlsDisabled(false);
  }
}

async function importBackupFile(file: File): Promise<void> {
  if (file.size === 0 || file.size > MAX_VAULT_BACKUP_BYTES) {
    setBackupStatus("备份文件为空或超过 20 MB 限制。", "error");
    elements.importBackupFile.value = "";
    return;
  }

  const confirmed = window.confirm(
    "导入会完整替换当前纯插件加密凭据库。请确认已备份现有数据，是否继续？"
  );
  if (!confirmed) {
    elements.importBackupFile.value = "";
    return;
  }

  setControlsDisabled(true);
  setBackupStatus("正在校验并导入加密备份…");

  let store: IndexedDbVaultStore | undefined;
  try {
    const lockResponse = (await chrome.runtime.sendMessage({
      type: "lockVault"
    })) as PopupResponse;
    if (!lockResponse.ok) {
      throw new Error(lockResponse.error);
    }
    const backup = await file.text();
    store = await IndexedDbVaultStore.open();
    const result = await importVaultBackup(store, backup);
    setBackupStatus(
      `已恢复 ${result.credentialCount} 枚通行密钥，请使用原主密码解锁。`,
      "success"
    );
    await sendPopupRequest(
      { type: "getExtensionStatus" },
      "正在刷新导入结果"
    );
  } catch (error) {
    setBackupStatus(`导入失败：${errorMessage(error)}`, "error");
  } finally {
    store?.close();
    elements.importBackupFile.value = "";
    setControlsDisabled(false);
  }
}

function setBackupStatus(
  message: string,
  state?: "success" | "error"
): void {
  elements.backupStatus.textContent = message;
  if (state) {
    elements.backupStatus.dataset.state = state;
  } else {
    delete elements.backupStatus.dataset.state;
  }
}

function showOperationError(message: string): void {
  elements.dot.className = "status-dot error";
  elements.title.textContent = "操作未完成";
  elements.detail.textContent = message;
}

function vaultLabel(state: VaultState): string {
  switch (state) {
    case "notInitialized":
      return "尚未创建";
    case "locked":
      return "已锁定";
    case "unlocked":
      return "已解锁";
  }
}

function formatDate(timestamp: number): string {
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "short",
    timeStyle: "short"
  }).format(new Date(timestamp * 1_000));
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function requireElement(id: string): HTMLElement {
  const element = document.getElementById(id);
  if (!element) {
    throw new Error(`Missing element #${id}`);
  }
  return element;
}

function requireButton(id: string): HTMLButtonElement {
  const element = requireElement(id);
  if (!(element instanceof HTMLButtonElement)) {
    throw new Error(`#${id} is not a button`);
  }
  return element;
}

function requireInput(id: string): HTMLInputElement {
  const element = requireElement(id);
  if (!(element instanceof HTMLInputElement)) {
    throw new Error(`#${id} is not an input`);
  }
  return element;
}

function requireForm(id: string): HTMLFormElement {
  const element = requireElement(id);
  if (!(element instanceof HTMLFormElement)) {
    throw new Error(`#${id} is not a form`);
  }
  return element;
}

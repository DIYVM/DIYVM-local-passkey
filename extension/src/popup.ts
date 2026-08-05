import type {
  CredentialSummary,
  OssConfigurationSummary,
  OssRemoteBackupInfo,
  PasswordDetails,
  PasswordInput,
  PasswordSummary,
  VaultSettings,
  VaultState,
  VaultStatus
} from "./types";
import type { AuditEntry } from "./pure-vault";

import {
  AMAZON_MARKETPLACES,
  PRIMARY_AMAZON_DOMAIN
} from "./amazon-sites";
import {
  generatePassword,
  normalizeCredentialOrigin,
  passwordStrength
} from "./password-model";
import {
  IndexedDbVaultStore
} from "./indexeddb-vault";
import {
  createBackupFileName,
  exportVaultBackup,
  importVaultBackup,
  MAX_VAULT_BACKUP_BYTES,
  verifyVaultBackup
} from "./vault-backup";
import {
  removeAmazonRegion,
  removeAutoFillOrigin,
  requestAmazonRegion,
  requestAutoFillOrigin
} from "./site-access";
import {
  normalizeOssConfiguration,
  ossPermissionPattern,
  type OssConfigurationInput
} from "./oss-client";

interface ExtensionStatus extends VaultStatus {
  extensionVersion: string;
  platform: "Chrome Extension";
  credentialCount: number;
  currentOrigin: string | null;
  ossConfiguration: OssConfigurationSummary | null;
}

type PopupRequest =
  | { type: "getExtensionStatus" | "lockVault" }
  | {
      type: "initializeVault" | "unlockVault";
      masterPassword: string;
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
      type: "configureOss";
      configuration: OssConfigurationInput;
    }
  | {
      type:
        | "captureLoginForm"
        | "syncSiteAccess"
        | "recordBackupExport"
        | "uploadOssBackup"
        | "inspectOssBackup"
        | "restoreOssBackup"
        | "disconnectOss";
    };

type PopupResponse =
  | {
      ok: true;
      status: ExtensionStatus;
      credentials: CredentialSummary[];
      passwords: PasswordSummary[];
      auditEntries: AuditEntry[];
      passwordDetails?: PasswordDetails;
      capturedLogin?: {
        origin: string;
        title: string;
        username: string;
        password: string;
      };
      fillResult?: {
        ok: boolean;
        usernameFilled: boolean;
        passwordFilled: boolean;
        message: string;
      };
      ossRemoteBackupInfo?: OssRemoteBackupInfo;
    }
  | {
      ok: false;
      error: string;
      status?: ExtensionStatus;
      credentials?: CredentialSummary[];
      passwords?: PasswordSummary[];
      auditEntries?: AuditEntry[];
    };

const elements = {
  dot: requireElement("status-dot"),
  title: requireElement("status-title"),
  detail: requireElement("status-detail"),
  refresh: requireButton("refresh"),
  lockVault: requireButton("lock-vault"),
  vaultForm: requireForm("vault-form"),
  masterPassword: requireInput("master-password"),
  vaultAction: requireButton("vault-action"),
  vaultContent: requireElement("vault-content"),
  passkeyCount: requireElement("passkey-count"),
  passwordCount: requireElement("password-count"),
  riskCount: requireElement("risk-count"),
  autoLockLabel: requireElement("auto-lock-label"),
  extensionVersion: requireElement("extension-version"),
  currentOrigin: requireElement("current-origin"),
  captureLogin: requireButton("capture-login"),
  quickEmpty: requireElement("quick-empty"),
  quickPasswordList: requireElement("quick-password-list"),
  addPassword: requireButton("add-password"),
  passwordSearch: requireInput("password-search"),
  showPasswordTrash: requireInput("show-password-trash"),
  passwordEmpty: requireElement("password-empty"),
  passwordList: requireElement("password-list"),
  passkeySearch: requireInput("passkey-search"),
  showPasskeyTrash: requireInput("show-passkey-trash"),
  passkeyEmpty: requireElement("passkey-empty"),
  passkeyList: requireElement("passkey-list"),
  auditWeak: requireElement("audit-weak"),
  auditReused: requireElement("audit-reused"),
  auditStale: requireElement("audit-stale"),
  auditTrash: requireElement("audit-trash"),
  lastBackup: requireElement("last-backup"),
  exportBackup: requireButton("export-backup"),
  verifyBackup: requireButton("verify-backup"),
  importBackup: requireButton("import-backup"),
  verifyBackupFile: requireInput("verify-backup-file"),
  importBackupFile: requireInput("import-backup-file"),
  backupStatus: requireElement("backup-status"),
  auditLog: requireElement("audit-log"),
  changePasswordForm: requireForm("change-password-form"),
  currentMasterPassword: requireInput("current-master-password"),
  newMasterPassword: requireInput("new-master-password"),
  confirmMasterPassword: requireInput("confirm-master-password"),
  autoLockMinutes: requireSelect("auto-lock-minutes"),
  amazonRegionList: requireElement("amazon-region-list"),
  addAutoFillOriginForm: requireForm("add-autofill-origin-form"),
  autoFillOrigin: requireInput("autofill-origin"),
  autoFillOriginList: requireElement("autofill-origin-list"),
  ossForm: requireForm("oss-form"),
  ossEndpoint: requireInput("oss-endpoint"),
  ossRegion: requireInput("oss-region"),
  ossBucket: requireInput("oss-bucket"),
  ossObjectKey: requireInput("oss-object-key"),
  ossAccessKeyId: requireInput("oss-access-key-id"),
  ossAccessKeySecret: requireInput("oss-access-key-secret"),
  ossConsent: requireInput("oss-consent"),
  ossUpload: requireButton("oss-upload"),
  ossInspect: requireButton("oss-inspect"),
  ossRestore: requireButton("oss-restore"),
  ossDisconnect: requireButton("oss-disconnect"),
  ossSummary: requireElement("oss-summary"),
  ossStatus: requireElement("oss-status"),
  operationStatus: requireElement("operation-status"),
  passwordDialog: requireDialog("password-dialog"),
  passwordForm: requireForm("password-form"),
  passwordDialogTitle: requireElement("password-dialog-title"),
  closePasswordDialog: requireButton("close-password-dialog"),
  cancelPasswordDialog: requireButton("cancel-password-dialog"),
  passwordItemId: requireInput("password-item-id"),
  passwordName: requireInput("password-name"),
  passwordOrigin: requireInput("password-origin"),
  passwordUsername: requireInput("password-username"),
  passwordSecret: requireInput("password-secret"),
  passwordTags: requireInput("password-tags"),
  passwordNotes: requireTextArea("password-notes"),
  passwordFavorite: requireInput("password-favorite"),
  passwordAutoFill: requireInput("password-autofill"),
  togglePassword: requireButton("toggle-password"),
  generatorLength: requireInput("generator-length"),
  generatePassword: requireButton("generate-password"),
  passwordStrength: requireElement("password-strength")
};

let currentStatus: ExtensionStatus | undefined;
let passkeys: CredentialSummary[] = [];
let passwords: PasswordSummary[] = [];
let auditEntries: AuditEntry[] = [];
let busy = false;

const darkColorScheme = window.matchMedia("(prefers-color-scheme: dark)");
applyColorScheme(darkColorScheme.matches);
darkColorScheme.addEventListener("change", (event) => {
  applyColorScheme(event.matches);
});

document.querySelectorAll<HTMLButtonElement>("[data-tab]").forEach((button) => {
  button.addEventListener("click", () => activateTab(button.dataset.tab ?? "quick"));
});

elements.refresh.addEventListener("click", () => {
  void sendPopupRequest({ type: "getExtensionStatus" }, "正在刷新 Vault");
});
elements.lockVault.addEventListener("click", () => {
  void sendPopupRequest({ type: "lockVault" }, "正在锁定 Vault");
});
elements.vaultForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const masterPassword = elements.masterPassword.value;
  if (new TextEncoder().encode(masterPassword).byteLength < 12) {
    setOperationStatus("主密码至少需要 12 个 UTF-8 字节", "error");
    return;
  }
  const type =
    currentStatus?.vaultState === "notInitialized"
      ? "initializeVault"
      : "unlockVault";
  void sendPopupRequest(
    { type, masterPassword },
    type === "initializeVault" ? "正在创建加密 Vault" : "正在解锁 Vault"
  );
});

elements.passwordSearch.addEventListener("input", renderPasswords);
elements.showPasswordTrash.addEventListener("change", renderPasswords);
elements.passkeySearch.addEventListener("input", renderPasskeys);
elements.showPasskeyTrash.addEventListener("change", renderPasskeys);
elements.addPassword.addEventListener("click", () => openPasswordDialog());
elements.captureLogin.addEventListener("click", () => {
  void captureCurrentLogin();
});
elements.closePasswordDialog.addEventListener("click", closePasswordDialog);
elements.cancelPasswordDialog.addEventListener("click", closePasswordDialog);
elements.togglePassword.addEventListener("click", togglePasswordVisibility);
elements.generatePassword.addEventListener("click", () => {
  try {
    elements.passwordSecret.value = generatePassword({
      length: Number(elements.generatorLength.value)
    });
    elements.passwordSecret.type = "text";
    elements.togglePassword.textContent = "隐藏";
    renderPasswordStrength();
  } catch (error) {
    setOperationStatus(errorMessage(error), "error");
  }
});
elements.passwordSecret.addEventListener("input", renderPasswordStrength);
elements.passwordForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void savePasswordFromDialog();
});
elements.exportBackup.addEventListener("click", () => {
  void exportBackupFile();
});
elements.verifyBackup.addEventListener("click", () => {
  elements.verifyBackupFile.value = "";
  elements.verifyBackupFile.click();
});
elements.importBackup.addEventListener("click", () => {
  elements.importBackupFile.value = "";
  elements.importBackupFile.click();
});
elements.verifyBackupFile.addEventListener("change", () => {
  const file = elements.verifyBackupFile.files?.[0];
  if (file) {
    void verifyBackupFile(file);
  }
});
elements.importBackupFile.addEventListener("change", () => {
  const file = elements.importBackupFile.files?.[0];
  if (file) {
    void importBackupFile(file);
  }
});
elements.changePasswordForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void changeMasterPassword();
});
elements.autoLockMinutes.addEventListener("change", () => {
  const value = Number(elements.autoLockMinutes.value);
  if (value === 5 || value === 15 || value === 30 || value === 60) {
    void updateSettings({ autoLockMinutes: value });
  }
});
elements.addAutoFillOriginForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void addAutoFillOrigin();
});
elements.ossForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void configureOss();
});
elements.ossUpload.addEventListener("click", () => {
  void uploadOssBackup();
});
elements.ossInspect.addEventListener("click", () => {
  void inspectOssBackup();
});
elements.ossRestore.addEventListener("click", () => {
  void restoreOssBackup();
});
elements.ossDisconnect.addEventListener("click", () => {
  void disconnectOss();
});

void sendPopupRequest(
  { type: "getExtensionStatus" },
  "正在读取本地 Vault"
);

async function sendPopupRequest(
  request: PopupRequest,
  pendingMessage: string
): Promise<PopupResponse | undefined> {
  if (busy) {
    return undefined;
  }
  setBusy(true);
  renderPending(pendingMessage);
  try {
    const response = await chrome.runtime.sendMessage(request) as PopupResponse;
    if (response.ok) {
      applyResponse(response);
      setOperationStatus("");
      return response;
    }
    if (response.status) {
      applyResponse({
        ok: true,
        status: response.status,
        credentials: response.credentials ?? [],
        passwords: response.passwords ?? [],
        auditEntries: response.auditEntries ?? []
      });
    }
    setOperationStatus(response.error, "error");
    return response;
  } catch (error) {
    elements.dot.className = "status-dot error";
    elements.title.textContent = "扩展后台不可用";
    elements.detail.textContent = errorMessage(error);
    setOperationStatus(errorMessage(error), "error");
    return undefined;
  } finally {
    elements.masterPassword.value = "";
    setBusy(false);
  }
}

function applyResponse(response: Extract<PopupResponse, { ok: true }>): void {
  currentStatus = response.status;
  passkeys = response.credentials;
  passwords = response.passwords;
  auditEntries = response.auditEntries;
  renderAll();
}

function renderAll(): void {
  if (!currentStatus) {
    return;
  }
  const unlocked = currentStatus.vaultState === "unlocked";
  elements.dot.className = "status-dot connected";
  elements.title.textContent =
    currentStatus.vaultState === "notInitialized"
      ? "等待创建本地 Vault"
      : unlocked
        ? "本地 Vault 已解锁"
        : "本地 Vault 已锁定";
  elements.detail.textContent = unlocked
    ? "密码和通行密钥均使用 AES-256-GCM 加密"
    : "解锁后才能读取加密凭据";
  elements.vaultForm.hidden = unlocked;
  elements.vaultContent.hidden = !unlocked;
  elements.lockVault.hidden = !unlocked;
  elements.vaultAction.textContent =
    currentStatus.vaultState === "notInitialized" ? "创建 Vault" : "解锁";
  elements.masterPassword.autocomplete =
    currentStatus.vaultState === "notInitialized"
      ? "new-password"
      : "current-password";
  elements.passkeyCount.textContent = String(currentStatus.passkeyCount);
  elements.passwordCount.textContent = String(currentStatus.passwordCount);
  elements.riskCount.textContent = String(
    currentStatus.passwordAudit.weak + currentStatus.passwordAudit.reused
  );
  elements.autoLockLabel.textContent =
    `${currentStatus.settings.autoLockMinutes}M`;
  elements.extensionVersion.textContent = currentStatus.extensionVersion;
  elements.currentOrigin.textContent =
    currentStatus.currentOrigin ?? "非 HTTPS 页面";
  elements.autoLockMinutes.value = String(
    currentStatus.settings.autoLockMinutes
  );
  elements.auditWeak.textContent = String(currentStatus.passwordAudit.weak);
  elements.auditReused.textContent = String(currentStatus.passwordAudit.reused);
  elements.auditStale.textContent = String(currentStatus.passwordAudit.stale);
  elements.auditTrash.textContent = String(currentStatus.trashCount);
  elements.lastBackup.textContent =
    currentStatus.settings.lastBackupAt === null
      ? "尚未记录备份"
      : `上次备份：${formatMillisecondDate(
          currentStatus.settings.lastBackupAt
        )}`;
  renderQuickPasswords();
  renderPasswords();
  renderPasskeys();
  renderAuditLog();
  renderAmazonRegions();
  renderAutoFillOrigins();
  renderOssConfiguration();
}

function renderQuickPasswords(): void {
  elements.quickPasswordList.replaceChildren();
  const origin = currentStatus?.currentOrigin;
  const matches = origin
    ? passwords.filter(
        (password) =>
          password.deletedAt === null && password.origin === origin
      )
    : [];
  elements.quickEmpty.hidden = matches.length !== 0;
  for (const password of matches) {
    elements.quickPasswordList.append(createPasswordItem(password, true));
  }
}

function renderPasswords(): void {
  elements.passwordList.replaceChildren();
  const query = elements.passwordSearch.value.trim().toLocaleLowerCase();
  const showTrash = elements.showPasswordTrash.checked;
  const filtered = passwords.filter((password) => {
    if (showTrash !== (password.deletedAt !== null)) {
      return false;
    }
    const haystack = [
      password.name,
      password.origin,
      password.username,
      ...password.tags
    ].join("\n").toLocaleLowerCase();
    return query.length === 0 || haystack.includes(query);
  });
  elements.passwordEmpty.hidden = filtered.length !== 0;
  for (const password of filtered) {
    elements.passwordList.append(createPasswordItem(password, false));
  }
}

function createPasswordItem(
  password: PasswordSummary,
  quick: boolean
): HTMLLIElement {
  const item = document.createElement("li");
  const main = document.createElement("div");
  const name = document.createElement("strong");
  const account = document.createElement("span");
  const metadata = document.createElement("small");
  const actions = document.createElement("div");
  main.className = "item-main";
  actions.className = "item-actions";
  name.textContent = `${password.favorite ? "★ " : ""}${password.name}`;
  account.textContent = `${password.username || "无用户名"} · ${
    new URL(password.origin).hostname
  }`;
  const riskText = [
    password.weak ? "弱密码" : "",
    password.reused ? "重复使用" : "",
    password.autoFill ? "自动填充" : ""
  ].filter(Boolean).join(" · ");
  metadata.textContent =
    riskText || `更新于 ${formatSecondDate(password.updatedAt)}`;
  metadata.className =
    password.weak || password.reused ? "risk" : "safe";

  if (password.deletedAt !== null) {
    actions.append(
      actionButton("恢复", () => {
        void sendPopupRequest(
          { type: "restoreItem", itemId: password.itemId },
          "正在恢复密码"
        );
      }),
      actionButton("永久删除", () => {
        if (window.confirm(`永久删除“${password.name}”？此操作无法撤销。`)) {
          void sendPopupRequest(
            { type: "deleteItemPermanently", itemId: password.itemId },
            "正在永久删除"
          );
        }
      }, "danger")
    );
  } else {
    if (password.origin === currentStatus?.currentOrigin) {
      actions.append(
        actionButton("填充", () => {
          void fillPassword(password.itemId);
        })
      );
    }
    if (!quick) {
      actions.append(
        actionButton("编辑", () => {
          void editPassword(password.itemId);
        }),
        actionButton("删除", () => {
          void sendPopupRequest(
            { type: "trashItem", itemId: password.itemId },
            "正在移入回收站"
          );
        }, "danger")
      );
    }
  }
  main.append(name, account, metadata);
  item.append(main, actions);
  return item;
}

function renderPasskeys(): void {
  elements.passkeyList.replaceChildren();
  const query = elements.passkeySearch.value.trim().toLocaleLowerCase();
  const showTrash = elements.showPasskeyTrash.checked;
  const filtered = passkeys.filter((passkey) => {
    if (showTrash !== (passkey.deletedAt !== null)) {
      return false;
    }
    const haystack = [
      passkey.rpId,
      passkey.userName ?? "",
      passkey.displayName ?? "",
      passkey.alias ?? "",
      ...passkey.tags
    ].join("\n").toLocaleLowerCase();
    return query.length === 0 || haystack.includes(query);
  });
  elements.passkeyEmpty.hidden = filtered.length !== 0;
  for (const passkey of filtered) {
    const item = document.createElement("li");
    const main = document.createElement("div");
    const name = document.createElement("strong");
    const account = document.createElement("span");
    const metadata = document.createElement("small");
    const actions = document.createElement("div");
    main.className = "item-main";
    actions.className = "item-actions";
    name.textContent =
      `${passkey.favorite ? "★ " : ""}${
        passkey.alias || passkey.rpId
      }`;
    account.textContent =
      passkey.displayName || passkey.userName || "未命名账户";
    metadata.textContent =
      `使用 ${passkey.signCount} 次 · ${
        formatSecondDate(passkey.lastUsedAt ?? passkey.createdAt)
      }`;

    if (passkey.deletedAt !== null) {
      actions.append(
        actionButton("恢复", () => {
          void sendPopupRequest(
            { type: "restoreItem", itemId: passkey.credentialId },
            "正在恢复通行密钥"
          );
        }),
        actionButton("永久删除", () => {
          if (window.confirm("永久删除该通行密钥？网站上的注册记录不会自动移除。")) {
            void sendPopupRequest(
              {
                type: "deleteItemPermanently",
                itemId: passkey.credentialId
              },
              "正在永久删除"
            );
          }
        }, "danger")
      );
    } else {
      actions.append(
        actionButton(passkey.favorite ? "取消收藏" : "收藏", () => {
          void sendPopupRequest(
            {
              type: "updatePasskeyMetadata",
              credentialId: passkey.credentialId,
              favorite: !passkey.favorite
            },
            "正在更新通行密钥"
          );
        }),
        actionButton("别名", () => editPasskeyMetadata(passkey)),
        actionButton("删除", () => {
          void sendPopupRequest(
            { type: "trashItem", itemId: passkey.credentialId },
            "正在移入回收站"
          );
        }, "danger")
      );
    }
    main.append(name, account, metadata);
    item.append(main, actions);
    elements.passkeyList.append(item);
  }
}

function renderAuditLog(): void {
  elements.auditLog.replaceChildren();
  const labels: Record<AuditEntry["type"], string> = {
    "vault-created": "创建 Vault",
    "vault-unlocked": "解锁 Vault",
    "vault-locked": "锁定 Vault",
    "master-password-changed": "修改主密码",
    "passkey-created": "创建通行密钥",
    "passkey-used": "使用通行密钥",
    "passkey-updated": "更新通行密钥",
    "password-created": "创建密码",
    "password-used": "使用密码",
    "password-updated": "更新密码",
    "item-trashed": "移入回收站",
    "item-restored": "恢复凭据",
    "item-deleted": "永久删除凭据",
    "backup-exported": "导出备份",
    "backup-imported": "导入备份",
    "oss-connected": "连接阿里云 OSS",
    "oss-backup-uploaded": "上传 OSS 备份",
    "oss-disconnected": "断开阿里云 OSS"
  };
  for (const entry of auditEntries.slice(0, 100)) {
    const item = document.createElement("li");
    item.textContent = `${formatMillisecondDate(entry.at)} · ${
      labels[entry.type]
    }${entry.targetLabel ? ` · ${entry.targetLabel}` : ""}`;
    elements.auditLog.append(item);
  }
  if (auditEntries.length === 0) {
    const item = document.createElement("li");
    item.textContent = "暂无安全日志";
    elements.auditLog.append(item);
  }
}

function renderAmazonRegions(): void {
  elements.amazonRegionList.replaceChildren();
  const enabled = new Set(currentStatus?.settings.enabledAmazonRegions ?? []);
  for (const marketplace of AMAZON_MARKETPLACES) {
    const label = document.createElement("label");
    const copy = document.createElement("span");
    const title = document.createElement("strong");
    const detail = document.createElement("small");
    const checkbox = document.createElement("input");
    copy.className = "region-copy";
    title.textContent = `${marketplace.label} · ${marketplace.domain}`;
    detail.textContent = marketplace.region;
    checkbox.type = "checkbox";
    checkbox.checked =
      marketplace.domain === PRIMARY_AMAZON_DOMAIN ||
      enabled.has(marketplace.domain);
    checkbox.dataset.amazonDomain = marketplace.domain;
    checkbox.disabled = marketplace.domain === PRIMARY_AMAZON_DOMAIN || busy;
    checkbox.addEventListener("change", () => {
      void toggleAmazonRegion(marketplace.domain, checkbox.checked);
    });
    copy.append(title, detail);
    label.append(copy, checkbox);
    elements.amazonRegionList.append(label);
  }
}

function renderAutoFillOrigins(): void {
  elements.autoFillOriginList.replaceChildren();
  for (const origin of currentStatus?.settings.autoFillOrigins ?? []) {
    const item = document.createElement("li");
    const text = document.createElement("span");
    text.textContent = origin;
    item.append(
      text,
      actionButton("撤销", () => {
        void revokeAutoFillOrigin(origin);
      }, "danger")
    );
    elements.autoFillOriginList.append(item);
  }
}

async function fillPassword(itemId: string): Promise<void> {
  const response = await sendPopupRequest(
    { type: "fillPassword", itemId },
    "正在安全填充当前页面"
  );
  if (response?.ok && response.fillResult) {
    setOperationStatus(response.fillResult.message, "success");
  }
}

async function captureCurrentLogin(): Promise<void> {
  const response = await sendPopupRequest(
    { type: "captureLoginForm" },
    "正在读取当前登录表单"
  );
  if (response?.ok && response.capturedLogin) {
    openPasswordDialog({
      itemId: "",
      name:
        response.capturedLogin.title ||
        new URL(response.capturedLogin.origin).hostname,
      origin: response.capturedLogin.origin,
      username: response.capturedLogin.username,
      password: response.capturedLogin.password,
      notes: "",
      favorite: false,
      tags: [],
      autoFill: false,
      createdAt: 0,
      updatedAt: 0,
      lastUsedAt: null,
      deletedAt: null
    });
  }
}

async function editPassword(itemId: string): Promise<void> {
  const response = await sendPopupRequest(
    { type: "getPasswordDetails", itemId },
    "正在解密密码条目"
  );
  if (response?.ok && response.passwordDetails) {
    openPasswordDialog(response.passwordDetails);
  }
}

function openPasswordDialog(details?: PasswordDetails): void {
  elements.passwordForm.reset();
  elements.passwordItemId.value = details?.itemId ?? "";
  elements.passwordDialogTitle.textContent = details ? "编辑密码" : "新建密码";
  elements.passwordName.value = details?.name ?? "";
  elements.passwordOrigin.value =
    details?.origin ?? currentStatus?.currentOrigin ?? "";
  elements.passwordUsername.value = details?.username ?? "";
  elements.passwordSecret.value = details?.password ?? "";
  elements.passwordNotes.value = details?.notes ?? "";
  elements.passwordTags.value = details?.tags.join(", ") ?? "";
  elements.passwordFavorite.checked = details?.favorite ?? false;
  elements.passwordAutoFill.checked = details?.autoFill ?? false;
  elements.passwordSecret.type = "password";
  elements.togglePassword.textContent = "显示";
  renderPasswordStrength();
  elements.passwordDialog.showModal();
}

function closePasswordDialog(): void {
  elements.passwordSecret.value = "";
  elements.passwordNotes.value = "";
  elements.passwordDialog.close();
}

async function savePasswordFromDialog(): Promise<void> {
  try {
    const origin = normalizeCredentialOrigin(elements.passwordOrigin.value);
    let autoFill = elements.passwordAutoFill.checked;
    if (autoFill && !currentStatus?.settings.autoFillOrigins.includes(origin)) {
      const permission = await requestAutoFillOrigin(origin);
      if (!permission.granted) {
        autoFill = false;
        elements.passwordAutoFill.checked = false;
        setOperationStatus(
          "未获得网站权限，密码仍会保存，但只支持点击后填充。",
          "error"
        );
      } else {
        const origins = [
          ...(currentStatus?.settings.autoFillOrigins ?? []),
          permission.origin
        ];
        await sendPopupRequest(
          {
            type: "updateSettings",
            settings: { autoFillOrigins: [...new Set(origins)] }
          },
          "正在保存网站授权"
        );
      }
    }
    const itemId = elements.passwordItemId.value || undefined;
    const password: PasswordInput = {
      ...(itemId ? { itemId } : {}),
      name: elements.passwordName.value,
      origin,
      username: elements.passwordUsername.value,
      password: elements.passwordSecret.value,
      notes: elements.passwordNotes.value,
      favorite: elements.passwordFavorite.checked,
      tags: elements.passwordTags.value
        .split(",")
        .map((tag) => tag.trim())
        .filter(Boolean),
      autoFill
    };
    const response = await sendPopupRequest(
      {
        type: itemId ? "updatePassword" : "savePassword",
        password
      },
      itemId ? "正在更新密码" : "正在加密保存密码"
    );
    if (response?.ok) {
      closePasswordDialog();
      activateTab("passwords");
      setOperationStatus("密码已加密保存", "success");
    }
  } catch (error) {
    setOperationStatus(errorMessage(error), "error");
  }
}

function editPasskeyMetadata(passkey: CredentialSummary): void {
  const alias = window.prompt(
    "通行密钥别名（留空使用站点名称）",
    passkey.alias ?? ""
  );
  if (alias === null) {
    return;
  }
  const tags = window.prompt(
    "标签，以英文逗号分隔",
    passkey.tags.join(", ")
  );
  if (tags === null) {
    return;
  }
  void sendPopupRequest(
    {
      type: "updatePasskeyMetadata",
      credentialId: passkey.credentialId,
      alias,
      tags: tags.split(",").map((tag) => tag.trim()).filter(Boolean)
    },
    "正在更新通行密钥"
  );
}

async function toggleAmazonRegion(
  domain: string,
  enabled: boolean
): Promise<void> {
  if (!currentStatus) {
    return;
  }
  try {
    let regions = [...currentStatus.settings.enabledAmazonRegions];
    if (enabled) {
      if (!(await requestAmazonRegion(domain))) {
        throw new Error("用户未授予该 Amazon 区域站权限");
      }
      regions = [...new Set([...regions, domain])];
    } else {
      await removeAmazonRegion(domain);
      regions = regions.filter((item) => item !== domain);
    }
    await updateSettings({ enabledAmazonRegions: regions });
  } catch (error) {
    setOperationStatus(errorMessage(error), "error");
    await sendPopupRequest({ type: "getExtensionStatus" }, "正在恢复设置");
  }
}

async function addAutoFillOrigin(): Promise<void> {
  try {
    const { granted, origin } = await requestAutoFillOrigin(
      elements.autoFillOrigin.value
    );
    if (!granted) {
      throw new Error("用户未授予该网站权限");
    }
    const origins = [
      ...(currentStatus?.settings.autoFillOrigins ?? []),
      origin
    ];
    elements.autoFillOrigin.value = "";
    await updateSettings({ autoFillOrigins: [...new Set(origins)] });
  } catch (error) {
    setOperationStatus(errorMessage(error), "error");
  }
}

async function revokeAutoFillOrigin(origin: string): Promise<void> {
  await removeAutoFillOrigin(origin);
  const origins = (currentStatus?.settings.autoFillOrigins ?? []).filter(
    (item) => item !== origin
  );
  await updateSettings({ autoFillOrigins: origins });
}

function renderOssConfiguration(): void {
  const configuration = currentStatus?.ossConfiguration ?? null;
  const editing = elements.ossForm.contains(document.activeElement);
  if (!editing) {
    if (configuration) {
      elements.ossEndpoint.value = configuration.endpoint;
      elements.ossRegion.value = configuration.region;
      elements.ossBucket.value = configuration.bucket;
      elements.ossObjectKey.value = configuration.objectKey;
      elements.ossAccessKeyId.value = configuration.accessKeyId;
      elements.ossConsent.checked = true;
    } else {
      elements.ossEndpoint.value =
        "https://oss-cn-hangzhou.aliyuncs.com";
      elements.ossRegion.value = "cn-hangzhou";
      elements.ossBucket.value = "";
      elements.ossObjectKey.value =
        "diyvm-local-passkey/vault-backup.json";
      elements.ossAccessKeyId.value = "";
      elements.ossConsent.checked = false;
    }
    elements.ossAccessKeySecret.value = "";
  }
  if (!configuration) {
    elements.ossSummary.textContent = "用户自有阿里云 OSS（未连接）";
    setOssStatus("尚未连接用户自有 OSS。");
    return;
  }
  elements.ossSummary.textContent =
    `用户自有阿里云 OSS（${configuration.bucket}）`;
  const uploaded =
    configuration.lastUploadedAt === null
      ? "尚未上传"
      : `上次上传 ${formatMillisecondDate(configuration.lastUploadedAt)}`;
  setOssStatus(
    `已连接 ${configuration.bucket} · ${configuration.objectKey} · ${uploaded}`,
    "success"
  );
}

async function configureOss(): Promise<void> {
  if (!elements.ossConsent.checked) {
    setOssStatus(
      "请先确认仅向你配置的 OSS 发送加密备份。",
      "error"
    );
    return;
  }
  let configuration: OssConfigurationInput;
  try {
    configuration = normalizeOssConfiguration({
      endpoint: elements.ossEndpoint.value,
      region: elements.ossRegion.value,
      bucket: elements.ossBucket.value,
      objectKey: elements.ossObjectKey.value,
      accessKeyId: elements.ossAccessKeyId.value,
      accessKeySecret: elements.ossAccessKeySecret.value
    });
  } catch (error) {
    setOssStatus(errorMessage(error), "error");
    return;
  }

  let granted = false;
  setBusy(true);
  setOssStatus("正在请求该 OSS Bucket 的精确访问权限…");
  try {
    granted = await chrome.permissions.request({
      origins: [ossPermissionPattern(configuration)]
    });
  } catch (error) {
    setOssStatus(`权限请求失败：${errorMessage(error)}`, "error");
  } finally {
    setBusy(false);
  }
  if (!granted) {
    elements.ossAccessKeySecret.value = "";
    setOssStatus("未获得 OSS 访问权限，配置没有保存。", "error");
    return;
  }

  const response = await sendPopupRequest(
    { type: "configureOss", configuration },
    "正在测试并加密保存 OSS 配置"
  );
  elements.ossAccessKeySecret.value = "";
  if (response?.ok) {
    setOssStatus(
      "OSS 连接测试成功；AccessKey Secret 已加密保存在本地 Vault。",
      "success"
    );
  } else {
    const previous = currentStatus?.ossConfiguration;
    if (
      !previous ||
      ossPermissionPattern(previous) !== ossPermissionPattern(configuration)
    ) {
      await chrome.permissions.remove({
        origins: [ossPermissionPattern(configuration)]
      }).catch(() => false);
    }
    setOssStatus(
      response?.error ?? "OSS 连接测试失败，配置没有保存。",
      "error"
    );
  }
}

async function uploadOssBackup(): Promise<void> {
  if (!currentStatus?.ossConfiguration) {
    setOssStatus("请先保存并测试 OSS 配置。", "error");
    return;
  }
  if (
    !window.confirm(
      "上传会写入配置的固定对象路径；如果 Bucket 未开启版本控制，现有同名备份会被覆盖。是否继续？"
    )
  ) {
    return;
  }
  setOssStatus("正在生成并上传加密备份…");
  const response = await sendPopupRequest(
    { type: "uploadOssBackup" },
    "正在上传加密 OSS 备份"
  );
  if (response?.ok) {
    setOssStatus(
      "加密备份已上传。建议在 OSS Bucket 中开启版本控制。",
      "success"
    );
  }
}

async function inspectOssBackup(): Promise<OssRemoteBackupInfo | undefined> {
  if (!currentStatus?.ossConfiguration) {
    setOssStatus("请先保存并测试 OSS 配置。", "error");
    return undefined;
  }
  setOssStatus("正在下载并验证远程加密备份…");
  const response = await sendPopupRequest(
    { type: "inspectOssBackup" },
    "正在检查远程 OSS 备份"
  );
  if (!response?.ok || !response.ossRemoteBackupInfo) {
    return undefined;
  }
  setOssStatus(formatOssBackupInfo(response.ossRemoteBackupInfo), "success");
  return response.ossRemoteBackupInfo;
}

async function restoreOssBackup(): Promise<void> {
  const info = await inspectOssBackup();
  if (!info) {
    return;
  }
  if (
    !window.confirm(
      `远程备份包含 ${info.itemCount} 个凭据，导出于 ${
        formatMillisecondDate(new Date(info.exportedAt).getTime())
      }。恢复会完整替换当前 Vault，是否继续？`
    )
  ) {
    return;
  }
  const response = await sendPopupRequest(
    { type: "restoreOssBackup" },
    "正在恢复远程 OSS 备份"
  );
  if (response?.ok && response.ossRemoteBackupInfo) {
    setOperationStatus(
      `已从 OSS 恢复 ${response.ossRemoteBackupInfo.itemCount} 个凭据，` +
        "请使用备份对应的主密码解锁。",
      "success"
    );
  }
}

async function disconnectOss(): Promise<void> {
  if (!currentStatus?.ossConfiguration) {
    setOssStatus("当前没有已保存的 OSS 配置。", "error");
    return;
  }
  if (
    !window.confirm(
      "断开后会删除 Vault 内的 OSS AccessKey 配置并撤销该 Bucket 权限，远程备份不会被删除。是否继续？"
    )
  ) {
    return;
  }
  const response = await sendPopupRequest(
    { type: "disconnectOss" },
    "正在断开 OSS 并撤销权限"
  );
  if (response?.ok) {
    setOssStatus("已断开 OSS；远程对象仍由你在 OSS 控制台管理。", "success");
  }
}

function formatOssBackupInfo(info: OssRemoteBackupInfo): string {
  const size = info.size === null ? "大小未知" : formatBytes(info.size);
  const modified =
    info.lastModifiedAt === null
      ? ""
      : `，OSS 修改于 ${formatMillisecondDate(info.lastModifiedAt)}`;
  return `远程备份有效：${info.itemCount} 个凭据，${size}，导出于 ${
    formatMillisecondDate(new Date(info.exportedAt).getTime())
  }${modified}。`;
}

async function updateSettings(settings: Partial<VaultSettings>): Promise<void> {
  const response = await sendPopupRequest(
    { type: "updateSettings", settings },
    "正在保存设置"
  );
  if (response?.ok) {
    setOperationStatus("设置已保存", "success");
  }
}

async function changeMasterPassword(): Promise<void> {
  const currentPassword = elements.currentMasterPassword.value;
  const newPassword = elements.newMasterPassword.value;
  if (newPassword !== elements.confirmMasterPassword.value) {
    setOperationStatus("两次输入的新主密码不一致", "error");
    return;
  }
  const response = await sendPopupRequest(
    { type: "changeMasterPassword", currentPassword, newPassword },
    "正在更新主密码并重新包装 Vault Key"
  );
  elements.changePasswordForm.reset();
  if (response?.ok) {
    setOperationStatus("主密码已更新，现有凭据无需重建", "success");
  }
}

async function exportBackupFile(): Promise<void> {
  setBusy(true);
  setBackupStatus("正在生成加密备份…");
  let store: IndexedDbVaultStore | undefined;
  let exported = false;
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
    exported = true;
    setBackupStatus("加密备份已导出，请保存到可信位置。", "success");
  } catch (error) {
    setBackupStatus(errorMessage(error), "error");
  } finally {
    store?.close();
    setBusy(false);
  }
  if (exported) {
    await sendPopupRequest(
      { type: "recordBackupExport" },
      "正在记录备份时间"
    );
  }
}

async function verifyBackupFile(file: File): Promise<void> {
  if (!validBackupFile(file)) {
    return;
  }
  setBusy(true);
  setBackupStatus("正在验证备份结构和完整性…");
  try {
    const result = await verifyVaultBackup(await file.text());
    setBackupStatus(
      `备份有效：${result.itemCount} 个凭据，导出于 ${
        formatMillisecondDate(new Date(result.exportedAt).getTime())
      }，KDF ${result.kdf}。`,
      "success"
    );
  } catch (error) {
    setBackupStatus(`备份验证失败：${errorMessage(error)}`, "error");
  } finally {
    elements.verifyBackupFile.value = "";
    setBusy(false);
  }
}

async function importBackupFile(file: File): Promise<void> {
  if (!validBackupFile(file)) {
    return;
  }
  if (
    !window.confirm(
      "恢复会完整替换当前 Vault。请确认已经导出现有备份，是否继续？"
    )
  ) {
    elements.importBackupFile.value = "";
    return;
  }
  setBusy(true);
  setBackupStatus("正在校验并恢复加密备份…");
  let store: IndexedDbVaultStore | undefined;
  try {
    const lockResponse = await chrome.runtime.sendMessage({
      type: "lockVault"
    }) as PopupResponse;
    if (!lockResponse.ok) {
      throw new Error(lockResponse.error);
    }
    store = await IndexedDbVaultStore.open();
    const result = await importVaultBackup(store, await file.text());
    setBackupStatus(
      `已恢复 ${result.itemCount} 个凭据，请使用备份对应的主密码解锁。`,
      "success"
    );
  } catch (error) {
    setBackupStatus(`恢复失败：${errorMessage(error)}`, "error");
  } finally {
    store?.close();
    elements.importBackupFile.value = "";
    setBusy(false);
  }
  await sendPopupRequest({ type: "getExtensionStatus" }, "正在刷新恢复结果");
}

function validBackupFile(file: File): boolean {
  if (file.size === 0 || file.size > MAX_VAULT_BACKUP_BYTES) {
    setBackupStatus("备份文件为空或超过 20 MB 限制。", "error");
    return false;
  }
  return true;
}

function renderPasswordStrength(): void {
  if (elements.passwordSecret.value.length === 0) {
    elements.passwordStrength.textContent = "尚未输入密码";
    return;
  }
  const strength = passwordStrength(elements.passwordSecret.value);
  elements.passwordStrength.textContent =
    `强度：${strength.label}${
      strength.suggestions[0] ? ` · ${strength.suggestions[0]}` : ""
    }`;
  elements.passwordStrength.className = strength.weak ? "risk" : "safe";
}

function togglePasswordVisibility(): void {
  const visible = elements.passwordSecret.type === "text";
  elements.passwordSecret.type = visible ? "password" : "text";
  elements.togglePassword.textContent = visible ? "显示" : "隐藏";
}

function activateTab(tab: string): void {
  document.querySelectorAll<HTMLButtonElement>("[data-tab]").forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === tab);
  });
  document.querySelectorAll<HTMLElement>("[data-panel]").forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.panel === tab);
  });
}

function actionButton(
  label: string,
  action: () => void,
  className?: string
): HTMLButtonElement {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  if (className) {
    button.className = className;
  }
  button.addEventListener("click", action);
  return button;
}

function setBusy(value: boolean): void {
  busy = value;
  document.querySelectorAll<HTMLButtonElement>("button").forEach((button) => {
    if (
      button === elements.closePasswordDialog ||
      button === elements.cancelPasswordDialog
    ) {
      return;
    }
    button.disabled = value;
  });
  document.querySelectorAll<HTMLInputElement>(
    "input[data-amazon-domain]"
  ).forEach((checkbox) => {
    checkbox.disabled =
      checkbox.dataset.amazonDomain === PRIMARY_AMAZON_DOMAIN || value;
  });
}

function renderPending(message: string): void {
  elements.dot.className = "status-dot pending";
  elements.title.textContent = message;
  elements.detail.textContent = "请稍候…";
}

function setOperationStatus(
  message: string,
  state?: "success" | "error"
): void {
  elements.operationStatus.textContent = message;
  if (state) {
    elements.operationStatus.dataset.state = state;
  } else {
    delete elements.operationStatus.dataset.state;
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

function setOssStatus(
  message: string,
  state?: "success" | "error"
): void {
  elements.ossStatus.textContent = message;
  if (state) {
    elements.ossStatus.dataset.state = state;
  } else {
    delete elements.ossStatus.dataset.state;
  }
}

function applyColorScheme(isDark: boolean): void {
  document.documentElement.dataset.theme = isDark ? "dark" : "light";
}

function formatSecondDate(timestamp: number): string {
  return formatMillisecondDate(timestamp * 1_000);
}

function formatMillisecondDate(timestamp: number): string {
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "short",
    timeStyle: "short"
  }).format(new Date(timestamp));
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
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

function requireTextArea(id: string): HTMLTextAreaElement {
  const element = requireElement(id);
  if (!(element instanceof HTMLTextAreaElement)) {
    throw new Error(`#${id} is not a textarea`);
  }
  return element;
}

function requireSelect(id: string): HTMLSelectElement {
  const element = requireElement(id);
  if (!(element instanceof HTMLSelectElement)) {
    throw new Error(`#${id} is not a select`);
  }
  return element;
}

function requireDialog(id: string): HTMLDialogElement {
  const element = requireElement(id);
  if (!(element instanceof HTMLDialogElement)) {
    throw new Error(`#${id} is not a dialog`);
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

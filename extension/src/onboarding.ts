import {
  ALL_HTTPS_MATCH_PATTERN,
  requestAllHttpsPasskeys,
  syncRegisteredContentScripts
} from "./site-access";
import {
  ChromeVaultSettingsStorage,
  updateVaultSettings
} from "./vault-settings";

const enableButton = requireButton("enable-passkeys");
const skipButton = requireButton("skip");
const status = requireElement("status");
const version = requireElement("version");

version.textContent = `v${chrome.runtime.getManifest().version}`;

enableButton.addEventListener("click", () => {
  void enableAllHttpsPasskeys();
});

skipButton.addEventListener("click", () => {
  void closeOnboardingTab();
});

void renderCurrentState();

async function renderCurrentState(): Promise<void> {
  const settings = await new ChromeVaultSettingsStorage().read();
  const granted = await chrome.permissions.contains({
    origins: [ALL_HTTPS_MATCH_PATTERN]
  });
  if (settings.passkeyAllHttps && granted) {
    showEnabled();
  }
}

async function enableAllHttpsPasskeys(): Promise<void> {
  setBusy(true);
  setStatus("正在等待 Chrome 权限确认…");
  try {
    if (!(await requestAllHttpsPasskeys())) {
      throw new Error("未授予所有 HTTPS 网站权限，你可以稍后在扩展设置中启用");
    }
    const storage = new ChromeVaultSettingsStorage();
    const settings = await updateVaultSettings(storage, {
      passkeyAllHttps: true
    });
    await syncRegisteredContentScripts(settings);
    showEnabled();
  } catch (error) {
    setStatus(errorMessage(error), "error");
    setBusy(false);
  }
}

async function closeOnboardingTab(): Promise<void> {
  const tab = await chrome.tabs.getCurrent();
  if (typeof tab?.id === "number") {
    await chrome.tabs.remove(tab.id);
    return;
  }
  window.close();
}

function showEnabled(): void {
  enableButton.textContent = "通用 Passkey 已启用";
  enableButton.disabled = true;
  skipButton.textContent = "完成并关闭";
  setStatus("已启用。请点击工具栏中的 DIYVM 图标创建本地保险库。", "success");
}

function setBusy(busy: boolean): void {
  enableButton.disabled = busy;
  skipButton.disabled = busy;
}

function setStatus(
  message: string,
  state?: "success" | "error"
): void {
  status.textContent = message;
  if (state) {
    status.dataset.state = state;
  } else {
    delete status.dataset.state;
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function requireButton(id: string): HTMLButtonElement {
  const element = document.getElementById(id);
  if (!(element instanceof HTMLButtonElement)) {
    throw new TypeError(`Missing button #${id}`);
  }
  return element;
}

function requireElement(id: string): HTMLElement {
  const element = document.getElementById(id);
  if (!element) {
    throw new TypeError(`Missing element #${id}`);
  }
  return element;
}

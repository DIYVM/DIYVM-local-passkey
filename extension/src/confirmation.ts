import {
  isConfirmationId,
  type ConfirmationDetails,
  type ConfirmationResponse
} from "./confirmation-messages";

const confirmationId = new URL(location.href).searchParams.get("id");
const elements = {
  title: requireElement("confirmation-title"),
  description: requireElement("confirmation-description"),
  origin: requireElement("confirmation-origin"),
  site: requireElement("confirmation-site"),
  accountGroup: requireElement("account-group"),
  account: requireSelect("confirmation-account"),
  approve: requireButton("approve"),
  fallback: requireButton("fallback"),
  cancel: requireButton("cancel"),
  error: requireElement("confirmation-error")
};

let resolved = false;

elements.approve.addEventListener("click", () => {
  void resolve("local");
});
elements.fallback.addEventListener("click", () => {
  void resolve("fallback");
});
elements.cancel.addEventListener("click", () => {
  void resolve("cancel");
});

void loadDetails();

async function loadDetails(): Promise<void> {
  if (!isConfirmationId(confirmationId)) {
    showError("确认请求无效");
    return;
  }
  try {
    const response = (await chrome.runtime.sendMessage({
      type: "getConfirmation",
      confirmationId
    })) as ConfirmationResponse;
    if (!response.ok || !response.details) {
      showError(response.ok ? "确认请求已经结束" : response.error);
      return;
    }
    renderDetails(response.details);
  } catch (error) {
    showError(error instanceof Error ? error.message : String(error));
  }
}

function renderDetails(details: ConfirmationDetails): void {
  elements.origin.textContent = details.origin;
  elements.site.textContent = details.rpId;
  if (details.operation === "create") {
    elements.title.textContent = "创建本地通行密钥";
    elements.description.textContent =
      "确认后，纯插件将在本机生成并加密保存一枚通行密钥。";
    elements.account.replaceChildren(
      option(
        "",
        `${details.displayName || details.userName} · ${details.userName}`
      )
    );
    elements.account.disabled = true;
  } else {
    elements.title.textContent = "使用本地通行密钥";
    elements.description.textContent =
      "请选择账户并确认本次登录。私钥不会离开浏览器扩展。";
    elements.account.replaceChildren(
      ...details.credentials.map((credential) =>
        option(
          credential.credentialId,
          `${credential.displayName || credential.userName} · ${credential.userName}`
        )
      )
    );
  }
  setButtonsDisabled(false);
}

async function resolve(
  decision: "local" | "fallback" | "cancel"
): Promise<void> {
  if (resolved || !isConfirmationId(confirmationId)) {
    return;
  }
  resolved = true;
  setButtonsDisabled(true);
  try {
    const response = (await chrome.runtime.sendMessage({
      type: "resolveConfirmation",
      confirmationId,
      decision,
      ...(decision === "local" && elements.account.value
        ? { credentialId: elements.account.value }
        : {})
    })) as ConfirmationResponse | undefined;
    if (!response?.ok) {
      resolved = false;
      showError(response?.error ?? "插件后台没有返回确认结果，请重试");
      setButtonsDisabled(false);
      return;
    }
    window.close();
  } catch {
    resolved = false;
    showError("插件后台连接中断，请返回网页刷新后重试");
    setButtonsDisabled(false);
  }
}

function showError(message: string): void {
  elements.error.textContent = message;
  elements.error.hidden = false;
}

function setButtonsDisabled(disabled: boolean): void {
  elements.approve.disabled = disabled;
  elements.fallback.disabled = disabled;
  elements.cancel.disabled = disabled;
}

function option(value: string, label: string): HTMLOptionElement {
  const element = document.createElement("option");
  element.value = value;
  element.textContent = label;
  return element;
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

function requireSelect(id: string): HTMLSelectElement {
  const element = requireElement(id);
  if (!(element instanceof HTMLSelectElement)) {
    throw new Error(`#${id} is not a select`);
  }
  return element;
}

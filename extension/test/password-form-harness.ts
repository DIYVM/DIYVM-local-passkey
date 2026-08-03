import {
  captureLoginFormInPage,
  fillPasswordInPage
} from "../src/page-password-actions";

type BrowserCheck = readonly [string, () => void];

const fixture = requireElement("fixture");
const checks: BrowserCheck[] = [
  ["优先填充当前登录弹窗", checkModalPreference],
  ["填充开放式 Shadow DOM 登录框", checkOpenShadowRoot],
  ["支持先账号后密码的分步登录", checkUsernameOnlyStep],
  ["从当前弹窗截取账号密码", checkModalCapture],
  ["拒绝向不同 Origin 填充", checkOriginMismatch],
  ["触发框架可识别的 input/change 事件", checkInputEvents]
];

try {
  for (const [name, check] of checks) {
    check();
    appendResult(name, true);
  }
  setStatus("passed", `${checks.length} 项密码表单兼容测试通过`);
} catch (error) {
  appendResult(error instanceof Error ? error.message : String(error), false);
  setStatus("failed", "密码表单兼容测试失败");
  console.error(error);
}

function checkModalPreference(): void {
  fixture.innerHTML = `
    <form id="background-form">
      <input autocomplete="username">
      <input type="password" autocomplete="current-password">
    </form>
    <section role="dialog" aria-modal="true" id="login-dialog">
      <input id="modal-user" autocomplete="username">
      <input id="modal-password" type="password" autocomplete="current-password">
    </section>
  `;
  const modalPassword = requireInput("modal-password");
  modalPassword.focus();
  const result = fillPasswordInPage(
    "modal@example.com",
    "modal-secret",
    location.origin,
    false,
    true
  );
  assert(result.ok, result.message);
  assert(requireInput("modal-user").value === "modal@example.com");
  assert(modalPassword.value === "modal-secret");
  assert(
    fixture.querySelector<HTMLInputElement>(
      "#background-form input[type=password]"
    )?.value === ""
  );
}

function checkOpenShadowRoot(): void {
  fixture.replaceChildren();
  const host = document.createElement("section");
  host.id = "shadow-host";
  fixture.append(host);
  const root = host.attachShadow({ mode: "open" });
  root.innerHTML = `
    <style>
      form { display: grid; gap: 8px; }
      input { min-height: 40px; }
    </style>
    <form>
      <input id="shadow-user" autocomplete="username">
      <input id="shadow-password" type="password" autocomplete="current-password">
    </form>
  `;
  const shadowPassword = root.querySelector<HTMLInputElement>(
    "#shadow-password"
  );
  const shadowUser = root.querySelector<HTMLInputElement>("#shadow-user");
  assert(shadowPassword && shadowUser);
  shadowPassword.focus();
  const result = fillPasswordInPage(
    "shadow@example.com",
    "shadow-secret",
    location.origin,
    false,
    true
  );
  assert(result.ok, result.message);
  assert(shadowUser.value === "shadow@example.com");
  assert(shadowPassword.value === "shadow-secret");
}

function checkUsernameOnlyStep(): void {
  fixture.innerHTML = `
    <section role="dialog" aria-modal="true">
      <input id="step-user" type="email" autocomplete="username">
    </section>
  `;
  const username = requireInput("step-user");
  username.focus();
  const result = fillPasswordInPage(
    "step@example.com",
    "unused-secret",
    location.origin,
    false,
    true
  );
  assert(result.ok, result.message);
  assert(result.usernameFilled);
  assert(!result.passwordFilled);
  assert(username.value === "step@example.com");
}

function checkModalCapture(): void {
  fixture.innerHTML = `
    <form>
      <input autocomplete="username" value="background@example.com">
      <input type="password" value="background-secret">
    </form>
    <section role="dialog" aria-modal="true">
      <input id="capture-user" autocomplete="username" value="capture@example.com">
      <input id="capture-password" type="password" autocomplete="current-password"
        value="capture-secret">
    </section>
  `;
  requireInput("capture-password").focus();
  const captured = captureLoginFormInPage(location.origin, true);
  assert(captured);
  assert(captured.username === "capture@example.com");
  assert(captured.password === "capture-secret");
}

function checkOriginMismatch(): void {
  fixture.innerHTML = `
    <input id="blocked-user" autocomplete="username">
    <input id="blocked-password" type="password">
  `;
  const result = fillPasswordInPage(
    "blocked@example.com",
    "blocked-secret",
    "https://different.example",
    false,
    true
  );
  assert(!result.ok);
  assert(requireInput("blocked-user").value === "");
  assert(requireInput("blocked-password").value === "");
}

function checkInputEvents(): void {
  fixture.innerHTML = `
    <form>
      <input id="event-user" autocomplete="username">
      <input id="event-password" type="password" autocomplete="current-password">
    </form>
  `;
  let inputEvents = 0;
  let changeEvents = 0;
  fixture.addEventListener("input", () => {
    inputEvents += 1;
  }, { once: false });
  fixture.addEventListener("change", () => {
    changeEvents += 1;
  }, { once: false });
  requireInput("event-password").focus();
  const result = fillPasswordInPage(
    "events@example.com",
    "events-secret",
    location.origin,
    false,
    true
  );
  assert(result.ok, result.message);
  assert(inputEvents === 2);
  assert(changeEvents === 2);
}

function requireElement(id: string): HTMLElement {
  const element = document.getElementById(id);
  if (!(element instanceof HTMLElement)) {
    throw new Error(`缺少测试元素：${id}`);
  }
  return element;
}

function requireInput(id: string): HTMLInputElement {
  const element = document.getElementById(id);
  if (!(element instanceof HTMLInputElement)) {
    throw new Error(`缺少测试输入框：${id}`);
  }
  return element;
}

function assert(
  condition: unknown,
  message = "浏览器断言失败"
): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

function appendResult(name: string, passed: boolean): void {
  const item = document.createElement("li");
  item.textContent = `${passed ? "✓" : "✗"} ${name}`;
  item.dataset.status = passed ? "passed" : "failed";
  requireElement("results").append(item);
}

function setStatus(status: "passed" | "failed", text: string): void {
  const element = requireElement("status");
  element.dataset.status = status;
  element.textContent = text;
}

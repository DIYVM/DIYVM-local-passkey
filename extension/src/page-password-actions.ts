export interface PasswordFillResult {
  ok: boolean;
  usernameFilled: boolean;
  passwordFilled: boolean;
  message: string;
}

export interface CapturedLoginForm {
  origin: string;
  title: string;
  username: string;
  password: string;
}

export function fillPasswordInPage(
  username: string,
  password: string
): PasswordFillResult {
  const visible = (element: HTMLInputElement): boolean => {
    const style = getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    return (
      !element.disabled &&
      !element.readOnly &&
      style.display !== "none" &&
      style.visibility !== "hidden" &&
      rect.width > 0 &&
      rect.height > 0
    );
  };
  const setValue = (input: HTMLInputElement, value: string): void => {
    const descriptor = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value"
    );
    if (descriptor?.set) {
      descriptor.set.call(input, value);
    } else {
      input.value = value;
    }
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  };

  const passwordInputs = Array.from(document.querySelectorAll<HTMLInputElement>(
    'input[type="password"]'
  )).filter(visible);
  const focused =
    document.activeElement instanceof HTMLInputElement &&
    document.activeElement.type === "password" &&
    visible(document.activeElement)
      ? document.activeElement
      : undefined;
  const passwordInput = focused ?? passwordInputs[0];
  if (!passwordInput) {
    return {
      ok: false,
      usernameFilled: false,
      passwordFilled: false,
      message: "当前页面没有可填写的密码输入框"
    };
  }

  const scope: ParentNode = passwordInput.form ?? document;
  const candidateInputs = Array.from(scope.querySelectorAll<HTMLInputElement>(
    'input[type="email"], input[type="text"], input:not([type])'
  )).filter(visible);
  const usernameInput =
    candidateInputs.find((input) =>
      /^(?:username|email)$/u.test(input.autocomplete)
    ) ??
    [...candidateInputs]
      .filter(
        (input) =>
          input.compareDocumentPosition(passwordInput) &
          Node.DOCUMENT_POSITION_FOLLOWING
      )
      .at(-1) ??
    candidateInputs[0];

  if (usernameInput && username.length > 0) {
    setValue(usernameInput, username);
  }
  setValue(passwordInput, password);
  passwordInput.focus();

  return {
    ok: true,
    usernameFilled: Boolean(usernameInput && username.length > 0),
    passwordFilled: true,
    message: "凭据已填入，提交前请核对网站域名"
  };
}

export function captureLoginFormInPage(): CapturedLoginForm | undefined {
  const visible = (element: HTMLInputElement): boolean => {
    const style = getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    return (
      !element.disabled &&
      !element.readOnly &&
      style.display !== "none" &&
      style.visibility !== "hidden" &&
      rect.width > 0 &&
      rect.height > 0
    );
  };
  const passwordInput = Array.from(document.querySelectorAll<HTMLInputElement>(
    'input[type="password"]'
  )).find((input) => visible(input) && input.value.length > 0);
  if (!passwordInput) {
    return undefined;
  }
  const scope: ParentNode = passwordInput.form ?? document;
  const candidateInputs = Array.from(scope.querySelectorAll<HTMLInputElement>(
    'input[type="email"], input[type="text"], input:not([type])'
  )).filter(visible);
  const usernameInput =
    candidateInputs.find((input) =>
      /^(?:username|email)$/u.test(input.autocomplete)
    ) ??
    [...candidateInputs]
      .filter(
        (input) =>
          input.compareDocumentPosition(passwordInput) &
          Node.DOCUMENT_POSITION_FOLLOWING
      )
      .at(-1) ??
    candidateInputs[0];

  return {
    origin: location.origin,
    title: document.title.slice(0, 128),
    username: usernameInput?.value ?? "",
    password: passwordInput.value
  };
}

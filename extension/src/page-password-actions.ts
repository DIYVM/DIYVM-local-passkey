export interface PasswordFillResult {
  ok: boolean;
  usernameFilled: boolean;
  passwordFilled: boolean;
  message: string;
  targetScore?: number;
  focusedTarget?: boolean;
}

export interface CapturedLoginForm {
  origin: string;
  title: string;
  username: string;
  password: string;
  targetScore?: number;
  focusedTarget?: boolean;
}

export function fillPasswordInPage(
  username: string,
  password: string,
  expectedOrigin = location.origin,
  inspectOnly = false,
  allowInsecureLoopbackForTesting = false
): PasswordFillResult {
  type QueryRoot = Document | ShadowRoot;

  const failure = (message: string): PasswordFillResult => ({
    ok: false,
    usernameFilled: false,
    passwordFilled: false,
    message
  });
  const trustedProtocol =
    location.protocol === "https:" ||
    (
      allowInsecureLoopbackForTesting &&
      location.protocol === "http:" &&
      (
        location.hostname === "localhost" ||
        location.hostname === "127.0.0.1" ||
        location.hostname === "[::1]"
      )
    );
  if (!trustedProtocol || location.origin !== expectedOrigin) {
    return failure("登录框来源与密码条目不一致");
  }

  const composedParent = (node: Node): Node | null => {
    if (node.parentNode) {
      return node.parentNode;
    }
    return node instanceof ShadowRoot ? node.host : null;
  };
  const composedContains = (container: Node, node: Node | null): boolean => {
    let current = node;
    while (current) {
      if (current === container) {
        return true;
      }
      current = composedParent(current);
    }
    return false;
  };
  const roots: QueryRoot[] = [document];
  for (let index = 0; index < roots.length && roots.length < 128; index += 1) {
    const root = roots[index]!;
    for (const element of Array.from(
      root.querySelectorAll<HTMLElement>("*")
    )) {
      if (element.shadowRoot && !roots.includes(element.shadowRoot)) {
        roots.push(element.shadowRoot);
      }
    }
  }
  const queryAll = <ElementType extends Element>(
    selector: string
  ): ElementType[] => {
    const matches = new Set<ElementType>();
    for (const root of roots) {
      for (const element of Array.from(
        root.querySelectorAll<ElementType>(selector)
      )) {
        matches.add(element);
      }
    }
    return [...matches];
  };
  const deepActiveElement = (): Element | null => {
    let active: Element | null = document.activeElement;
    while (
      active instanceof HTMLElement &&
      active.shadowRoot?.activeElement
    ) {
      active = active.shadowRoot.activeElement;
    }
    return active;
  };
  const activeElement = deepActiveElement();
  const visibleElement = (element: HTMLElement): boolean => {
    const style = getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    return (
      !element.hidden &&
      element.getAttribute("aria-hidden") !== "true" &&
      style.display !== "none" &&
      style.visibility !== "hidden" &&
      style.opacity !== "0" &&
      rect.width > 0 &&
      rect.height > 0 &&
      rect.bottom > 0 &&
      rect.right > 0 &&
      rect.top < innerHeight &&
      rect.left < innerWidth
    );
  };
  const visibleInput = (input: HTMLInputElement): boolean =>
    !input.disabled &&
    !input.readOnly &&
    input.getAttribute("aria-hidden") !== "true" &&
    visibleElement(input);
  const modalSelector = [
    "dialog[open]",
    '[role="dialog"]',
    '[aria-modal="true"]',
    "[data-modal]",
    '[class*="modal" i]',
    '[class*="dialog" i]',
    '[class*="popup" i]'
  ].join(",");
  const modals = queryAll<HTMLElement>(modalSelector).filter(visibleElement);
  const containingModal = (input: HTMLInputElement): HTMLElement | undefined =>
    modals
      .filter((modal) => composedContains(modal, input))
      .sort((left, right) => {
        const leftFocused = composedContains(left, activeElement) ? 1 : 0;
        const rightFocused = composedContains(right, activeElement) ? 1 : 0;
        if (leftFocused !== rightFocused) {
          return rightFocused - leftFocused;
        }
        const leftArea =
          left.getBoundingClientRect().width * left.getBoundingClientRect().height;
        const rightArea =
          right.getBoundingClientRect().width *
          right.getBoundingClientRect().height;
        return leftArea - rightArea;
      })[0];
  const isTopMost = (input: HTMLInputElement): boolean => {
    const rect = input.getBoundingClientRect();
    const x = Math.min(
      Math.max(rect.left + rect.width / 2, 0),
      Math.max(innerWidth - 1, 0)
    );
    const y = Math.min(
      Math.max(rect.top + rect.height / 2, 0),
      Math.max(innerHeight - 1, 0)
    );
    return document
      .elementsFromPoint(x, y)
      .slice(0, 6)
      .some(
        (element) =>
          composedContains(input, element) ||
          composedContains(element, input)
      );
  };
  const fieldText = (input: HTMLInputElement): string =>
    [
      input.autocomplete,
      input.name,
      input.id,
      input.placeholder,
      input.getAttribute("aria-label") ?? ""
    ].join(" ").toLocaleLowerCase();
  const usernameEvidence = (input: HTMLInputElement): boolean => {
    const text = fieldText(input);
    return (
      input === activeElement ||
      /^(?:username|email)$/u.test(input.autocomplete) ||
      input.type === "email" ||
      input.type === "tel" ||
      /(?:user|email|login|account|phone|mobile|用户名|邮箱|账号|手机)/u.test(
        text
      )
    );
  };
  const usernameInputs = queryAll<HTMLInputElement>(
    'input[type="email"], input[type="text"], input[type="tel"], input:not([type])'
  ).filter(
    (input) =>
      visibleInput(input) &&
      input.autocomplete !== "one-time-code" &&
      !/(?:search|query|搜索)/u.test(fieldText(input))
  );
  const passwordInputs = queryAll<HTMLInputElement>(
    'input[type="password"]'
  ).filter(visibleInput);
  const passwordScore = (
    input: HTMLInputElement,
    index: number
  ): number => {
    let score = index / 1_000;
    if (input === activeElement) {
      score += 10_000;
    }
    if (
      activeElement instanceof HTMLInputElement &&
      input.form &&
      activeElement.form === input.form
    ) {
      score += 4_000;
    }
    if (containingModal(input)) {
      score += 3_000;
    }
    if (input.autocomplete === "current-password") {
      score += 1_500;
    } else if (input.autocomplete === "new-password") {
      score -= 1_500;
    }
    if (isTopMost(input)) {
      score += 750;
    }
    return score;
  };
  const rankedPasswords = passwordInputs
    .map((input, index) => ({
      input,
      score: passwordScore(input, index)
    }))
    .sort((left, right) => right.score - left.score);
  const passwordTarget = rankedPasswords[0];
  const passwordInput = passwordTarget?.input;
  const passwordModal = passwordInput
    ? containingModal(passwordInput)
    : undefined;
  const usernameScore = (
    input: HTMLInputElement,
    passwordField?: HTMLInputElement
  ): number => {
    let score = 0;
    const text = fieldText(input);
    if (input === activeElement) {
      score += 10_000;
    }
    if (passwordField?.form && input.form === passwordField.form) {
      score += 4_000;
    }
    if (
      passwordModal &&
      composedContains(passwordModal, input)
    ) {
      score += 2_500;
    } else if (!passwordField && containingModal(input)) {
      score += 2_500;
    }
    if (/^(?:username|email)$/u.test(input.autocomplete)) {
      score += 1_500;
    }
    if (input.type === "email" || input.type === "tel") {
      score += 500;
    }
    if (
      /(?:user|email|login|account|phone|mobile|用户名|邮箱|账号|手机)/u.test(
        text
      )
    ) {
      score += 700;
    }
    if (
      passwordField &&
      input.compareDocumentPosition(passwordField) &
        Node.DOCUMENT_POSITION_FOLLOWING
    ) {
      score += 300;
    }
    if (passwordField) {
      const inputRect = input.getBoundingClientRect();
      const passwordRect = passwordField.getBoundingClientRect();
      const distance =
        Math.abs(inputRect.left - passwordRect.left) +
        Math.abs(inputRect.top - passwordRect.top);
      score += Math.max(0, 500 - Math.min(distance, 500));
    }
    return score;
  };
  const rankedUsernames = usernameInputs
    .filter((input) => Boolean(passwordInput) || usernameEvidence(input))
    .map((input) => ({
      input,
      score: usernameScore(input, passwordInput)
    }))
    .sort((left, right) => right.score - left.score);
  const usernameTarget = rankedUsernames[0];
  const usernameInput = usernameTarget?.input;
  const targetScore = Math.max(
    passwordTarget?.score ?? Number.NEGATIVE_INFINITY,
    usernameTarget?.score ?? Number.NEGATIVE_INFINITY
  );
  const focusedTarget =
    activeElement === passwordInput || activeElement === usernameInput;

  if (!passwordInput && !usernameInput) {
    return failure("当前页面没有可填写的登录输入框");
  }
  if (inspectOnly) {
    return {
      ok: true,
      usernameFilled: Boolean(usernameInput),
      passwordFilled: Boolean(passwordInput),
      message: "已找到登录输入框",
      targetScore,
      focusedTarget
    };
  }

  const setValue = (input: HTMLInputElement, value: string): void => {
    input.focus({ preventScroll: true });
    const inputWindow = input.ownerDocument.defaultView ?? window;
    const descriptor = Object.getOwnPropertyDescriptor(
      inputWindow.HTMLInputElement.prototype,
      "value"
    );
    if (descriptor?.set) {
      descriptor.set.call(input, value);
    } else {
      input.value = value;
    }
    const inputEvent =
      typeof inputWindow.InputEvent === "function"
        ? new inputWindow.InputEvent("input", {
            bubbles: true,
            composed: true,
            data: value,
            inputType: "insertReplacementText"
          })
        : new inputWindow.Event("input", {
            bubbles: true,
            composed: true
          });
    input.dispatchEvent(inputEvent);
    input.dispatchEvent(new inputWindow.Event("change", {
      bubbles: true,
      composed: true
    }));
  };

  let usernameFilled = false;
  if (usernameInput && username.length > 0) {
    setValue(usernameInput, username);
    usernameFilled = true;
  }
  if (passwordInput) {
    setValue(passwordInput, password);
    return {
      ok: true,
      usernameFilled,
      passwordFilled: true,
      message: usernameFilled
        ? "账号和密码已填入，提交前请核对网站域名"
        : "密码已填入，提交前请核对账号和网站域名",
      targetScore,
      focusedTarget
    };
  }
  if (usernameFilled) {
    return {
      ok: true,
      usernameFilled: true,
      passwordFilled: false,
      message: "账号已填入；进入下一步后请再次点击填充密码",
      targetScore,
      focusedTarget
    };
  }
  return failure("当前步骤只有账号输入框，但该密码条目没有账号");
}

export function captureLoginFormInPage(
  expectedOrigin = location.origin,
  allowInsecureLoopbackForTesting = false
): CapturedLoginForm | undefined {
  type QueryRoot = Document | ShadowRoot;

  const trustedProtocol =
    location.protocol === "https:" ||
    (
      allowInsecureLoopbackForTesting &&
      location.protocol === "http:" &&
      (
        location.hostname === "localhost" ||
        location.hostname === "127.0.0.1" ||
        location.hostname === "[::1]"
      )
    );
  if (!trustedProtocol || location.origin !== expectedOrigin) {
    return undefined;
  }
  const composedParent = (node: Node): Node | null => {
    if (node.parentNode) {
      return node.parentNode;
    }
    return node instanceof ShadowRoot ? node.host : null;
  };
  const composedContains = (container: Node, node: Node | null): boolean => {
    let current = node;
    while (current) {
      if (current === container) {
        return true;
      }
      current = composedParent(current);
    }
    return false;
  };
  const roots: QueryRoot[] = [document];
  for (let index = 0; index < roots.length && roots.length < 128; index += 1) {
    const root = roots[index]!;
    for (const element of Array.from(
      root.querySelectorAll<HTMLElement>("*")
    )) {
      if (element.shadowRoot && !roots.includes(element.shadowRoot)) {
        roots.push(element.shadowRoot);
      }
    }
  }
  const queryAll = <ElementType extends Element>(
    selector: string
  ): ElementType[] => {
    const matches = new Set<ElementType>();
    for (const root of roots) {
      for (const element of Array.from(
        root.querySelectorAll<ElementType>(selector)
      )) {
        matches.add(element);
      }
    }
    return [...matches];
  };
  const deepActiveElement = (): Element | null => {
    let active: Element | null = document.activeElement;
    while (
      active instanceof HTMLElement &&
      active.shadowRoot?.activeElement
    ) {
      active = active.shadowRoot.activeElement;
    }
    return active;
  };
  const activeElement = deepActiveElement();
  const visibleElement = (element: HTMLElement): boolean => {
    const style = getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    return (
      !element.hidden &&
      element.getAttribute("aria-hidden") !== "true" &&
      style.display !== "none" &&
      style.visibility !== "hidden" &&
      style.opacity !== "0" &&
      rect.width > 0 &&
      rect.height > 0 &&
      rect.bottom > 0 &&
      rect.right > 0 &&
      rect.top < innerHeight &&
      rect.left < innerWidth
    );
  };
  const visibleInput = (input: HTMLInputElement): boolean =>
    !input.disabled && !input.readOnly && visibleElement(input);
  const modalSelector = [
    "dialog[open]",
    '[role="dialog"]',
    '[aria-modal="true"]',
    "[data-modal]",
    '[class*="modal" i]',
    '[class*="dialog" i]',
    '[class*="popup" i]'
  ].join(",");
  const modals = queryAll<HTMLElement>(modalSelector).filter(visibleElement);
  const containingModal = (input: HTMLInputElement): HTMLElement | undefined =>
    modals.find((modal) => composedContains(modal, input));
  const fieldText = (input: HTMLInputElement): string =>
    [
      input.autocomplete,
      input.name,
      input.id,
      input.placeholder,
      input.getAttribute("aria-label") ?? ""
    ].join(" ").toLocaleLowerCase();
  const passwordInputs = queryAll<HTMLInputElement>(
    'input[type="password"]'
  ).filter((input) => visibleInput(input) && input.value.length > 0);
  const rankedPasswords = passwordInputs
    .map((input, index) => {
      let score = index / 1_000;
      if (input === activeElement) {
        score += 10_000;
      }
      if (containingModal(input)) {
        score += 3_000;
      }
      if (input.autocomplete === "current-password") {
        score += 1_500;
      } else if (input.autocomplete === "new-password") {
        score -= 1_500;
      }
      return { input, score };
    })
    .sort((left, right) => right.score - left.score);
  const passwordTarget = rankedPasswords[0];
  const passwordInput = passwordTarget?.input;
  if (!passwordInput) {
    return undefined;
  }
  const passwordModal = containingModal(passwordInput);
  const usernameInputs = queryAll<HTMLInputElement>(
    'input[type="email"], input[type="text"], input[type="tel"], input:not([type])'
  ).filter(
    (input) =>
      visibleInput(input) &&
      input.autocomplete !== "one-time-code" &&
      !/(?:search|query|搜索)/u.test(fieldText(input))
  );
  const usernameTarget = usernameInputs
    .map((input) => {
      let score = 0;
      const text = fieldText(input);
      if (input === activeElement) {
        score += 10_000;
      }
      if (passwordInput.form && input.form === passwordInput.form) {
        score += 4_000;
      }
      if (passwordModal && composedContains(passwordModal, input)) {
        score += 2_500;
      }
      if (/^(?:username|email)$/u.test(input.autocomplete)) {
        score += 1_500;
      }
      if (input.type === "email" || input.type === "tel") {
        score += 500;
      }
      if (
        /(?:user|email|login|account|phone|mobile|用户名|邮箱|账号|手机)/u.test(
          text
        )
      ) {
        score += 700;
      }
      if (
        input.compareDocumentPosition(passwordInput) &
          Node.DOCUMENT_POSITION_FOLLOWING
      ) {
        score += 300;
      }
      return { input, score };
    })
    .sort((left, right) => right.score - left.score)[0];
  const usernameInput = usernameTarget?.input;

  return {
    origin: location.origin,
    title: document.title.slice(0, 128),
    username: usernameInput?.value ?? "",
    password: passwordInput.value,
    targetScore: Math.max(
      passwordTarget?.score ?? Number.NEGATIVE_INFINITY,
      usernameTarget?.score ?? Number.NEGATIVE_INFINITY
    ),
    focusedTarget:
      activeElement === passwordInput || activeElement === usernameInput
  };
}

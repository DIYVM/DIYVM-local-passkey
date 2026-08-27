const MAX_LABEL_CHARACTERS = 80;

export function conditionalAccountLabel(
  alias: string,
  displayName: string,
  userName: string
): string {
  const preferred = cleanDisplayText(alias) || cleanDisplayText(displayName);
  const normalizedUserName = cleanDisplayText(userName);
  if (
    preferred.length === 0 ||
    preferred.localeCompare(normalizedUserName, undefined, {
      sensitivity: "accent"
    }) === 0
  ) {
    return "本地账户";
  }
  return Array.from(preferred).slice(0, MAX_LABEL_CHARACTERS).join("");
}

export function maskAccountIdentifier(value: string): string {
  const account = cleanDisplayText(value);
  const at = account.lastIndexOf("@");
  if (at > 0 && at < account.length - 1) {
    const local = Array.from(account.slice(0, at));
    const visible = local.slice(0, Math.min(2, local.length)).join("");
    return `${visible}***${account.slice(at)}`;
  }

  if (/^\+?[\d\s().-]{6,}$/u.test(account)) {
    const digits = account.replace(/\D/gu, "");
    return `***${digits.slice(-4)}`;
  }

  const characters = Array.from(account);
  if (characters.length === 0) {
    return "未提供账号";
  }
  if (characters.length <= 2) {
    return `${characters[0]}***`;
  }
  if (characters.length <= 5) {
    return `${characters[0]}***${characters.at(-1)}`;
  }
  return `${characters.slice(0, 2).join("")}***${characters.slice(-2).join("")}`;
}

function cleanDisplayText(value: string): string {
  return value
    .replace(/[\p{Cc}\p{Cf}]/gu, " ")
    .replace(/\s+/gu, " ")
    .trim();
}

export function formatConditionalLastUsed(
  lastUsedAt: number | null,
  now = Date.now()
): string {
  if (lastUsedAt === null) {
    return "尚未使用";
  }
  const elapsedDays = Math.max(
    0,
    Math.floor((now - lastUsedAt) / (24 * 60 * 60 * 1_000))
  );
  if (elapsedDays === 0) {
    return "今天使用过";
  }
  if (elapsedDays === 1) {
    return "昨天使用过";
  }
  if (elapsedDays < 30) {
    return `${elapsedDays} 天前使用`;
  }
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).format(new Date(lastUsedAt));
}

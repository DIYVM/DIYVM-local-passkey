import type {
  PasswordAuditSummary,
  PasswordInput
} from "./types";

const MAX_PASSWORD_BYTES = 16 * 1024;
const MAX_NOTES_BYTES = 64 * 1024;
const MAX_TAGS = 20;
const MAX_TAG_LENGTH = 32;
const STALE_PASSWORD_MS = 365 * 24 * 60 * 60 * 1_000;

const COMMON_PASSWORDS = new Set([
  "123456",
  "12345678",
  "123456789",
  "1234567890",
  "111111",
  "000000",
  "abc123",
  "admin",
  "iloveyou",
  "letmein",
  "password",
  "password1",
  "qwerty",
  "qwerty123",
  "welcome"
]);

export interface PasswordStrength {
  score: number;
  weak: boolean;
  label: "很弱" | "较弱" | "一般" | "较强" | "强";
  suggestions: string[];
}

export interface PasswordGeneratorOptions {
  length?: number;
  uppercase?: boolean;
  lowercase?: boolean;
  numbers?: boolean;
  symbols?: boolean;
  excludeAmbiguous?: boolean;
}

export interface AuditablePassword {
  password: string;
  origin: string;
  updatedAt: number;
  deletedAt: number | null;
}

export function normalizeCredentialOrigin(value: string): string {
  const trimmed = value.trim();
  let url: URL;
  try {
    url = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
  } catch (error) {
    throw new TypeError("请输入有效的网站地址", { cause: error });
  }

  if (
    (url.protocol !== "https:" && url.protocol !== "http:") ||
    url.hostname.length === 0 ||
    url.username !== "" ||
    url.password !== ""
  ) {
    throw new TypeError("密码条目只允许绑定无账号信息的 HTTP/HTTPS 网站");
  }
  return url.origin;
}

export function normalizePasswordInput(input: PasswordInput): Required<
  Omit<PasswordInput, "itemId">
> & { itemId?: string } {
  const name = input.name.trim();
  const username = input.username.trim();
  const password = input.password;
  const notes = input.notes?.trim() ?? "";
  const tags = normalizeTags(input.tags ?? []);
  const origin = normalizeCredentialOrigin(input.origin);

  if (name.length < 1 || name.length > 128) {
    throw new TypeError("条目名称必须为 1 至 128 个字符");
  }
  if (username.length > 512) {
    throw new TypeError("用户名不能超过 512 个字符");
  }
  const passwordBytes = new TextEncoder().encode(password).byteLength;
  if (passwordBytes < 1 || passwordBytes > MAX_PASSWORD_BYTES) {
    throw new TypeError("密码必须为 1 至 16384 个 UTF-8 字节");
  }
  if (new TextEncoder().encode(notes).byteLength > MAX_NOTES_BYTES) {
    throw new TypeError("加密备注不能超过 64 KiB");
  }

  return {
    ...(input.itemId ? { itemId: input.itemId } : {}),
    name,
    origin,
    username,
    password,
    notes,
    favorite: input.favorite === true,
    tags,
    autoFill:
      input.autoFill === true && new URL(origin).protocol === "https:"
  };
}

export function normalizeTags(tags: readonly string[]): string[] {
  if (!Array.isArray(tags) || tags.length > MAX_TAGS) {
    throw new TypeError(`标签数量不能超过 ${MAX_TAGS} 个`);
  }
  const normalized = new Set<string>();
  for (const rawTag of tags) {
    if (typeof rawTag !== "string") {
      throw new TypeError("标签必须为文本");
    }
    const tag = rawTag.trim();
    if (tag.length === 0) {
      continue;
    }
    if (tag.length > MAX_TAG_LENGTH) {
      throw new TypeError(`单个标签不能超过 ${MAX_TAG_LENGTH} 个字符`);
    }
    normalized.add(tag);
  }
  return [...normalized].sort((left, right) => left.localeCompare(right));
}

export function passwordStrength(password: string): PasswordStrength {
  const suggestions: string[] = [];
  const normalized = password.toLocaleLowerCase("en-US");
  let score = 0;

  if (password.length >= 12) {
    score += 1;
  } else {
    suggestions.push("建议至少使用 12 个字符");
  }
  if (password.length >= 16) {
    score += 1;
  }

  const characterGroups = [
    /[a-z]/u.test(password),
    /[A-Z]/u.test(password),
    /\d/u.test(password),
    /[^A-Za-z0-9]/u.test(password)
  ].filter(Boolean).length;
  if (characterGroups >= 3) {
    score += 1;
  } else {
    suggestions.push("混合使用大小写字母、数字或符号");
  }

  const uniqueRatio =
    password.length === 0
      ? 0
      : new Set(password).size / password.length;
  if (uniqueRatio >= 0.5 && !/(.)\1{2,}/u.test(password)) {
    score += 1;
  } else {
    suggestions.push("避免连续重复字符和简单规律");
  }

  if (
    COMMON_PASSWORDS.has(normalized) ||
    /^(?:1234|abcd|qwerty|password)/u.test(normalized)
  ) {
    score = Math.min(score, 1);
    suggestions.unshift("该密码过于常见，请更换");
  }

  score = Math.max(0, Math.min(4, score));
  const labels = ["很弱", "较弱", "一般", "较强", "强"] as const;
  return {
    score,
    weak: score < 3,
    label: labels[score] ?? "很弱",
    suggestions
  };
}

export function auditPasswords(
  passwords: readonly AuditablePassword[],
  now = Date.now()
): {
  summary: PasswordAuditSummary;
  reusedPasswords: Set<string>;
} {
  const active = passwords.filter((item) => item.deletedAt === null);
  const counts = new Map<string, number>();
  for (const item of active) {
    counts.set(item.password, (counts.get(item.password) ?? 0) + 1);
  }
  const reusedPasswords = new Set(
    [...counts].filter(([, count]) => count > 1).map(([password]) => password)
  );

  return {
    summary: {
      total: active.length,
      weak: active.filter((item) => passwordStrength(item.password).weak).length,
      reused: active.filter((item) => reusedPasswords.has(item.password)).length,
      stale: active.filter((item) => now - item.updatedAt >= STALE_PASSWORD_MS)
        .length,
      insecureOrigins: active.filter((item) => !item.origin.startsWith("https://"))
        .length
    },
    reusedPasswords
  };
}

export function generatePassword(
  options: PasswordGeneratorOptions = {}
): string {
  const length = options.length ?? 20;
  if (!Number.isInteger(length) || length < 12 || length > 128) {
    throw new TypeError("生成密码长度必须为 12 至 128");
  }

  const excludeAmbiguous = options.excludeAmbiguous !== false;
  const groups = [
    options.lowercase === false
      ? ""
      : excludeAmbiguous
        ? "abcdefghijkmnopqrstuvwxyz"
        : "abcdefghijklmnopqrstuvwxyz",
    options.uppercase === false
      ? ""
      : excludeAmbiguous
        ? "ABCDEFGHJKLMNPQRSTUVWXYZ"
        : "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    options.numbers === false
      ? ""
      : excludeAmbiguous
        ? "23456789"
        : "0123456789",
    options.symbols === false ? "" : "!@#$%^&*()-_=+[]{}:,.?"
  ].filter((group) => group.length > 0);

  if (groups.length === 0) {
    throw new TypeError("至少选择一种字符类型");
  }
  if (length < groups.length) {
    throw new TypeError("密码长度不足以包含所选字符类型");
  }

  const characters = groups.map((group) => randomCharacter(group));
  const alphabet = groups.join("");
  while (characters.length < length) {
    characters.push(randomCharacter(alphabet));
  }
  for (let index = characters.length - 1; index > 0; index -= 1) {
    const swapIndex = randomInteger(index + 1);
    const current = characters[index]!;
    characters[index] = characters[swapIndex]!;
    characters[swapIndex] = current;
  }
  return characters.join("");
}

function randomCharacter(alphabet: string): string {
  return alphabet[randomInteger(alphabet.length)]!;
}

function randomInteger(upperBound: number): number {
  if (!Number.isInteger(upperBound) || upperBound < 1 || upperBound > 65_536) {
    throw new TypeError("Invalid random upper bound");
  }
  const limit = Math.floor(0x1_0000_0000 / upperBound) * upperBound;
  const value = new Uint32Array(1);
  do {
    crypto.getRandomValues(value);
  } while (value[0]! >= limit);
  return value[0]! % upperBound;
}

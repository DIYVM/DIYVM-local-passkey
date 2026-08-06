import { normalizeCredentialOrigin } from "./password-model";
import type { VaultSettings } from "./types";

const LEGACY_AMAZON_SCRIPT_PREFIX = "diyvm-amazon-";
const AUTOFILL_SCRIPT_PREFIX = "diyvm-autofill-";
const ALL_HTTPS_SCRIPT_PREFIX = "diyvm-passkey-all-https-";
const ALL_HTTPS_MAIN_SCRIPT_ID = `${ALL_HTTPS_SCRIPT_PREFIX}main`;
const ALL_HTTPS_ISOLATED_SCRIPT_ID = `${ALL_HTTPS_SCRIPT_PREFIX}isolated`;
const PERMISSION_TRANSITION_KEY = "diyvmPasskeyPermissionTransition";
const PERMISSION_TRANSITION_MAX_AGE_MS = 30_000;

export const ALL_HTTPS_MATCH_PATTERN = "https://*/*";

export async function requestAllHttpsPasskeys(): Promise<boolean> {
  return chrome.permissions.request({
    origins: [ALL_HTTPS_MATCH_PATTERN]
  });
}

export async function removeAllHttpsPasskeys(
  retainedOrigins: readonly string[]
): Promise<{ removed: boolean; retained: boolean }> {
  const origins = [...new Set(
    retainedOrigins.filter(
      (origin) =>
        origin.startsWith("https://") &&
        origin.endsWith("/*") &&
        origin.length <= 2048
    )
  )];
  await chrome.storage.session.set({
    [PERMISSION_TRANSITION_KEY]: Date.now()
  });
  try {
    await unregisterByIds([
      ALL_HTTPS_MAIN_SCRIPT_ID,
      ALL_HTTPS_ISOLATED_SCRIPT_ID
    ]);
    const removed = await chrome.permissions.remove({
      origins: [ALL_HTTPS_MATCH_PATTERN]
    });
    const retained =
      origins.length === 0 ||
      await chrome.permissions.request({ origins });
    return { removed, retained };
  } finally {
    await chrome.storage.session.remove(PERMISSION_TRANSITION_KEY);
  }
}

export async function sitePermissionTransitionInProgress(): Promise<boolean> {
  const stored = await chrome.storage.session.get(PERMISSION_TRANSITION_KEY);
  const startedAt = stored[PERMISSION_TRANSITION_KEY];
  if (
    typeof startedAt === "number" &&
    Date.now() - startedAt >= 0 &&
    Date.now() - startedAt < PERMISSION_TRANSITION_MAX_AGE_MS
  ) {
    return true;
  }
  await chrome.storage.session.remove(PERMISSION_TRANSITION_KEY);
  return false;
}

export async function requestAutoFillOrigin(originValue: string): Promise<{
  granted: boolean;
  origin: string;
}> {
  const origin = normalizeCredentialOrigin(originValue);
  if (new URL(origin).protocol !== "https:") {
    throw new TypeError("自动填充只允许用于 HTTPS 网站");
  }
  return {
    granted: await chrome.permissions.request({
      origins: [`${origin}/*`]
    }),
    origin
  };
}

export async function removeAutoFillOrigin(
  originValue: string
): Promise<boolean> {
  const origin = normalizeCredentialOrigin(originValue);
  if (new URL(origin).protocol !== "https:") {
    throw new TypeError("自动填充只允许用于 HTTPS 网站");
  }
  const removed = await chrome.permissions.remove({
    origins: [`${origin}/*`]
  });
  await unregisterByIds([autoFillScriptId(origin)]);
  return removed;
}

export async function syncRegisteredContentScripts(
  settings: VaultSettings
): Promise<void> {
  const existing = await chrome.scripting.getRegisteredContentScripts();
  const managedIds = existing
    .map((script) => script.id)
    .filter(
      (id) =>
        id.startsWith(LEGACY_AMAZON_SCRIPT_PREFIX) ||
        id.startsWith(AUTOFILL_SCRIPT_PREFIX) ||
        id.startsWith(ALL_HTTPS_SCRIPT_PREFIX)
    );
  await unregisterByIds(managedIds);

  const scripts: chrome.scripting.RegisteredContentScript[] = [];
  if (
    settings.passkeyAllHttps &&
    await chrome.permissions.contains({
      origins: [ALL_HTTPS_MATCH_PATTERN]
    })
  ) {
    scripts.push(
      {
        id: ALL_HTTPS_MAIN_SCRIPT_ID,
        matches: [ALL_HTTPS_MATCH_PATTERN],
        js: ["page-bridge.js"],
        runAt: "document_start",
        world: "MAIN",
        allFrames: false,
        persistAcrossSessions: true
      },
      {
        id: ALL_HTTPS_ISOLATED_SCRIPT_ID,
        matches: [ALL_HTTPS_MATCH_PATTERN],
        js: ["content-script.js"],
        runAt: "document_start",
        world: "ISOLATED",
        allFrames: false,
        persistAcrossSessions: true
      }
    );
  }

  for (const origin of settings.autoFillOrigins) {
    if (
      !(await chrome.permissions.contains({
        origins: [`${origin}/*`]
      }))
    ) {
      continue;
    }
    scripts.push({
      id: autoFillScriptId(origin),
      matches: [`${origin}/*`],
      js: ["password-autofill.js"],
      runAt: "document_idle",
      world: "ISOLATED",
      allFrames: true,
      persistAcrossSessions: true
    });
  }

  if (scripts.length > 0) {
    await chrome.scripting.registerContentScripts(scripts);
  }
}

function autoFillScriptId(origin: string): string {
  return `${AUTOFILL_SCRIPT_PREFIX}${safeId(origin)}`;
}

function safeId(value: string): string {
  const encoded = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of encoded) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

async function unregisterByIds(ids: string[]): Promise<void> {
  if (ids.length === 0) {
    return;
  }
  await chrome.scripting.unregisterContentScripts({ ids }).catch(() => undefined);
}

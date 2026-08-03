import {
  AMAZON_MARKETPLACES,
  PRIMARY_AMAZON_DOMAIN,
  amazonMatchPatterns,
  isAmazonMarketplaceDomain
} from "./amazon-sites";
import { normalizeCredentialOrigin } from "./password-model";
import type { VaultSettings } from "./types";

const AMAZON_SCRIPT_PREFIX = "diyvm-amazon-";
const AUTOFILL_SCRIPT_PREFIX = "diyvm-autofill-";

export async function requestAmazonRegion(domain: string): Promise<boolean> {
  const normalized = domain.toLowerCase();
  if (
    normalized === PRIMARY_AMAZON_DOMAIN ||
    !isAmazonMarketplaceDomain(normalized)
  ) {
    return normalized === PRIMARY_AMAZON_DOMAIN;
  }
  return chrome.permissions.request({
    origins: amazonMatchPatterns(normalized)
  });
}

export async function removeAmazonRegion(domain: string): Promise<boolean> {
  const normalized = domain.toLowerCase();
  if (
    normalized === PRIMARY_AMAZON_DOMAIN ||
    !isAmazonMarketplaceDomain(normalized)
  ) {
    return false;
  }
  const removed = await chrome.permissions.remove({
    origins: amazonMatchPatterns(normalized)
  });
  await unregisterByIds([
    amazonMainScriptId(normalized),
    amazonIsolatedScriptId(normalized)
  ]);
  return removed;
}

export async function grantedAmazonRegions(): Promise<string[]> {
  const domains: string[] = [];
  for (const marketplace of AMAZON_MARKETPLACES) {
    if (marketplace.domain === PRIMARY_AMAZON_DOMAIN) {
      continue;
    }
    if (
      await chrome.permissions.contains({
        origins: amazonMatchPatterns(marketplace.domain)
      })
    ) {
      domains.push(marketplace.domain);
    }
  }
  return domains;
}

export async function requestAutoFillOrigin(originValue: string): Promise<{
  granted: boolean;
  origin: string;
}> {
  const origin = normalizeCredentialOrigin(originValue);
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
        id.startsWith(AMAZON_SCRIPT_PREFIX) ||
        id.startsWith(AUTOFILL_SCRIPT_PREFIX)
    );
  await unregisterByIds(managedIds);

  const scripts: chrome.scripting.RegisteredContentScript[] = [];
  for (const domain of settings.enabledAmazonRegions) {
    if (
      domain === PRIMARY_AMAZON_DOMAIN ||
      !isAmazonMarketplaceDomain(domain) ||
      !(await chrome.permissions.contains({
        origins: amazonMatchPatterns(domain)
      }))
    ) {
      continue;
    }
    const matches = amazonMatchPatterns(domain);
    scripts.push(
      {
        id: amazonMainScriptId(domain),
        matches,
        js: ["page-bridge.js"],
        runAt: "document_start",
        world: "MAIN",
        allFrames: false,
        persistAcrossSessions: true
      },
      {
        id: amazonIsolatedScriptId(domain),
        matches,
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

function amazonMainScriptId(domain: string): string {
  return `${AMAZON_SCRIPT_PREFIX}main-${safeId(domain)}`;
}

function amazonIsolatedScriptId(domain: string): string {
  return `${AMAZON_SCRIPT_PREFIX}isolated-${safeId(domain)}`;
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

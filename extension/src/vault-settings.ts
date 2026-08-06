import type {
  AutoLockMinutes,
  VaultSettings
} from "./types";

const SETTINGS_KEY = "localVaultSettingsV1";
const AUTO_LOCK_VALUES = new Set<AutoLockMinutes>([
  5,
  15,
  30,
  60,
  120,
  480,
  1440
]);

export const DEFAULT_VAULT_SETTINGS: VaultSettings = {
  autoLockMinutes: 15,
  lastBackupAt: null,
  passkeyAllHttps: false,
  autoFillOrigins: []
};

export interface VaultSettingsStorage {
  read(): Promise<VaultSettings>;
  write(settings: VaultSettings): Promise<void>;
}

export class ChromeVaultSettingsStorage implements VaultSettingsStorage {
  async read(): Promise<VaultSettings> {
    const value = await chrome.storage.local.get(SETTINGS_KEY);
    return parseVaultSettings(value[SETTINGS_KEY]);
  }

  async write(settings: VaultSettings): Promise<void> {
    await chrome.storage.local.set({
      [SETTINGS_KEY]: parseVaultSettings(settings)
    });
  }
}

export class MemoryVaultSettingsStorage implements VaultSettingsStorage {
  private settings = structuredClone(DEFAULT_VAULT_SETTINGS);

  async read(): Promise<VaultSettings> {
    return structuredClone(this.settings);
  }

  async write(settings: VaultSettings): Promise<void> {
    this.settings = parseVaultSettings(settings);
  }
}

export async function updateVaultSettings(
  storage: VaultSettingsStorage,
  patch: Partial<VaultSettings>
): Promise<VaultSettings> {
  const current = await storage.read();
  const updated = parseVaultSettings({ ...current, ...patch });
  await storage.write(updated);
  return updated;
}

export function parseVaultSettings(value: unknown): VaultSettings {
  if (typeof value !== "object" || value === null) {
    return structuredClone(DEFAULT_VAULT_SETTINGS);
  }
  const candidate = value as Partial<VaultSettings>;
  const autoLockMinutes = AUTO_LOCK_VALUES.has(
    candidate.autoLockMinutes as AutoLockMinutes
  )
    ? candidate.autoLockMinutes as AutoLockMinutes
    : DEFAULT_VAULT_SETTINGS.autoLockMinutes;
  const lastBackupAt =
    candidate.lastBackupAt === null ||
    (Number.isSafeInteger(candidate.lastBackupAt) &&
      (candidate.lastBackupAt ?? -1) >= 0)
      ? candidate.lastBackupAt ?? null
      : null;
  const autoFillOrigins = uniqueStrings(candidate.autoFillOrigins, (origin) => {
    try {
      const url = new URL(origin);
      return (
        url.origin === origin &&
        url.protocol === "https:" &&
        url.username === "" &&
        url.password === ""
      );
    } catch {
      return false;
    }
  });
  return {
    autoLockMinutes,
    lastBackupAt,
    passkeyAllHttps: candidate.passkeyAllHttps === true,
    autoFillOrigins
  };
}

function uniqueStrings(
  value: unknown,
  predicate: (item: string) => boolean
): string[] {
  if (!Array.isArray(value) || value.length > 100) {
    return [];
  }
  const result = new Set<string>();
  for (const item of value) {
    if (typeof item === "string" && predicate(item)) {
      result.add(item);
    }
  }
  return [...result].sort((left, right) => left.localeCompare(right));
}

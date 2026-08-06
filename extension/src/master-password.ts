export const MIN_MASTER_PASSWORD_CHARACTERS = 8;
export const MAX_MASTER_PASSWORD_CHARACTERS = 1024;
export const MAX_MASTER_PASSWORD_UTF8_BYTES = 4096;

export function masterPasswordCharacterCount(value: string): number {
  return [...value].length;
}

export function isExistingMasterPassword(value: unknown): value is string {
  return (
    typeof value === "string" &&
    masterPasswordCharacterCount(value) >= 1 &&
    masterPasswordCharacterCount(value) <= MAX_MASTER_PASSWORD_CHARACTERS &&
    new TextEncoder().encode(value).byteLength <= MAX_MASTER_PASSWORD_UTF8_BYTES
  );
}

export function isNewMasterPassword(value: unknown): value is string {
  return (
    isExistingMasterPassword(value) &&
    masterPasswordCharacterCount(value) >= MIN_MASTER_PASSWORD_CHARACTERS
  );
}

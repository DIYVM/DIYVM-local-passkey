export type VaultState = "notInitialized" | "locked" | "unlocked";

export interface CredentialSummary {
  credentialId: string;
  rpId: string;
  userName: string | null;
  displayName: string | null;
  alias: string | null;
  favorite: boolean;
  tags: string[];
  signCount: number;
  createdAt: number;
  lastUsedAt: number | null;
  deletedAt: number | null;
}

export interface PasswordSummary {
  itemId: string;
  name: string;
  origin: string;
  username: string;
  favorite: boolean;
  tags: string[];
  autoFill: boolean;
  createdAt: number;
  updatedAt: number;
  lastUsedAt: number | null;
  deletedAt: number | null;
  strengthScore: number;
  weak: boolean;
  reused: boolean;
}

export interface PasswordDetails {
  itemId: string;
  name: string;
  origin: string;
  username: string;
  password: string;
  notes: string;
  favorite: boolean;
  tags: string[];
  autoFill: boolean;
  createdAt: number;
  updatedAt: number;
  lastUsedAt: number | null;
  deletedAt: number | null;
}

export interface PasswordInput {
  itemId?: string;
  name: string;
  origin: string;
  username: string;
  password: string;
  notes?: string;
  favorite?: boolean;
  tags?: string[];
  autoFill?: boolean;
}

export interface PasswordAuditSummary {
  total: number;
  weak: number;
  reused: number;
  stale: number;
  insecureOrigins: number;
}

export type AutoLockMinutes = 5 | 15 | 30 | 60 | 120 | 480 | 1440;

export interface VaultSettings {
  autoLockMinutes: AutoLockMinutes;
  lastBackupAt: number | null;
  passkeyAllHttps: boolean;
  autoFillOrigins: string[];
}

export interface VaultStatus {
  vaultState: VaultState;
  itemCount: number;
  passkeyCount: number;
  passwordCount: number;
  trashCount: number;
  settings: VaultSettings;
  passwordAudit: PasswordAuditSummary;
}

export interface OssConfigurationSummary {
  endpoint: string;
  region: string;
  bucket: string;
  objectKey: string;
  accessKeyId: string;
  lastUploadedAt: number | null;
  lastEtag: string | null;
  updatedAt: number;
}

export interface OssRemoteBackupInfo {
  itemCount: number;
  exportedAt: string;
  kdf: "ARGON2ID" | "PBKDF2-SHA-256";
  size: number | null;
  etag: string | null;
  lastModifiedAt: number | null;
  versionId: string | null;
}

export type ExtensionErrorCode =
  | "INVALID_MESSAGE"
  | "INVALID_REQUEST_ID"
  | "MESSAGE_TOO_LARGE"
  | "ABORTED"
  | "INVALID_STATE"
  | "NOT_ALLOWED"
  | "NOT_SUPPORTED"
  | "SECURITY_ERROR"
  | "VAULT_LOCKED"
  | "VAULT_NOT_INITIALIZED"
  | "INVALID_PASSWORD"
  | "CREDENTIAL_NOT_FOUND"
  | "PERMISSION_DENIED"
  | "UNSUPPORTED_MESSAGE"
  | "UNSUPPORTED_PROTOCOL"
  | "USE_NATIVE_AUTHENTICATOR"
  | "INTERNAL_ERROR";

export interface SerializedCredentialDescriptor {
  type: "public-key";
  id: string;
  transports?: string[];
}

export interface SerializedCreationOptions {
  rp: {
    id?: string;
    name: string;
  };
  user: {
    id: string;
    name: string;
    displayName: string;
  };
  challenge: string;
  pubKeyCredParams: Array<{
    type: "public-key";
    alg: number;
  }>;
  timeout?: number;
  excludeCredentials?: SerializedCredentialDescriptor[];
  authenticatorSelection?: {
    authenticatorAttachment?: string;
    residentKey?: string;
    requireResidentKey?: boolean;
    userVerification?: string;
  };
  hints?: string[];
  attestation?: string;
  attestationFormats?: string[];
  extensions?: Record<string, unknown>;
}

export interface SerializedRequestOptions {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: SerializedCredentialDescriptor[];
  userVerification?: string;
  hints?: string[];
  extensions?: Record<string, unknown>;
}

export interface SerializedCreatedCredential {
  id: string;
  rawId: string;
  type: "public-key";
  authenticatorAttachment: "platform";
  response: {
    clientDataJSON: string;
    attestationObject: string;
    authenticatorData: string;
    publicKey: string | null;
    publicKeyAlgorithm: number;
    transports: string[];
  };
  clientExtensionResults: Record<string, unknown>;
}

export interface SerializedAssertionCredential {
  id: string;
  rawId: string;
  type: "public-key";
  authenticatorAttachment: "platform";
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle: string | null;
  };
  clientExtensionResults: Record<string, unknown>;
}

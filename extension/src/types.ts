export type VaultState = "notInitialized" | "locked" | "unlocked";

export interface CredentialSummary {
  credentialId: string;
  rpId: string;
  userName: string | null;
  displayName: string | null;
  signCount: number;
  createdAt: number;
  lastUsedAt: number | null;
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

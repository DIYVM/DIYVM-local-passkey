import type {
  ExtensionErrorCode,
  SerializedAssertionCredential,
  SerializedCreatedCredential,
  SerializedCreationOptions,
  SerializedCredentialDescriptor,
  SerializedRequestOptions
} from "./types";

import {
  BRIDGE_CHANNEL,
  type ExtensionBridgeResponse,
  type PageBridgeCancel,
  type PageBridgeRequest
} from "./bridge-messages";

const MAX_CEREMONY_MS = 120_000;
const MIN_CEREMONY_MS = 15_000;

type PendingRequest = {
  operation: "create" | "get";
  resolve: (credential: Credential | null) => void;
  reject: (error: unknown) => void;
  fallback: () => Promise<Credential | null>;
  timeout: ReturnType<typeof setTimeout>;
  signal?: AbortSignal;
  abortHandler?: () => void;
};

const pending = new Map<string, PendingRequest>();
const credentials = navigator.credentials;
const originalCreate = credentials.create.bind(credentials);
const originalGet = credentials.get.bind(credentials);

window.addEventListener("message", handleExtensionMessage);

try {
  Object.defineProperties(credentials, {
    create: {
      configurable: true,
      value: interceptCreate
    },
    get: {
      configurable: true,
      value: interceptGet
    }
  });
} catch {
  // If Chrome changes the property descriptors, leave Chrome WebAuthn untouched.
}

function interceptCreate(
  options?: CredentialCreationOptions
): Promise<Credential | null> {
  if (!options?.publicKey) {
    return originalCreate(options);
  }

  let serialized: SerializedCreationOptions;
  try {
    serialized = serializeCreationOptions(options.publicKey);
  } catch {
    return originalCreate(options);
  }

  return dispatchRequest(
    "create",
    serialized,
    options.publicKey.timeout,
    options.signal,
    () => originalCreate(options)
  );
}

function interceptGet(
  options?: CredentialRequestOptions
): Promise<Credential | null> {
  if (!options?.publicKey || options.mediation === "conditional") {
    return originalGet(options);
  }

  let serialized: SerializedRequestOptions;
  try {
    serialized = serializeRequestOptions(options.publicKey);
  } catch {
    return originalGet(options);
  }

  return dispatchRequest(
    "get",
    serialized,
    options.publicKey.timeout,
    options.signal,
    () => originalGet(options)
  );
}

function dispatchRequest(
  operation: "create",
  publicKey: SerializedCreationOptions,
  requestedTimeout: number | undefined,
  signal: AbortSignal | undefined,
  fallback: () => Promise<Credential | null>
): Promise<Credential | null>;
function dispatchRequest(
  operation: "get",
  publicKey: SerializedRequestOptions,
  requestedTimeout: number | undefined,
  signal: AbortSignal | undefined,
  fallback: () => Promise<Credential | null>
): Promise<Credential | null>;
function dispatchRequest(
  operation: "create" | "get",
  publicKey: SerializedCreationOptions | SerializedRequestOptions,
  requestedTimeout: number | undefined,
  signal: AbortSignal | undefined,
  fallback: () => Promise<Credential | null>
): Promise<Credential | null> {
  if (signal?.aborted) {
    return Promise.reject(new DOMException("The request was aborted", "AbortError"));
  }

  const requestId = crypto.randomUUID().replaceAll("-", "");
  const timeoutMs = clampTimeout(requestedTimeout);

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      const request = pending.get(requestId);
      if (!request) {
        return;
      }
      cleanupPending(requestId, request);
      const cancel: PageBridgeCancel = {
        channel: BRIDGE_CHANNEL,
        source: "page",
        kind: "cancel",
        requestId
      };
      window.postMessage(cancel, location.origin);
      void fallback().then(resolve, reject);
    }, timeoutMs);

    const request: PendingRequest = {
      operation,
      resolve,
      reject,
      fallback,
      timeout,
      ...(signal ? { signal } : {})
    };

    if (signal) {
      request.abortHandler = () => {
        cleanupPending(requestId, request);
        const cancel: PageBridgeCancel = {
          channel: BRIDGE_CHANNEL,
          source: "page",
          kind: "cancel",
          requestId
        };
        window.postMessage(cancel, location.origin);
        reject(new DOMException("The request was aborted", "AbortError"));
      };
      signal.addEventListener("abort", request.abortHandler, { once: true });
    }

    pending.set(requestId, request);

    const message: PageBridgeRequest =
      operation === "create"
        ? {
            channel: BRIDGE_CHANNEL,
            source: "page",
            kind: "request",
            requestId,
            operation,
            publicKey: publicKey as SerializedCreationOptions
          }
        : {
            channel: BRIDGE_CHANNEL,
            source: "page",
            kind: "request",
            requestId,
            operation,
            publicKey: publicKey as SerializedRequestOptions
          };
    window.postMessage(message, location.origin);
  });
}

function handleExtensionMessage(event: MessageEvent<unknown>): void {
  if (
    event.source !== window ||
    event.origin !== location.origin ||
    !isExtensionResponse(event.data)
  ) {
    return;
  }

  const request = pending.get(event.data.requestId);
  if (!request) {
    return;
  }
  cleanupPending(event.data.requestId, request);

  if (!event.data.ok) {
    if (event.data.error.code === "USE_NATIVE_AUTHENTICATOR") {
      void request.fallback().then(request.resolve, request.reject);
      return;
    }
    request.reject(toDomException(event.data.error.code, event.data.error.message));
    return;
  }

  try {
    if (event.data.operation !== request.operation) {
      throw new DOMException("Mismatched WebAuthn response", "UnknownError");
    }
    request.resolve(
      event.data.operation === "create"
        ? restoreCreatedCredential(event.data.credential)
        : restoreAssertionCredential(event.data.credential)
    );
  } catch (error) {
    request.reject(error);
  }
}

function cleanupPending(requestId: string, request: PendingRequest): void {
  pending.delete(requestId);
  clearTimeout(request.timeout);
  if (request.signal && request.abortHandler) {
    request.signal.removeEventListener("abort", request.abortHandler);
  }
}

function restoreCreatedCredential(
  serialized: SerializedCreatedCredential
): PublicKeyCredential {
  const response = Object.create(
    globalThis.AuthenticatorAttestationResponse?.prototype ?? Object.prototype
  ) as AuthenticatorAttestationResponse;
  const clientDataJSON = decodeBase64Url(serialized.response.clientDataJSON);
  const attestationObject = decodeBase64Url(
    serialized.response.attestationObject
  );
  const authenticatorData = decodeBase64Url(
    serialized.response.authenticatorData
  );
  const publicKey = serialized.response.publicKey
    ? decodeBase64Url(serialized.response.publicKey)
    : null;

  Object.defineProperties(response, {
    clientDataJSON: { enumerable: true, value: clientDataJSON },
    attestationObject: { enumerable: true, value: attestationObject },
    getAuthenticatorData: {
      value: () => authenticatorData.slice(0)
    },
    getPublicKey: {
      value: () => publicKey?.slice(0) ?? null
    },
    getPublicKeyAlgorithm: {
      value: () => serialized.response.publicKeyAlgorithm
    },
    getTransports: {
      value: () => [...serialized.response.transports]
    }
  });

  return restoreCredentialBase(serialized, response);
}

function restoreAssertionCredential(
  serialized: SerializedAssertionCredential
): PublicKeyCredential {
  const response = Object.create(
    globalThis.AuthenticatorAssertionResponse?.prototype ?? Object.prototype
  ) as AuthenticatorAssertionResponse;

  Object.defineProperties(response, {
    clientDataJSON: {
      enumerable: true,
      value: decodeBase64Url(serialized.response.clientDataJSON)
    },
    authenticatorData: {
      enumerable: true,
      value: decodeBase64Url(serialized.response.authenticatorData)
    },
    signature: {
      enumerable: true,
      value: decodeBase64Url(serialized.response.signature)
    },
    userHandle: {
      enumerable: true,
      value: serialized.response.userHandle
        ? decodeBase64Url(serialized.response.userHandle)
        : null
    }
  });

  return restoreCredentialBase(serialized, response);
}

function restoreCredentialBase(
  serialized: SerializedCreatedCredential | SerializedAssertionCredential,
  response: AuthenticatorResponse
): PublicKeyCredential {
  const credential = Object.create(
    globalThis.PublicKeyCredential?.prototype ?? Object.prototype
  ) as PublicKeyCredential;
  const extensionResults = cloneJson(serialized.clientExtensionResults);

  Object.defineProperties(credential, {
    id: { enumerable: true, value: serialized.id },
    rawId: { enumerable: true, value: decodeBase64Url(serialized.rawId) },
    type: { enumerable: true, value: "public-key" },
    response: { enumerable: true, value: response },
    authenticatorAttachment: {
      enumerable: true,
      value: serialized.authenticatorAttachment
    },
    getClientExtensionResults: {
      value: () => cloneJson(extensionResults)
    },
    toJSON: {
      value: () => cloneJson(serialized)
    }
  });

  return credential;
}

function serializeCreationOptions(
  options: PublicKeyCredentialCreationOptions
): SerializedCreationOptions {
  const level3 = options as PublicKeyCredentialCreationOptions & {
    hints?: readonly string[];
    attestationFormats?: readonly string[];
  };

  return compact({
    rp: compact({
      id: options.rp.id,
      name: options.rp.name
    }),
    user: {
      id: encodeBase64Url(options.user.id),
      name: options.user.name,
      displayName: options.user.displayName
    },
    challenge: encodeBase64Url(options.challenge),
    pubKeyCredParams: options.pubKeyCredParams.map((parameter) => ({
      type: "public-key" as const,
      alg: parameter.alg
    })),
    timeout: options.timeout,
    excludeCredentials: options.excludeCredentials?.map(serializeDescriptor),
    authenticatorSelection: options.authenticatorSelection
      ? compact({
          authenticatorAttachment:
            options.authenticatorSelection.authenticatorAttachment,
          residentKey: options.authenticatorSelection.residentKey,
          requireResidentKey:
            options.authenticatorSelection.requireResidentKey,
          userVerification: options.authenticatorSelection.userVerification
        })
      : undefined,
    hints: level3.hints ? [...level3.hints] : undefined,
    attestation: options.attestation,
    attestationFormats: level3.attestationFormats
      ? [...level3.attestationFormats]
      : undefined,
    extensions: serializeExtensions(options.extensions)
  }) as SerializedCreationOptions;
}

function serializeRequestOptions(
  options: PublicKeyCredentialRequestOptions
): SerializedRequestOptions {
  const level3 = options as PublicKeyCredentialRequestOptions & {
    hints?: readonly string[];
  };

  return compact({
    challenge: encodeBase64Url(options.challenge),
    timeout: options.timeout,
    rpId: options.rpId,
    allowCredentials: options.allowCredentials?.map(serializeDescriptor),
    userVerification: options.userVerification,
    hints: level3.hints ? [...level3.hints] : undefined,
    extensions: serializeExtensions(options.extensions)
  }) as SerializedRequestOptions;
}

function serializeDescriptor(
  descriptor: PublicKeyCredentialDescriptor
): SerializedCredentialDescriptor {
  return compact({
    type: "public-key" as const,
    id: encodeBase64Url(descriptor.id),
    transports: descriptor.transports
      ? [...descriptor.transports]
      : undefined
  }) as SerializedCredentialDescriptor;
}

function serializeExtensions(
  extensions: AuthenticationExtensionsClientInputs | undefined
): Record<string, unknown> | undefined {
  if (!extensions) {
    return undefined;
  }
  return serializeUnknown(extensions, 0) as Record<string, unknown>;
}

function serializeUnknown(value: unknown, depth: number): unknown {
  if (depth > 6) {
    throw new TypeError("WebAuthn extension input is too deeply nested");
  }
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
    return encodeBase64Url(value);
  }
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > 64) {
      throw new TypeError("WebAuthn extension array is too large");
    }
    return value.map((item) => serializeUnknown(item, depth + 1));
  }
  if (typeof value === "object") {
    const entries = Object.entries(value);
    if (entries.length > 64) {
      throw new TypeError("WebAuthn extension object has too many fields");
    }
    return Object.fromEntries(
      entries
        .filter(([, item]) => item !== undefined)
        .map(([key, item]) => [key, serializeUnknown(item, depth + 1)])
    );
  }
  throw new TypeError("Unsupported WebAuthn extension value");
}

function encodeBase64Url(
  source: ArrayBuffer | ArrayBufferView<ArrayBufferLike>
): string {
  const bytes =
    source instanceof ArrayBuffer
      ? new Uint8Array(source)
      : new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

function decodeBase64Url(value: string): ArrayBuffer {
  const padded = value
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes.buffer;
}

function compact<T extends Record<string, unknown>>(value: T): Partial<T> {
  return Object.fromEntries(
    Object.entries(value).filter(([, item]) => item !== undefined)
  ) as Partial<T>;
}

function clampTimeout(timeout: number | undefined): number {
  if (typeof timeout !== "number" || !Number.isFinite(timeout)) {
    return MAX_CEREMONY_MS;
  }
  return Math.min(MAX_CEREMONY_MS, Math.max(MIN_CEREMONY_MS, timeout));
}

function toDomException(code: ExtensionErrorCode, message: string): DOMException {
  const names: Partial<Record<ExtensionErrorCode, string>> = {
    ABORTED: "AbortError",
    INVALID_STATE: "InvalidStateError",
    INTERNAL_ERROR: "NotAllowedError",
    NOT_ALLOWED: "NotAllowedError",
    NOT_SUPPORTED: "NotSupportedError",
    SECURITY_ERROR: "SecurityError"
  };
  return new DOMException(message, names[code] ?? "UnknownError");
}

function cloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function isExtensionResponse(value: unknown): value is ExtensionBridgeResponse {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const message = value as Partial<ExtensionBridgeResponse>;
  return (
    message.channel === BRIDGE_CHANNEL &&
    message.source === "extension" &&
    message.kind === "response" &&
    typeof message.requestId === "string" &&
    typeof message.ok === "boolean"
  );
}

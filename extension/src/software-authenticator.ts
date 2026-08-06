import type {
  ExtensionErrorCode,
  SerializedAssertionCredential,
  SerializedCreatedCredential,
  SerializedCreationOptions,
  SerializedCredentialDescriptor,
  SerializedRequestOptions
} from "./types";
import { parse as parseDomain } from "tldts";

import {
  PureExtensionError,
  type PureVault,
  type StoredSoftwareCredential
} from "./pure-vault";
import {
  arrayBuffer,
  concatenateBytes,
  decodeBase64Url,
  encodeBase64Url,
  randomBytes,
  sha256
} from "./binary";
import { encodeCbor, type CborValue } from "./cbor";

const ES256_ALGORITHM = -7;
const CREATE_FLAGS = 0x01 | 0x04 | 0x40;
const ASSERTION_FLAGS = 0x01 | 0x04;
const AAGUID = new Uint8Array(16);

export interface CreationConfirmationDetails {
  operation: "create";
  origin: string;
  rpId: string;
  rpName: string;
  userName: string;
  displayName: string;
}

export interface AssertionCandidate {
  credentialId: string;
  rpId: string;
  userName: string;
  displayName: string;
  lastUsedAt: number | null;
}

export interface AssertionConfirmationDetails {
  operation: "get";
  origin: string;
  rpId: string;
  credentials: AssertionCandidate[];
}

export class SoftwareAuthenticator {
  constructor(
    private readonly vault: PureVault,
    private readonly now: () => number = Date.now
  ) {}

  async creationDetails(
    origin: string,
    options: SerializedCreationOptions
  ): Promise<CreationConfirmationDetails> {
    const validated = validateCreation(origin, options);
    const excluded = descriptorIds(options.excludeCredentials);
    if (excluded.size > 0) {
      const matches = await this.vault.findCredentials(
        validated.rpId,
        excluded
      );
      if (matches.length > 0) {
        throw extensionError(
          "INVALID_STATE",
          "该账户已经注册过本地通行密钥"
        );
      }
    }
    return {
      operation: "create",
      origin: validated.origin,
      rpId: validated.rpId,
      rpName: options.rp.name,
      userName: options.user.name,
      displayName: options.user.displayName
    };
  }

  async assertionDetails(
    origin: string,
    options: SerializedRequestOptions
  ): Promise<AssertionConfirmationDetails> {
    const validated = validateRequest(origin, options);
    const allowedIds =
      options.allowCredentials && options.allowCredentials.length > 0
        ? descriptorIds(options.allowCredentials)
        : undefined;
    const credentials = await this.vault.findCredentials(
      validated.rpId,
      allowedIds
    );
    if (credentials.length === 0) {
      throw extensionError(
        "CREDENTIAL_NOT_FOUND",
        "没有找到与网站匹配的本地通行密钥"
      );
    }
    credentials.sort(
      (left, right) =>
        (right.lastUsedAt ?? right.createdAt) -
        (left.lastUsedAt ?? left.createdAt)
    );
    return {
      operation: "get",
      origin: validated.origin,
      rpId: validated.rpId,
      credentials: credentials.map((credential) => ({
        credentialId: credential.credentialId,
        rpId: credential.rpId,
        userName: credential.userName,
        displayName: credential.displayName,
        lastUsedAt: credential.lastUsedAt
      }))
    };
  }

  async makeCredential(
    origin: string,
    options: SerializedCreationOptions
  ): Promise<SerializedCreatedCredential> {
    const validated = validateCreation(origin, options);
    await this.creationDetails(origin, options);

    const generated = (await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-256"
      },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;
    const [privateKeyPkcs8, publicKeySpki, rawPublicKey] = await Promise.all([
      crypto.subtle.exportKey("pkcs8", generated.privateKey),
      crypto.subtle.exportKey("spki", generated.publicKey),
      crypto.subtle.exportKey("raw", generated.publicKey)
    ]);
    const publicKeyBytes = new Uint8Array(rawPublicKey);
    if (publicKeyBytes.length !== 65 || publicKeyBytes[0] !== 0x04) {
      throw extensionError(
        "INTERNAL_ERROR",
        "浏览器返回了不受支持的 P-256 公钥"
      );
    }
    const publicKeyCose = createCosePublicKey(publicKeyBytes);
    const credentialIdBytes = randomBytes(32);
    const credentialId = encodeBase64Url(credentialIdBytes);
    const createdAt = this.now();
    const stored: StoredSoftwareCredential = {
      schemaVersion: 1,
      kind: "passkey",
      credentialId,
      rpId: validated.rpId,
      userHandle: options.user.id,
      userName: options.user.name,
      displayName: options.user.displayName,
      privateKeyPkcs8: encodeBase64Url(privateKeyPkcs8),
      publicKeySpki: encodeBase64Url(publicKeySpki),
      publicKeyCose: encodeBase64Url(publicKeyCose),
      signCount: 0,
      alias: "",
      favorite: false,
      tags: [],
      createdAt,
      lastUsedAt: null,
      deletedAt: null
    };
    await this.vault.saveCredential(stored);

    const clientDataJSON = createClientData(
      "webauthn.create",
      options.challenge,
      validated.origin
    );
    const authenticatorData = await createRegistrationAuthenticatorData(
      validated.rpId,
      credentialIdBytes,
      publicKeyCose
    );
    const attestationObject = encodeCbor(
      new Map<CborValue, CborValue>([
        ["fmt", "none"],
        ["attStmt", new Map<CborValue, CborValue>()],
        ["authData", authenticatorData]
      ])
    );
    const credPropsRequested = options.extensions?.credProps === true;

    return {
      id: credentialId,
      rawId: credentialId,
      type: "public-key",
      authenticatorAttachment: "platform",
      response: {
        clientDataJSON: encodeBase64Url(clientDataJSON),
        attestationObject: encodeBase64Url(attestationObject),
        authenticatorData: encodeBase64Url(authenticatorData),
        publicKey: encodeBase64Url(publicKeySpki),
        publicKeyAlgorithm: ES256_ALGORITHM,
        transports: ["internal"]
      },
      clientExtensionResults: credPropsRequested
        ? { credProps: { rk: true } }
        : {}
    };
  }

  async getAssertion(
    origin: string,
    options: SerializedRequestOptions,
    selectedCredentialId?: string
  ): Promise<SerializedAssertionCredential> {
    const validated = validateRequest(origin, options);
    const details = await this.assertionDetails(origin, options);
    const selected = selectedCredentialId
      ? details.credentials.find(
          (credential) => credential.credentialId === selectedCredentialId
        )
      : details.credentials[0];
    if (!selected) {
      throw extensionError(
        "CREDENTIAL_NOT_FOUND",
        "所选通行密钥与当前网站请求不匹配"
      );
    }

    const credential = await this.vault.readCredential(
      selected.credentialId
    );
    if (!credential || credential.rpId !== validated.rpId) {
      throw extensionError(
        "CREDENTIAL_NOT_FOUND",
        "找不到所选的本地通行密钥"
      );
    }
    const clientDataJSON = createClientData(
      "webauthn.get",
      options.challenge,
      validated.origin
    );
    const nextSignCount =
      credential.signCount >= 0xffffffff
        ? 0xffffffff
        : credential.signCount + 1;
    const authenticatorData = await createAssertionAuthenticatorData(
      validated.rpId,
      nextSignCount
    );
    const clientDataHash = await sha256(clientDataJSON);
    const signedData = concatenateBytes(authenticatorData, clientDataHash);
    const privateKey = await crypto.subtle.importKey(
      "pkcs8",
      decodeBase64Url(credential.privateKeyPkcs8, 64, 512),
      {
        name: "ECDSA",
        namedCurve: "P-256"
      },
      false,
      ["sign"]
    );
    const rawSignature = await crypto.subtle.sign(
      {
        name: "ECDSA",
        hash: "SHA-256"
      },
      privateKey,
      signedData
    );
    const signature = ecdsaSignatureToDer(rawSignature);

    credential.signCount = nextSignCount;
    credential.lastUsedAt = this.now();
    await this.vault.updateCredential(credential);

    return {
      id: credential.credentialId,
      rawId: credential.credentialId,
      type: "public-key",
      authenticatorAttachment: "platform",
      response: {
        clientDataJSON: encodeBase64Url(clientDataJSON),
        authenticatorData: encodeBase64Url(authenticatorData),
        signature: encodeBase64Url(signature),
        userHandle: credential.userHandle
      },
      clientExtensionResults: {}
    };
  }
}

function validateCreation(
  origin: string,
  options: SerializedCreationOptions
): { origin: string; rpId: string } {
  const result = validateOriginAndRpId(origin, options.rp.id);
  validateChallenge(options.challenge);
  decodeBase64Url(options.user.id, 1, 64);
  if (
    typeof options.rp.name !== "string" ||
    options.rp.name.length < 1 ||
    options.rp.name.length > 256 ||
    typeof options.user.name !== "string" ||
    options.user.name.length < 1 ||
    options.user.name.length > 256 ||
    typeof options.user.displayName !== "string" ||
    options.user.displayName.length < 1 ||
    options.user.displayName.length > 256 ||
    !Array.isArray(options.pubKeyCredParams) ||
    options.pubKeyCredParams.length < 1 ||
    options.pubKeyCredParams.length > 32
  ) {
    throw extensionError("INVALID_MESSAGE", "WebAuthn 注册参数无效");
  }
  if (
    !options.pubKeyCredParams.some(
      (parameter) =>
        parameter.type === "public-key" &&
        parameter.alg === ES256_ALGORITHM
    )
  ) {
    throw extensionError(
      "NOT_SUPPORTED",
      "网站没有提供本插件支持的 ES256 算法"
    );
  }
  if (
    options.authenticatorSelection?.authenticatorAttachment ===
    "cross-platform"
  ) {
    throw extensionError(
      "NOT_SUPPORTED",
      "网站要求外接安全密钥，无法使用本地纯插件"
    );
  }
  validateExtensions(options.extensions, new Set(["credProps"]));
  validateDescriptors(options.excludeCredentials);
  return result;
}

function validateRequest(
  origin: string,
  options: SerializedRequestOptions
): { origin: string; rpId: string } {
  const result = validateOriginAndRpId(origin, options.rpId);
  validateChallenge(options.challenge);
  validateExtensions(options.extensions, new Set());
  validateDescriptors(options.allowCredentials);
  return result;
}

function validateOriginAndRpId(
  originValue: string,
  requestedRpId: string | undefined
): { origin: string; rpId: string } {
  let origin: URL;
  try {
    origin = new URL(originValue);
  } catch (error) {
    throw extensionError("SECURITY_ERROR", "WebAuthn 来源无效", error);
  }
  if (
    origin.protocol !== "https:" ||
    origin.origin !== originValue ||
    origin.username !== "" ||
    origin.password !== ""
  ) {
    throw extensionError("SECURITY_ERROR", "WebAuthn 来源不受信任");
  }
  const hostname = origin.hostname.toLowerCase();
  const rpId = normalizeRpId(requestedRpId ?? hostname);
  const exactHost = hostname === rpId;
  const parentDomain = hostname.endsWith(`.${rpId}`);
  const parsedRpId = parseDomain(rpId, { allowPrivateDomains: true });
  const registrableRpId =
    rpId === "localhost" ||
    (
      parsedRpId.isIp === false &&
      parsedRpId.domain !== null
    );
  if (
    (!exactHost && !parentDomain) ||
    !registrableRpId
  ) {
    throw extensionError(
      "SECURITY_ERROR",
      "RP ID 不是当前 HTTPS 域名的有效可注册域"
    );
  }
  return { origin: origin.origin, rpId };
}

function normalizeRpId(value: string): string {
  const normalized = value.toLowerCase();
  const labels = normalized.split(".");
  if (
    normalized.length < 1 ||
    normalized.length > 253 ||
    normalized.startsWith(".") ||
    normalized.endsWith(".") ||
    labels.some(
      (label) =>
        label.length < 1 ||
        label.length > 63 ||
        label.startsWith("-") ||
        label.endsWith("-") ||
        !/^[a-z0-9-]+$/u.test(label)
    )
  ) {
    throw extensionError("SECURITY_ERROR", "WebAuthn RP ID 无效");
  }
  return normalized;
}

function validateExtensions(
  extensions: Record<string, unknown> | undefined,
  supported: ReadonlySet<string>
): void {
  const unsupported = Object.keys(extensions ?? {}).filter(
    (name) => !supported.has(name)
  );
  if (unsupported.length > 0) {
    throw extensionError(
      "NOT_SUPPORTED",
      `网站请求了本地验证器尚不支持的 WebAuthn 扩展：${unsupported.join(", ")}`
    );
  }
}

function validateChallenge(challenge: string): void {
  try {
    decodeBase64Url(challenge, 16, 1024);
  } catch (error) {
    throw extensionError(
      "INVALID_MESSAGE",
      "WebAuthn challenge 无效",
      error
    );
  }
}

function validateDescriptors(
  descriptors: SerializedCredentialDescriptor[] | undefined
): void {
  if (!descriptors) {
    return;
  }
  if (descriptors.length > 64) {
    throw extensionError("INVALID_MESSAGE", "凭据列表过长");
  }
  try {
    for (const descriptor of descriptors) {
      if (descriptor.type !== "public-key") {
        throw new TypeError("Invalid credential type");
      }
      decodeBase64Url(descriptor.id, 16, 1023);
    }
  } catch (error) {
    throw extensionError("INVALID_MESSAGE", "凭据列表无效", error);
  }
}

function descriptorIds(
  descriptors: SerializedCredentialDescriptor[] | undefined
): Set<string> {
  return new Set(descriptors?.map((descriptor) => descriptor.id) ?? []);
}

function createClientData(
  type: "webauthn.create" | "webauthn.get",
  challenge: string,
  origin: string
): ArrayBuffer {
  return new TextEncoder().encode(
    JSON.stringify({
      type,
      challenge,
      origin,
      crossOrigin: false
    })
  ).buffer;
}

function createCosePublicKey(
  uncompressedPublicKey: Uint8Array<ArrayBufferLike>
): ArrayBuffer {
  const x = uncompressedPublicKey.slice(1, 33);
  const y = uncompressedPublicKey.slice(33, 65);
  return encodeCbor(
    new Map<CborValue, CborValue>([
      [1, 2],
      [3, ES256_ALGORITHM],
      [-1, 1],
      [-2, x],
      [-3, y]
    ])
  );
}

async function createRegistrationAuthenticatorData(
  rpId: string,
  credentialId: Uint8Array<ArrayBufferLike>,
  publicKeyCose: ArrayBuffer
): Promise<ArrayBuffer> {
  const credentialLength = new Uint8Array(2);
  new DataView(credentialLength.buffer).setUint16(
    0,
    credentialId.byteLength,
    false
  );
  return arrayBuffer(
    concatenateBytes(
      await sha256(new TextEncoder().encode(rpId)),
      Uint8Array.of(CREATE_FLAGS),
      uint32Bytes(0),
      AAGUID,
      credentialLength,
      credentialId,
      publicKeyCose
    )
  );
}

async function createAssertionAuthenticatorData(
  rpId: string,
  signCount: number
): Promise<ArrayBuffer> {
  return arrayBuffer(
    concatenateBytes(
      await sha256(new TextEncoder().encode(rpId)),
      Uint8Array.of(ASSERTION_FLAGS),
      uint32Bytes(signCount)
    )
  );
}

function uint32Bytes(value: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}

function ecdsaSignatureToDer(signature: ArrayBuffer): ArrayBuffer {
  const bytes = new Uint8Array(signature);
  if (bytes.length !== 64) {
    if (bytes.length >= 8 && bytes[0] === 0x30) {
      return signature.slice(0);
    }
    throw extensionError(
      "INTERNAL_ERROR",
      "浏览器返回了无效的 ES256 签名"
    );
  }
  const r = derInteger(bytes.subarray(0, 32));
  const s = derInteger(bytes.subarray(32, 64));
  const bodyLength = r.byteLength + s.byteLength;
  return concatenateBytes(Uint8Array.of(0x30, bodyLength), r, s).buffer;
}

function derInteger(value: Uint8Array<ArrayBufferLike>): Uint8Array<ArrayBuffer> {
  let offset = 0;
  while (offset < value.length - 1 && value[offset] === 0) {
    offset += 1;
  }
  const integer = value.slice(offset);
  const needsPadding = (integer[0] ?? 0) >= 0x80;
  return concatenateBytes(
    Uint8Array.of(0x02, integer.byteLength + (needsPadding ? 1 : 0)),
    ...(needsPadding ? [Uint8Array.of(0)] : []),
    integer
  );
}

function extensionError(
  code: ExtensionErrorCode,
  message: string,
  cause?: unknown
): PureExtensionError {
  return new PureExtensionError(
    code,
    message,
    cause === undefined ? undefined : { cause }
  );
}

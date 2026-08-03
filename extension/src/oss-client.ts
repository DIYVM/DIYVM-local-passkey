import { arrayBuffer } from "./binary";

const OSS_SIGNATURE_ALGORITHM = "OSS4-HMAC-SHA256";
const OSS_SIGNATURE_TERMINATOR = "aliyun_v4_request";
const OSS_SERVICE = "oss";
const UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
const MAX_ENDPOINT_LENGTH = 2048;
const MAX_OBJECT_KEY_BYTES = 1024;
const MAX_ACCESS_KEY_BYTES = 512;

export interface OssConfigurationInput {
  endpoint: string;
  region: string;
  bucket: string;
  objectKey: string;
  accessKeyId: string;
  accessKeySecret: string;
}

export interface OssConfiguration extends OssConfigurationInput {}

export interface OssObjectInfo {
  exists: boolean;
  size: number | null;
  etag: string | null;
  lastModifiedAt: number | null;
  versionId: string | null;
}

export interface OssSignedRequest {
  authorization: string;
  canonicalRequest: string;
  stringToSign: string;
  headers: Record<string, string>;
}

export class OssClientError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly ossCode?: string,
    options?: ErrorOptions
  ) {
    super(message, options);
    this.name = "OssClientError";
  }
}

export class AliyunOssClient {
  readonly configuration: OssConfiguration;

  constructor(
    configuration: OssConfigurationInput,
    private readonly fetcher: typeof fetch = fetch,
    private readonly now: () => Date = () => new Date()
  ) {
    this.configuration = normalizeOssConfiguration(configuration);
  }

  async inspectObject(): Promise<OssObjectInfo> {
    const response = await this.request("HEAD");
    if (response.status === 404) {
      return {
        exists: false,
        size: null,
        etag: null,
        lastModifiedAt: null,
        versionId: null
      };
    }
    if (!response.ok) {
      throw await responseError(response);
    }
    return objectInfo(response, true);
  }

  async putObject(contents: string): Promise<OssObjectInfo> {
    const response = await this.request("PUT", contents);
    if (!response.ok) {
      throw await responseError(response);
    }
    return objectInfo(response, true);
  }

  async getObject(maximumBytes: number): Promise<{
    contents: string;
    info: OssObjectInfo;
  }> {
    if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1) {
      throw new RangeError("无效的 OSS 下载大小限制");
    }
    const response = await this.request("GET");
    if (response.status === 404) {
      throw new OssClientError("OSS 中尚无远程备份", 404, "NoSuchKey");
    }
    if (!response.ok) {
      throw await responseError(response);
    }
    const declaredLength = contentLength(response.headers);
    if (declaredLength !== null && declaredLength > maximumBytes) {
      throw new OssClientError("远程备份超过 20 MB 限制");
    }
    const payload = await response.arrayBuffer();
    if (payload.byteLength === 0 || payload.byteLength > maximumBytes) {
      new Uint8Array(payload).fill(0);
      throw new OssClientError("远程备份为空或超过 20 MB 限制");
    }
    let contents: string;
    try {
      contents = new TextDecoder("utf-8", { fatal: true }).decode(payload);
    } catch (error) {
      throw new OssClientError("远程备份不是有效的 UTF-8 文件", undefined, undefined, {
        cause: error
      });
    } finally {
      new Uint8Array(payload).fill(0);
    }
    return {
      contents,
      info: objectInfo(response, true)
    };
  }

  private async request(
    method: "GET" | "HEAD" | "PUT",
    body?: string
  ): Promise<Response> {
    const headers: Record<string, string> = {
      ...(method === "PUT" ? { "content-type": "application/json" } : {})
    };
    const signed = await signOssRequest({
      configuration: this.configuration,
      method,
      headers,
      now: this.now()
    });
    try {
      return await this.fetcher(ossObjectUrl(this.configuration), {
        method,
        headers: signed.headers,
        ...(body === undefined ? {} : { body }),
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
        referrerPolicy: "no-referrer"
      });
    } catch (error) {
      throw new OssClientError(
        "无法连接阿里云 OSS，请检查网络、Endpoint 和扩展权限",
        undefined,
        undefined,
        { cause: error }
      );
    }
  }
}

export function normalizeOssConfiguration(
  value: OssConfigurationInput
): OssConfiguration {
  if (typeof value !== "object" || value === null) {
    throw new TypeError("OSS 配置无效");
  }
  const endpoint = normalizeEndpoint(value.endpoint);
  const region = normalizeRegion(value.region);
  const bucket = normalizeBucket(value.bucket);
  const objectKey = normalizeObjectKey(value.objectKey);
  const accessKeyId = normalizeAccessKey(
    value.accessKeyId,
    "AccessKey ID"
  );
  const accessKeySecret = normalizeAccessKey(
    value.accessKeySecret,
    "AccessKey Secret"
  );
  return {
    endpoint,
    region,
    bucket,
    objectKey,
    accessKeyId,
    accessKeySecret
  };
}

export function isOssConfigurationInput(
  value: unknown
): value is OssConfigurationInput {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  if (
    typeof candidate.endpoint !== "string" ||
    typeof candidate.region !== "string" ||
    typeof candidate.bucket !== "string" ||
    typeof candidate.objectKey !== "string" ||
    typeof candidate.accessKeyId !== "string" ||
    typeof candidate.accessKeySecret !== "string"
  ) {
    return false;
  }
  try {
    normalizeOssConfiguration(candidate as unknown as OssConfigurationInput);
    return true;
  } catch {
    return false;
  }
}

export function ossObjectOrigin(
  configuration: Pick<OssConfiguration, "endpoint" | "bucket">
): string {
  const endpoint = new URL(configuration.endpoint);
  endpoint.hostname = `${configuration.bucket}.${endpoint.hostname}`;
  return endpoint.origin;
}

export function ossPermissionPattern(
  configuration: Pick<OssConfiguration, "endpoint" | "bucket">
): string {
  return `${ossObjectOrigin(configuration)}/*`;
}

export function ossObjectUrl(
  configuration: Pick<
    OssConfiguration,
    "endpoint" | "bucket" | "objectKey"
  >
): string {
  return `${ossObjectOrigin(configuration)}/${encodeOssPath(
    configuration.objectKey
  )}`;
}

export async function signOssRequest(input: {
  configuration: OssConfigurationInput;
  method: string;
  headers?: Record<string, string>;
  additionalHeaders?: string[];
  now?: Date;
}): Promise<OssSignedRequest> {
  const configuration = normalizeOssConfiguration(input.configuration);
  const method = input.method.trim().toUpperCase();
  if (!/^(?:DELETE|GET|HEAD|OPTIONS|POST|PUT)$/u.test(method)) {
    throw new TypeError("OSS 请求方法无效");
  }
  const timestamp = ossTimestamp(input.now ?? new Date());
  const date = timestamp.slice(0, 8);
  const scope =
    `${date}/${configuration.region}/${OSS_SERVICE}/` +
    OSS_SIGNATURE_TERMINATOR;
  const headers = normalizeSigningHeaders(input.headers ?? {});
  headers["x-oss-content-sha256"] = UNSIGNED_PAYLOAD;
  headers["x-oss-date"] = timestamp;
  const additionalHeaders = normalizeAdditionalHeaders(
    input.additionalHeaders ?? [],
    headers
  );
  const canonicalHeaders = canonicalSigningHeaders(
    headers,
    additionalHeaders
  );
  const canonicalRequest = [
    method,
    `/${configuration.bucket}/${encodeOssPath(configuration.objectKey)}`,
    "",
    canonicalHeaders,
    additionalHeaders.join(";"),
    UNSIGNED_PAYLOAD
  ].join("\n");
  const stringToSign = [
    OSS_SIGNATURE_ALGORITHM,
    timestamp,
    scope,
    await sha256Hex(canonicalRequest)
  ].join("\n");
  const signature = await ossSignature(
    configuration.accessKeySecret,
    date,
    configuration.region,
    stringToSign
  );
  const additional =
    additionalHeaders.length === 0
      ? ""
      : `AdditionalHeaders=${additionalHeaders.join(";")},`;
  const authorization =
    `${OSS_SIGNATURE_ALGORITHM} Credential=` +
    `${configuration.accessKeyId}/${scope},${additional}Signature=${signature}`;
  return {
    authorization,
    canonicalRequest,
    stringToSign,
    headers: {
      ...headers,
      authorization
    }
  };
}

function normalizeEndpoint(value: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_ENDPOINT_LENGTH
  ) {
    throw new TypeError("OSS Endpoint 无效");
  }
  let url: URL;
  try {
    url = new URL(value.trim());
  } catch (error) {
    throw new TypeError("OSS Endpoint 无效", { cause: error });
  }
  const hostname = url.hostname.toLocaleLowerCase();
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.port !== "" ||
    (url.pathname !== "" && url.pathname !== "/") ||
    url.search !== "" ||
    url.hash !== "" ||
    !/^oss-[a-z0-9-]+\.aliyuncs\.com(?:\.cn)?$/u.test(hostname) ||
    hostname.includes("-internal.")
  ) {
    throw new TypeError("第一版仅支持阿里云 OSS 的 HTTPS 公网 Endpoint");
  }
  return `https://${hostname}`;
}

function normalizeRegion(value: string): string {
  const normalized = typeof value === "string"
    ? value.trim().toLocaleLowerCase()
    : "";
  if (!/^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/u.test(normalized)) {
    throw new TypeError("OSS Region ID 无效");
  }
  return normalized;
}

function normalizeBucket(value: string): string {
  const normalized = typeof value === "string"
    ? value.trim().toLocaleLowerCase()
    : "";
  if (!/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/u.test(normalized)) {
    throw new TypeError("OSS Bucket 名称无效");
  }
  return normalized;
}

function normalizeObjectKey(value: string): string {
  const normalized = typeof value === "string" ? value.trim() : "";
  const bytes = new TextEncoder().encode(normalized);
  try {
    if (
      normalized.length === 0 ||
      normalized.startsWith("/") ||
      normalized.endsWith("/") ||
      normalized.includes("\\") ||
      /[\u0000-\u001f\u007f]/u.test(normalized) ||
      normalized.split("/").some((part) => part === "." || part === "..") ||
      bytes.byteLength > MAX_OBJECT_KEY_BYTES
    ) {
      throw new TypeError("OSS 对象路径无效");
    }
    return normalized;
  } finally {
    bytes.fill(0);
  }
}

function normalizeAccessKey(value: string, label: string): string {
  if (typeof value !== "string") {
    throw new TypeError(`${label} 无效`);
  }
  const normalized = value.trim();
  const bytes = new TextEncoder().encode(normalized);
  try {
    if (
      bytes.byteLength < 8 ||
      bytes.byteLength > MAX_ACCESS_KEY_BYTES ||
      /[\u0000-\u0020\u007f]/u.test(normalized)
    ) {
      throw new TypeError(`${label} 无效`);
    }
    return normalized;
  } finally {
    bytes.fill(0);
  }
}

function normalizeSigningHeaders(
  input: Record<string, string>
): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(input)) {
    const normalizedName = name.trim().toLocaleLowerCase();
    if (
      !/^[a-z0-9!#$%&'*+.^_`|~-]+$/u.test(normalizedName) ||
      /[\r\n]/u.test(value)
    ) {
      throw new TypeError("OSS 请求头无效");
    }
    headers[normalizedName] = value.trim();
  }
  return headers;
}

function normalizeAdditionalHeaders(
  input: string[],
  headers: Record<string, string>
): string[] {
  const names = [...new Set(input.map((name) => name.toLocaleLowerCase()))]
    .filter(
      (name) =>
        name !== "content-type" &&
        name !== "content-md5" &&
        !name.startsWith("x-oss-")
    )
    .sort();
  if (names.some((name) => headers[name] === undefined)) {
    throw new TypeError("OSS 附加签名请求头不存在");
  }
  return names;
}

function canonicalSigningHeaders(
  headers: Record<string, string>,
  additionalHeaders: string[]
): string {
  const names = new Set(additionalHeaders);
  for (const name of Object.keys(headers)) {
    if (
      name === "content-type" ||
      name === "content-md5" ||
      name.startsWith("x-oss-")
    ) {
      names.add(name);
    }
  }
  return [...names]
    .sort()
    .map((name) => `${name}:${headers[name]?.trim() ?? ""}\n`)
    .join("");
}

function encodeOssPath(value: string): string {
  const bytes = new TextEncoder().encode(value);
  try {
    let encoded = "";
    for (const byte of bytes) {
      if (
        (byte >= 0x41 && byte <= 0x5a) ||
        (byte >= 0x61 && byte <= 0x7a) ||
        (byte >= 0x30 && byte <= 0x39) ||
        byte === 0x2d ||
        byte === 0x2e ||
        byte === 0x5f ||
        byte === 0x7e
      ) {
        encoded += String.fromCharCode(byte);
      } else if (byte === 0x2f) {
        encoded += "/";
      } else {
        encoded += `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
      }
    }
    return encoded;
  } finally {
    bytes.fill(0);
  }
}

function ossTimestamp(date: Date): string {
  if (Number.isNaN(date.getTime())) {
    throw new TypeError("OSS 签名时间无效");
  }
  return date.toISOString().replace(/[:-]|\.\d{3}/gu, "");
}

async function ossSignature(
  accessKeySecret: string,
  date: string,
  region: string,
  stringToSign: string
): Promise<string> {
  const secret = new TextEncoder().encode(`aliyun_v4${accessKeySecret}`);
  let dateKey: Uint8Array<ArrayBuffer> | undefined;
  let regionKey: Uint8Array<ArrayBuffer> | undefined;
  let serviceKey: Uint8Array<ArrayBuffer> | undefined;
  let signingKey: Uint8Array<ArrayBuffer> | undefined;
  try {
    dateKey = await hmacSha256(secret, date);
    regionKey = await hmacSha256(dateKey, region);
    serviceKey = await hmacSha256(regionKey, OSS_SERVICE);
    signingKey = await hmacSha256(serviceKey, OSS_SIGNATURE_TERMINATOR);
    return hex(await hmacSha256(signingKey, stringToSign));
  } finally {
    secret.fill(0);
    dateKey?.fill(0);
    regionKey?.fill(0);
    serviceKey?.fill(0);
    signingKey?.fill(0);
  }
}

async function hmacSha256(
  keyBytes: Uint8Array<ArrayBufferLike>,
  value: string
): Promise<Uint8Array<ArrayBuffer>> {
  const key = await crypto.subtle.importKey(
    "raw",
    arrayBuffer(keyBytes),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const message = new TextEncoder().encode(value);
  try {
    return new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  } finally {
    message.fill(0);
  }
}

async function sha256Hex(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  try {
    return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
  } finally {
    bytes.fill(0);
  }
}

function hex(value: Uint8Array<ArrayBufferLike>): string {
  return [...value]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function objectInfo(response: Response, exists: boolean): OssObjectInfo {
  return {
    exists,
    size: contentLength(response.headers),
    etag: cleanHeader(response.headers.get("etag"), 256),
    lastModifiedAt: headerTimestamp(response.headers.get("last-modified")),
    versionId: cleanHeader(response.headers.get("x-oss-version-id"), 1024)
  };
}

function contentLength(headers: Headers): number | null {
  const value = headers.get("content-length");
  if (value === null || !/^\d+$/u.test(value)) {
    return null;
  }
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

function cleanHeader(value: string | null, maximumLength: number): string | null {
  if (
    value === null ||
    value.length === 0 ||
    value.length > maximumLength ||
    /[\r\n]/u.test(value)
  ) {
    return null;
  }
  return value;
}

function headerTimestamp(value: string | null): number | null {
  if (value === null) {
    return null;
  }
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && timestamp >= 0 ? timestamp : null;
}

async function responseError(response: Response): Promise<OssClientError> {
  let details = "";
  try {
    details = (await response.text()).slice(0, 4096);
  } catch {
    // The HTTP status remains sufficient when OSS does not return a body.
  }
  const code = xmlValue(details, "Code");
  const message = xmlValue(details, "Message");
  const explanation =
    response.status === 403
      ? "OSS 拒绝访问，请检查 AccessKey、Region 和 RAM 权限"
      : response.status === 404
        ? "OSS 中尚无远程备份"
        : `OSS 请求失败（HTTP ${response.status}）`;
  return new OssClientError(
    message ? `${explanation}：${message}` : explanation,
    response.status,
    code ?? undefined
  );
}

function xmlValue(value: string, name: string): string | null {
  const match = value.match(new RegExp(`<${name}>([^<]{1,512})</${name}>`, "u"));
  return match?.[1]?.trim() ?? null;
}

export function encodeBase64Url(
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

export function decodeBase64Url(
  value: string,
  minimumBytes = 0,
  maximumBytes = Number.MAX_SAFE_INTEGER
): ArrayBuffer {
  if (
    typeof value !== "string" ||
    value.length > Math.ceil(maximumBytes * 4 / 3) + 4 ||
    !/^[A-Za-z0-9_-]*$/u.test(value)
  ) {
    throw new TypeError("Invalid Base64URL value");
  }

  const normalized = value
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  let binary: string;
  try {
    binary = atob(normalized);
  } catch (error) {
    throw new TypeError("Invalid Base64URL value", { cause: error });
  }
  if (binary.length < minimumBytes || binary.length > maximumBytes) {
    throw new TypeError("Base64URL value has an invalid length");
  }

  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes.buffer;
}

export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  if (!Number.isSafeInteger(length) || length < 1 || length > 65_536) {
    throw new RangeError("Invalid random byte length");
  }
  const result = new Uint8Array(length);
  crypto.getRandomValues(result);
  return result;
}

export function concatenateBytes(
  ...values: Array<ArrayBuffer | Uint8Array<ArrayBufferLike>>
): Uint8Array<ArrayBuffer> {
  const total = values.reduce(
    (length, value) => length + byteView(value).byteLength,
    0
  );
  const result = new Uint8Array(total);
  let offset = 0;
  for (const value of values) {
    const bytes = byteView(value);
    result.set(bytes, offset);
    offset += bytes.byteLength;
  }
  return result;
}

export function arrayBuffer(
  value: ArrayBuffer | Uint8Array<ArrayBufferLike>
): ArrayBuffer {
  const bytes = byteView(value);
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

export async function sha256(
  value: ArrayBuffer | Uint8Array<ArrayBufferLike>
): Promise<ArrayBuffer> {
  return crypto.subtle.digest("SHA-256", arrayBuffer(value));
}

function byteView(
  value: ArrayBuffer | Uint8Array<ArrayBufferLike>
): Uint8Array<ArrayBufferLike> {
  return value instanceof ArrayBuffer ? new Uint8Array(value) : value;
}

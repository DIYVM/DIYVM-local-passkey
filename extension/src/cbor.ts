import { arrayBuffer, concatenateBytes } from "./binary";

export type CborValue =
  | number
  | string
  | boolean
  | null
  | ArrayBuffer
  | Uint8Array<ArrayBufferLike>
  | CborValue[]
  | Map<CborValue, CborValue>;

export function encodeCbor(value: CborValue): ArrayBuffer {
  return arrayBuffer(encodeValue(value));
}

function encodeValue(value: CborValue): Uint8Array<ArrayBuffer> {
  if (value === null) {
    return Uint8Array.of(0xf6);
  }
  if (typeof value === "boolean") {
    return Uint8Array.of(value ? 0xf5 : 0xf4);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new TypeError("CBOR only supports safe integers");
    }
    return value >= 0
      ? encodeHead(0, value)
      : encodeHead(1, -1 - value);
  }
  if (typeof value === "string") {
    const encoded = new TextEncoder().encode(value);
    return concatenateBytes(encodeHead(3, encoded.byteLength), encoded);
  }
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
    const bytes =
      value instanceof ArrayBuffer
        ? new Uint8Array(value)
        : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    return concatenateBytes(encodeHead(2, bytes.byteLength), bytes);
  }
  if (Array.isArray(value)) {
    return concatenateBytes(
      encodeHead(4, value.length),
      ...value.map(encodeValue)
    );
  }
  if (value instanceof Map) {
    const entries: Uint8Array<ArrayBuffer>[] = [];
    for (const [key, entryValue] of value) {
      entries.push(encodeValue(key), encodeValue(entryValue));
    }
    return concatenateBytes(encodeHead(5, value.size), ...entries);
  }
  throw new TypeError("Unsupported CBOR value");
}

function encodeHead(
  majorType: number,
  value: number
): Uint8Array<ArrayBuffer> {
  const prefix = majorType << 5;
  if (value < 24) {
    return Uint8Array.of(prefix | value);
  }
  if (value <= 0xff) {
    return Uint8Array.of(prefix | 24, value);
  }
  if (value <= 0xffff) {
    return Uint8Array.of(prefix | 25, value >>> 8, value & 0xff);
  }
  if (value <= 0xffffffff) {
    return Uint8Array.of(
      prefix | 26,
      value >>> 24,
      value >>> 16,
      value >>> 8,
      value
    );
  }
  throw new RangeError("CBOR integer is too large");
}

import type {
  ExtensionErrorCode,
  SerializedAssertionCredential,
  SerializedCreatedCredential,
  SerializedCreationOptions,
  SerializedRequestOptions
} from "./types";

export const BRIDGE_CHANNEL = "local-passkey:webauthn:v1";

export type BridgeOperation = "create" | "get";

export type PageBridgeRequest =
  | {
      channel: typeof BRIDGE_CHANNEL;
      source: "page";
      kind: "request";
      requestId: string;
      operation: "create";
      publicKey: SerializedCreationOptions;
    }
  | {
      channel: typeof BRIDGE_CHANNEL;
      source: "page";
      kind: "request";
      requestId: string;
      operation: "get";
      publicKey: SerializedRequestOptions;
      mediation?: "conditional";
    };

export interface PageBridgeCancel {
  channel: typeof BRIDGE_CHANNEL;
  source: "page";
  kind: "cancel";
  requestId: string;
}

export type ExtensionBridgeResponse =
  | {
      channel: typeof BRIDGE_CHANNEL;
      source: "extension";
      kind: "response";
      requestId: string;
      ok: true;
      operation: "create";
      credential: SerializedCreatedCredential;
    }
  | {
      channel: typeof BRIDGE_CHANNEL;
      source: "extension";
      kind: "response";
      requestId: string;
      ok: true;
      operation: "get";
      credential: SerializedAssertionCredential;
    }
  | {
      channel: typeof BRIDGE_CHANNEL;
      source: "extension";
      kind: "response";
      requestId: string;
      ok: false;
      error: {
        code: ExtensionErrorCode;
        message: string;
      };
    };

export type PageBridgeMessage = PageBridgeRequest | PageBridgeCancel;

export interface BackgroundWebAuthnRequest {
  kind: "localPasskeyWebAuthn";
  requestId: string;
  operation: BridgeOperation;
  publicKey: SerializedCreationOptions | SerializedRequestOptions;
}

export interface BackgroundConditionalProbeRequest {
  kind: "localPasskeyConditionalProbe";
  requestId: string;
  publicKey: SerializedRequestOptions;
}

export type BackgroundConditionalProbeResponse =
  | {
      ok: true;
      available: boolean;
    }
  | {
      ok: false;
      error: string;
    };

export interface BackgroundCancelRequest {
  kind: "localPasskeyCancel";
  requestId: string;
}

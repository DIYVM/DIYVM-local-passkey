import type {
  AssertionConfirmationDetails,
  CreationConfirmationDetails
} from "./software-authenticator";

export type ConfirmationDetails =
  | CreationConfirmationDetails
  | AssertionConfirmationDetails;

export interface GetConfirmationRequest {
  type: "getConfirmation";
  confirmationId: string;
}

export interface ResolveConfirmationRequest {
  type: "resolveConfirmation";
  confirmationId: string;
  decision: "local" | "fallback" | "cancel";
  credentialId?: string;
}

export type ConfirmationMessage =
  | GetConfirmationRequest
  | ResolveConfirmationRequest;

export type ConfirmationResponse =
  | {
      ok: true;
      details?: ConfirmationDetails;
    }
  | {
      ok: false;
      error: string;
    };

export function isConfirmationId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^[A-Za-z0-9_-]{32,64}$/u.test(value)
  );
}

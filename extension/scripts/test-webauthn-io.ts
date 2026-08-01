import "fake-indexeddb/auto";

import type {
  SerializedCreationOptions,
  SerializedRequestOptions
} from "../src/types";

import {
  IndexedDbVaultStore,
  deleteIndexedDbVault
} from "../src/indexeddb-vault";
import {
  MemoryVaultSessionStorage,
  PureVault
} from "../src/pure-vault";
import { SoftwareAuthenticator } from "../src/software-authenticator";

const ORIGIN = "https://webauthn.io";
const username = `diyvm-codex-${Date.now().toString(36)}-${crypto
  .randomUUID()
  .slice(0, 8)}`;
const databaseName = `diyvm-live-${crypto.randomUUID()}`;
let sessionCookie = "";

function captureSessionCookie(response: Response): void {
  const setCookie = response.headers.get("set-cookie");
  if (setCookie) {
    sessionCookie = setCookie.split(";", 1)[0] ?? sessionCookie;
  }
}

async function startSiteSession(): Promise<void> {
  const response = await fetch(`${ORIGIN}/`);
  captureSessionCookie(response);
  if (!response.ok || !sessionCookie) {
    throw new Error(
      `webauthn.io did not start a test session (${response.status})`
    );
  }
}

async function postJson<T>(
  path: string,
  body: Record<string, unknown>
): Promise<T> {
  const response = await fetch(`${ORIGIN}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(sessionCookie ? { Cookie: sessionCookie } : {})
    },
    body: JSON.stringify(body)
  });
  captureSessionCookie(response);
  const responseText = await response.text();
  if (!response.ok) {
    throw new Error(
      `webauthn.io ${path} returned ${response.status}: ${responseText}`
    );
  }
  return JSON.parse(responseText) as T;
}

const store = await IndexedDbVaultStore.open({ databaseName });
try {
  await startSiteSession();
  const vault = new PureVault(
    store,
    new MemoryVaultSessionStorage()
  );
  await vault.initialize("diyvm live compatibility test");
  const authenticator = new SoftwareAuthenticator(vault);

  const creationOptions = await postJson<SerializedCreationOptions>(
    "/registration/options",
    {
      username,
      user_verification: "preferred",
      attestation: "none",
      attachment: "platform",
      algorithms: ["es256"],
      discoverable_credential: "preferred",
      hints: ["client-device"]
    }
  );
  const createdCredential = await authenticator.makeCredential(
    ORIGIN,
    creationOptions
  );
  const registration = await postJson<{ verified: boolean }>(
    "/registration/verification",
    {
      username,
      response: createdCredential
    }
  );
  if (registration.verified !== true) {
    throw new Error("webauthn.io did not verify the registration");
  }

  const requestOptions = await postJson<SerializedRequestOptions>(
    "/authentication/options",
    {
      username: "",
      user_verification: "preferred",
      hints: ["client-device"]
    }
  );
  const assertion = await authenticator.getAssertion(
    ORIGIN,
    requestOptions
  );
  const authentication = await postJson<{ verified: boolean }>(
    "/authentication/verification",
    {
      username: "",
      response: assertion
    }
  );
  if (authentication.verified !== true) {
    throw new Error("webauthn.io did not verify the authentication");
  }

  console.log(
    JSON.stringify(
      {
        site: ORIGIN,
        username,
        registrationVerified: true,
        authenticationVerified: true,
        credentialId: createdCredential.id,
        signCount: 1
      },
      null,
      2
    )
  );
} finally {
  store.close();
  await deleteIndexedDbVault(databaseName);
}

(() => {
const BRIDGE_CHANNEL = "local-passkey:webauthn:v1";
const bridgeRequests = [];
const bridgeCancels = [];
const nativeFallbackCalls = [];
let responseMode = "success";

const fallbackCredential = { source: "browser-native-fallback" };
const credentials = navigator.credentials;

Object.defineProperties(credentials, {
  create: {
    configurable: true,
    value: async (options) => {
      nativeFallbackCalls.push({ operation: "create", options });
      return fallbackCredential;
    }
  },
  get: {
    configurable: true,
    value: async (options) => {
      nativeFallbackCalls.push({ operation: "get", options });
      return fallbackCredential;
    }
  }
});

window.addEventListener("message", (event) => {
  const message = event.data;
  if (
    event.source !== window ||
    event.origin !== location.origin ||
    message?.channel !== BRIDGE_CHANNEL ||
    message?.source !== "page"
  ) {
    return;
  }

  if (message.kind === "cancel") {
    bridgeCancels.push(message);
    return;
  }
  if (message.kind !== "request") {
    return;
  }

  bridgeRequests.push(message);
  if (responseMode === "hold") {
    return;
  }

  const response =
    responseMode === "fallback"
      ? {
          channel: BRIDGE_CHANNEL,
          source: "extension",
          kind: "response",
          requestId: message.requestId,
          ok: false,
          error: {
            code: "USE_NATIVE_AUTHENTICATOR",
            message: "Use Chrome"
          }
        }
      : responseMode === "invalidState"
        ? {
            channel: BRIDGE_CHANNEL,
            source: "extension",
            kind: "response",
            requestId: message.requestId,
            ok: false,
            error: {
              code: "INVALID_STATE",
              message: "Credential already exists"
            }
          }
        : {
            channel: BRIDGE_CHANNEL,
            source: "extension",
            kind: "response",
            requestId: message.requestId,
            ok: true,
            operation: message.operation,
            credential:
              message.operation === "create"
                ? {
                    id: "AQIDBA",
                    rawId: "AQIDBA",
                    type: "public-key",
                    authenticatorAttachment: "platform",
                    response: {
                      clientDataJSON: "e30",
                      attestationObject: "AQI",
                      authenticatorData: "AwQ",
                      publicKey: "BQY",
                      publicKeyAlgorithm: -7,
                      transports: ["internal"]
                    },
                    clientExtensionResults: {
                      credProps: { rk: true }
                    }
                  }
                : {
                    id: "AQIDBA",
                    rawId: "AQIDBA",
                    type: "public-key",
                    authenticatorAttachment: "platform",
                    response: {
                      clientDataJSON: "e30",
                      authenticatorData: "AwQ",
                      signature: "BQY",
                      userHandle: "Bwg"
                    },
                    clientExtensionResults: {}
                  }
          };

  queueMicrotask(() => window.postMessage(response, location.origin));
});

window.addEventListener("DOMContentLoaded", () => {
  void runTests();
});

async function runTests() {
  const cases = [
    ["serializes creation and restores attestation prototypes", testCreate],
    ["matches SimpleWebAuthn 12 registration response access", testSimpleWebAuthn12],
    ["serializes requests and restores assertion prototypes", testGet],
    ["keeps non-WebAuthn and conditional requests native", testBypass],
    ["falls back to the saved Chrome implementation", testFallback],
    ["maps native errors to DOMException names", testErrorMapping],
    ["aborts pending ceremonies and emits cancellation", testAbort]
  ];

  try {
    for (const [name, test] of cases) {
      await test();
      appendResult(name, true);
    }
    setStatus("passed", `${cases.length} browser checks passed`);
  } catch (error) {
    appendResult(error instanceof Error ? error.message : String(error), false);
    setStatus("failed", "Browser checks failed");
    console.error(error);
  }
}

async function testCreate() {
  responseMode = "success";
  const credential = await navigator.credentials.create({
    publicKey: {
      rp: { id: location.hostname, name: "Local test" },
      user: {
        id: Uint8Array.of(9, 8, 7),
        name: "tester@example.com",
        displayName: "Tester"
      },
      challenge: Uint8Array.from({ length: 32 }, (_, index) => index),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "preferred"
      },
      extensions: { credProps: true }
    }
  });

  const request = last(bridgeRequests);
  assert(request.operation === "create", "creation was not intercepted");
  assert(request.publicKey.user.id === "CQgH", "user ID was not Base64URL encoded");
  assert(request.publicKey.challenge.length === 43, "challenge encoding is invalid");
  assert(credential instanceof PublicKeyCredential, "credential prototype is invalid");
  assert(
    credential.response instanceof AuthenticatorAttestationResponse,
    "attestation response prototype is invalid"
  );
  assert(
    bytes(credential.rawId) === "1,2,3,4",
    "credential raw ID was not restored"
  );
  assert(
    bytes(credential.response.getAuthenticatorData()) === "3,4",
    "authenticator data method is invalid"
  );
  assert(
    credential.response.getPublicKeyAlgorithm() === -7,
    "public key algorithm is invalid"
  );
  assert(
    credential.getClientExtensionResults().credProps.rk === true,
    "extension results are invalid"
  );
}

async function testGet() {
  responseMode = "success";
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: Uint8Array.from({ length: 32 }, () => 7),
      rpId: location.hostname,
      allowCredentials: [
        {
          type: "public-key",
          id: Uint8Array.of(1, 2, 3, 4),
          transports: ["internal"]
        }
      ]
    }
  });

  const request = last(bridgeRequests);
  assert(request.operation === "get", "assertion was not intercepted");
  assert(
    request.publicKey.allowCredentials[0].id === "AQIDBA",
    "allowCredentials was not serialized"
  );
  assert(credential instanceof PublicKeyCredential, "assertion prototype is invalid");
  assert(
    credential.response instanceof AuthenticatorAssertionResponse,
    "assertion response prototype is invalid"
  );
  assert(bytes(credential.response.signature) === "5,6", "signature is invalid");
  assert(bytes(credential.response.userHandle) === "7,8", "user handle is invalid");
}

async function testSimpleWebAuthn12() {
  responseMode = "success";
  const credential = await navigator.credentials.create({
    publicKey: {
      rp: { id: location.hostname, name: "Local test" },
      user: {
        id: Uint8Array.of(9, 8, 7),
        name: "tester@example.com",
        displayName: "Tester"
      },
      challenge: Uint8Array.from({ length: 32 }, (_, index) => index),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "preferred"
      },
      extensions: { credProps: true }
    }
  });

  const { id, rawId, response, type } = credential;
  const result = {
    id,
    rawId: base64Url(rawId),
    response: {
      attestationObject: base64Url(response.attestationObject),
      clientDataJSON: base64Url(response.clientDataJSON),
      transports:
        typeof response.getTransports === "function"
          ? response.getTransports()
          : undefined,
      publicKeyAlgorithm:
        typeof response.getPublicKeyAlgorithm === "function"
          ? response.getPublicKeyAlgorithm()
          : undefined,
      publicKey:
        typeof response.getPublicKey === "function" && response.getPublicKey()
          ? base64Url(response.getPublicKey())
          : undefined,
      authenticatorData:
        typeof response.getAuthenticatorData === "function"
          ? base64Url(response.getAuthenticatorData())
          : undefined
    },
    type,
    clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: credential.authenticatorAttachment
  };
  const json = credential.toJSON();

  assert(result.id === "AQIDBA", "SimpleWebAuthn could not read credential ID");
  assert(result.rawId === "AQIDBA", "SimpleWebAuthn could not encode raw ID");
  assert(
    result.response.publicKeyAlgorithm === -7,
    "SimpleWebAuthn could not read the public key algorithm"
  );
  assert(
    result.clientExtensionResults.credProps.rk === true,
    "SimpleWebAuthn could not read extension results"
  );
  assert(
    json.response.attestationObject === "AQI",
    "PublicKeyCredential.toJSON() output is invalid"
  );
}

async function testBypass() {
  const requestsBefore = bridgeRequests.length;
  const fallbacksBefore = nativeFallbackCalls.length;

  const nonWebAuthn = await navigator.credentials.create({});
  const conditional = await navigator.credentials.get({
    mediation: "conditional",
    publicKey: {
      challenge: Uint8Array.from({ length: 32 }, () => 1)
    }
  });

  assert(nonWebAuthn === fallbackCredential, "non-WebAuthn creation did not bypass");
  assert(conditional === fallbackCredential, "conditional request did not bypass");
  assert(
    bridgeRequests.length === requestsBefore,
    "bypassed requests reached the extension bridge"
  );
  assert(
    nativeFallbackCalls.length === fallbacksBefore + 2,
    "saved Chrome methods were not called"
  );
}

async function testFallback() {
  responseMode = "fallback";
  const fallbacksBefore = nativeFallbackCalls.length;
  const result = await navigator.credentials.get({
    publicKey: {
      challenge: Uint8Array.from({ length: 32 }, () => 2)
    }
  });

  assert(result === fallbackCredential, "fallback result was not returned");
  assert(
    nativeFallbackCalls.length === fallbacksBefore + 1,
    "Chrome fallback was not called once"
  );
}

async function testErrorMapping() {
  responseMode = "invalidState";
  let caught;
  try {
    await navigator.credentials.create({
      publicKey: {
        rp: { name: "Local test" },
        user: {
          id: Uint8Array.of(1),
          name: "tester@example.com",
          displayName: "Tester"
        },
        challenge: Uint8Array.from({ length: 32 }, () => 3),
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      }
    });
  } catch (error) {
    caught = error;
  }

  assert(caught instanceof DOMException, "native error was not a DOMException");
  assert(caught.name === "InvalidStateError", "native error name was not mapped");
}

async function testAbort() {
  responseMode = "hold";
  const controller = new AbortController();
  const pending = navigator.credentials.get({
    publicKey: {
      challenge: Uint8Array.from({ length: 32 }, () => 4)
    },
    signal: controller.signal
  });
  await new Promise((resolve) => setTimeout(resolve, 0));
  const requestId = last(bridgeRequests).requestId;
  controller.abort();

  let caught;
  try {
    await pending;
  } catch (error) {
    caught = error;
  }

  await new Promise((resolve) => setTimeout(resolve, 0));
  assert(caught instanceof DOMException, "abort was not a DOMException");
  assert(caught.name === "AbortError", "abort error name is invalid");
  assert(
    bridgeCancels.some((message) => message.requestId === requestId),
    "abort cancellation was not posted"
  );
}

function bytes(value) {
  return Array.from(new Uint8Array(value)).join(",");
}

function base64Url(value) {
  let binary = "";
  const data = new Uint8Array(value);
  for (const byte of data) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

function last(values) {
  const value = values.at(-1);
  assert(value, "expected at least one bridge message");
  return value;
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function appendResult(name, passed) {
  const item = document.createElement("li");
  item.textContent = `${passed ? "PASS" : "FAIL"} — ${name}`;
  item.dataset.result = passed ? "passed" : "failed";
  document.querySelector("#results").append(item);
}

function setStatus(status, text) {
  const element = document.querySelector("#status");
  element.dataset.status = status;
  element.textContent = text;
  document.documentElement.dataset.testStatus = status;
}
})();

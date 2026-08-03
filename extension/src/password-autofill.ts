import type { PasswordDetails } from "./types";
import { fillPasswordInPage } from "./page-password-actions";
import { sendRuntimeMessage } from "./runtime-message";

type AutoFillResponse =
  | {
      ok: true;
      credential?: PasswordDetails;
    }
  | {
      ok: false;
      error: string;
    };

if (location.protocol === "https:") {
  let requested = false;
  let observer: MutationObserver | undefined;
  const requestWhenReady = (): void => {
    if (
      requested ||
      !document.querySelector('input[type="password"]')
    ) {
      return;
    }
    requested = true;
    observer?.disconnect();
    void sendRuntimeMessage<AutoFillResponse>({
      type: "getAutoFillCredential"
    })
      .then((response) => {
        if (response.ok && response.credential) {
          fillPasswordInPage(
            response.credential.username,
            response.credential.password
          );
        }
      })
      .catch(() => undefined);
  };

  requestWhenReady();
  if (!requested) {
    observer = new MutationObserver(requestWhenReady);
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
    window.setTimeout(() => observer?.disconnect(), 30_000);
  }
}

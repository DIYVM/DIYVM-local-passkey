const ALLOWED_EXACT_HOSTS = new Set(["webauthn.io", "amazon.com"]);

export function allowedPageOrigin(urlValue: string): string | undefined {
  try {
    const url = new URL(urlValue);
    const hostname = url.hostname.toLowerCase();
    const allowedHost =
      ALLOWED_EXACT_HOSTS.has(hostname) || hostname.endsWith(".amazon.com");

    if (
      url.protocol !== "https:" ||
      !allowedHost ||
      url.username !== "" ||
      url.password !== "" ||
      url.port !== ""
    ) {
      return undefined;
    }
    return url.origin;
  } catch {
    return undefined;
  }
}

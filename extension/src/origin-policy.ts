export function allowedPageOrigin(urlValue: string): string | undefined {
  try {
    const url = new URL(urlValue);

    if (
      url.protocol !== "https:" ||
      url.hostname.length === 0 ||
      url.username !== "" ||
      url.password !== ""
    ) {
      return undefined;
    }
    return url.origin;
  } catch {
    return undefined;
  }
}

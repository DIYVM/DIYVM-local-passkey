import { amazonMarketplaceForHostname } from "./amazon-sites";

export function isAllowedAmazonHostname(hostname: string): boolean {
  return amazonMarketplaceForHostname(hostname) !== undefined;
}

export function allowedPageOrigin(urlValue: string): string | undefined {
  try {
    const url = new URL(urlValue);

    if (
      url.protocol !== "https:" ||
      !isAllowedAmazonHostname(url.hostname) ||
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

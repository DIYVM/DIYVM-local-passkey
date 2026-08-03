export interface AmazonMarketplace {
  domain: string;
  label: string;
  region: string;
}

export const PRIMARY_AMAZON_DOMAIN = "amazon.com";

export const AMAZON_MARKETPLACES: readonly AmazonMarketplace[] = [
  { domain: "amazon.com", label: "美国", region: "北美" },
  { domain: "amazon.ca", label: "加拿大", region: "北美" },
  { domain: "amazon.com.mx", label: "墨西哥", region: "北美" },
  { domain: "amazon.com.br", label: "巴西", region: "南美" },
  { domain: "amazon.co.uk", label: "英国", region: "欧洲" },
  { domain: "amazon.de", label: "德国", region: "欧洲" },
  { domain: "amazon.fr", label: "法国", region: "欧洲" },
  { domain: "amazon.it", label: "意大利", region: "欧洲" },
  { domain: "amazon.es", label: "西班牙", region: "欧洲" },
  { domain: "amazon.nl", label: "荷兰", region: "欧洲" },
  { domain: "amazon.se", label: "瑞典", region: "欧洲" },
  { domain: "amazon.pl", label: "波兰", region: "欧洲" },
  { domain: "amazon.com.be", label: "比利时", region: "欧洲" },
  { domain: "amazon.ie", label: "爱尔兰", region: "欧洲" },
  { domain: "amazon.com.tr", label: "土耳其", region: "欧洲" },
  { domain: "amazon.co.jp", label: "日本", region: "亚太" },
  { domain: "amazon.in", label: "印度", region: "亚太" },
  { domain: "amazon.com.au", label: "澳大利亚", region: "亚太" },
  { domain: "amazon.sg", label: "新加坡", region: "亚太" },
  { domain: "amazon.ae", label: "阿联酋", region: "中东和非洲" },
  { domain: "amazon.sa", label: "沙特阿拉伯", region: "中东和非洲" },
  { domain: "amazon.eg", label: "埃及", region: "中东和非洲" },
  { domain: "amazon.co.za", label: "南非", region: "中东和非洲" }
] as const;

const MARKETPLACE_DOMAINS = new Set(
  AMAZON_MARKETPLACES.map((marketplace) => marketplace.domain)
);

export function isAmazonMarketplaceDomain(domain: string): boolean {
  return MARKETPLACE_DOMAINS.has(domain.toLowerCase());
}

export function amazonMarketplaceForHostname(
  hostname: string
): AmazonMarketplace | undefined {
  const normalized = hostname.toLowerCase().replace(/\.$/u, "");
  return AMAZON_MARKETPLACES.find(
    ({ domain }) =>
      normalized === domain || normalized.endsWith(`.${domain}`)
  );
}

export function amazonMatchPatterns(domain: string): [string, string] {
  if (!isAmazonMarketplaceDomain(domain)) {
    throw new TypeError("不支持的 Amazon 区域站域名");
  }
  return [`https://${domain}/*`, `https://*.${domain}/*`];
}

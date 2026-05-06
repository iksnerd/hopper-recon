export const MOCK_TARGET = "tesla.com"

export const mockSubdomains = [
  "api.tesla.com", "owner-api.tesla.com", "auth.tesla.com", "fleet-api.tesla.com",
  "www.tesla.com", "shop.tesla.com", "service.tesla.com", "energy.tesla.com",
  "media.tesla.com", "cdn.tesla.com", "static.tesla.com", "assets.tesla.com",
  "blog.tesla.com", "forums.tesla.com", "support.tesla.com", "careers.tesla.com",
  "ir.tesla.com", "investor.tesla.com", "model3.tesla.com", "models.tesla.com",
  "modelx.tesla.com", "modely.tesla.com", "cybertruck.tesla.com", "roadster.tesla.com",
]

export const mockDns = {
  host: "tesla.com",
  ttl: 132,
  resolver: ["1.0.0.1:53", "8.8.8.8:53"],
  a: [
    "2.18.53.207", "2.18.54.207", "2.18.48.207", "2.18.50.207",
    "23.40.100.207", "23.7.244.207", "2.18.55.207", "2.18.51.207",
    "2.18.52.207", "2.18.49.207",
  ],
  status_code: "NOERROR",
  timestamp: "2026-05-06T10:30:21Z",
}

export const mockTls = {
  host: "tesla.com",
  ip: "23.40.100.207",
  port: "443",
  tls_version: "tls13",
  cipher: "TLS_AES_256_GCM_SHA384",
  not_before: "2026-03-10T21:27:01Z",
  not_after: "2026-06-08T21:27:00Z",
  subject_cn: "tesla.com",
  subject_an: ["tesla.com"],
  issuer_cn: "R12",
  issuer_org: ["Let's Encrypt"],
  serial: "05:2E:6F:BB:A5:86:CE:9E:BA:AA:7A:54:91:2B:68:D6:17:5D",
  fingerprint_hash: {
    md5: "c90050ad1e80862bb866fd7b5506365b",
    sha1: "1cc80f7a39a943f5dc1a390280c678d277c9a7b0",
    sha256: "b14677eefad96f215495d031592ae2dd9ee443b28ed29b8c035e1e5a6804b93a",
  },
}

export const mockHttp = {
  url: "https://tesla.com",
  title: "Access Denied",
  scheme: "https",
  webserver: "AkamaiGHost",
  status_code: 403,
  content_type: "text/html",
  tech: ["HSTS"],
  time: "183.526708ms",
  content_length: 359,
  a: [
    "2.18.52.207", "2.18.54.207", "2.18.53.207", "2.18.50.207", "2.18.49.207",
    "23.7.244.207", "23.40.100.207", "2.18.51.207", "2.18.48.207", "2.18.55.207",
  ],
}

// Cert expiry chart data (days remaining over the last 6 months)
export const certExpiryHistory = [
  { month: "Dec", days: 180 },
  { month: "Jan", days: 151 },
  { month: "Feb", days: 120 },
  { month: "Mar", days: 90 },
  { month: "Apr", days: 60 },
  { month: "May", days: 33 },
]

// IP distribution by /24 prefix
export const ipDistribution = [
  { prefix: "2.18.48.x", count: 8 },
  { prefix: "23.40.x.x", count: 1 },
  { prefix: "23.7.x.x",  count: 1 },
]

// Subdomain categories derived from names
export const subdomainCategories = [
  { category: "API / Auth",   count: 3 },
  { category: "Consumer",     count: 6 },
  { category: "Marketing",    count: 4 },
  { category: "Infrastructure", count: 5 },
  { category: "Support",      count: 4 },
  { category: "IR / Careers", count: 2 },
]

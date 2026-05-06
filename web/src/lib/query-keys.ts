export const queryKeys = {
  domains: () => ["domains"] as const,
  domainRows: (domain: string) => ["domain-rows", domain] as const,
}

import type { Metadata } from "next";
import { Geist_Mono } from "next/font/google";
import { QueryProvider } from "@/components/query-provider";
import "./globals.css";

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  metadataBase: new URL("https://github.com/iksnerd/hopper-recon"),
  title: {
    default: "hopper-recon",
    template: "%s · hopper-recon",
  },
  description:
    "Self-hosted attack surface recon dashboard + MCP server. AI agents and humans drive subfinder, dnsx, tlsx, httpx, cdncheck, urlfinder, and alterx — passive, non-invasive, no account required.",
  applicationName: "hopper-recon",
  authors: [{ name: "iksnerd", url: "https://github.com/iksnerd" }],
  keywords: [
    "recon", "osint", "subdomain-enumeration", "dns", "tls", "httpx",
    "mcp", "mcp-server", "security", "self-hosted", "attack-surface",
    "cdn", "alterx", "subfinder", "projectdiscovery", "bug-bounty",
  ],
  robots: { index: true, follow: true },
  openGraph: {
    title: "hopper-recon",
    description:
      "Self-hosted attack surface recon dashboard + MCP server. Passive, non-invasive — subfinder, dnsx, tlsx, httpx, cdncheck, urlfinder, alterx. Docker Compose, no account required.",
    type: "website",
    url: "https://github.com/iksnerd/hopper-recon",
    siteName: "hopper-recon",
  },
  twitter: {
    card: "summary_large_image",
    title: "hopper-recon",
    description:
      "Self-hosted attack surface recon dashboard + MCP server. AI agents and humans drive subfinder, dnsx, tlsx, httpx, cdncheck, alterx via Docker Compose.",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${geistMono.variable} h-full antialiased dark`}
    >
      <body className="min-h-full flex flex-col grid-bg"><QueryProvider>{children}</QueryProvider></body>
    </html>
  );
}

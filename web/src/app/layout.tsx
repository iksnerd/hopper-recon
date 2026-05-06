import type { Metadata } from "next";
import { Geist_Mono } from "next/font/google";
import { QueryProvider } from "@/components/query-provider";
import "./globals.css";

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: {
    default: "hopper-recon",
    template: "%s · hopper-recon",
  },
  description:
    "agent-first attack surface reconnaissance — passive, non-invasive scanning consumed via MCP. maps subdomains, dns, tls, and http without touching target infrastructure.",
  applicationName: "hopper-recon",
  authors: [{ name: "hopper-recon" }],
  keywords: ["recon", "osint", "subdomain", "dns", "tls", "httpx", "mcp", "security"],
  robots: { index: true, follow: true },
  openGraph: {
    title: "hopper-recon",
    description: "agent-first attack surface reconnaissance",
    type: "website",
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

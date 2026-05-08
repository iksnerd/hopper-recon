import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactCompiler: true,
  // Standalone output for the self-hosted Docker image. OpenNext/Cloudflare
  // run their own build pipeline and ignore this.
  output: "standalone",
};

export default nextConfig;

import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactCompiler: true,
  // Standalone output for the self-hosted Docker image. OpenNext/Cloudflare
  // run their own build pipeline and ignore this.
  output: "standalone",
  // `next dev` blocks dev-only assets requested from any origin but `localhost`,
  // so opening http://127.0.0.1:9120 (the URL the README uses for the engine)
  // loads the HTML and then never hydrates. Dev only; no effect on the build.
  allowedDevOrigins: ["127.0.0.1"],
};

export default nextConfig;

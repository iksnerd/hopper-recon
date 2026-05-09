import { defineConfig } from "vitest/config"
import path from "node:path"

// Vitest config — lightweight smoke-test harness for the parsers and other
// pure modules. Mirrors the Next.js path alias so tests can `import @/lib/...`
// without juggling relative paths.
export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
  },
})

export interface McpToolResult {
  content: Array<{ type: string; text: string }>
  isError?: boolean
}

export interface ScanExecutor {
  run(tool: string, args: Record<string, string>): Promise<McpToolResult>
}

// ── Docker (local dev) ────────────────────────────────────────────────────────

function createDockerExecutor(): ScanExecutor {
  return {
    run: async (tool, args) => {
      const { callDockerTool } = await import("./docker-mcp")
      return callDockerTool(tool as Parameters<typeof callDockerTool>[0], args)
    },
  }
}

// ── Cloudflare Sandboxes (production) ─────────────────────────────────────────

function createSandboxExecutor(): ScanExecutor {
  return {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    run: async (_tool, _args) => {
      // TODO: replace with real Cloudflare Sandbox SDK call once available
      // Expected shape when wired up:
      //
      //   const { getCloudflareContext } = await import("@opennextjs/cloudflare")
      //   const { env } = await getCloudflareContext()
      //   const sb = await env.SCANNER_ENV.create({
      //     image: "registry.cloudflare.com/your-account/hopper-recon:latest",
      //     id: `scan-${Date.now()}`,
      //   })
      //   const mcpPayload = JSON.stringify({
      //     method: "tools/call",
      //     params: { name: tool, arguments: args },
      //   })
      //   const result = await sb.exec(`echo '${mcpPayload}' | hopper-recon`)
      //   return JSON.parse(result.stdout)

      throw new Error("Cloudflare Sandbox executor not yet configured — set SCANNER_ENV binding in wrangler.jsonc")
    },
  }
}

// ── Factory — auto-detects environment ───────────────────────────────────────

export async function getExecutor(): Promise<ScanExecutor> {
  try {
    const { getCloudflareContext } = await import("@opennextjs/cloudflare")
    const { env } = await getCloudflareContext()
    if (env.SCANNER_ENV) return createSandboxExecutor()
  } catch {
    // Not on Cloudflare — fall through to Docker
  }

  return createDockerExecutor()
}

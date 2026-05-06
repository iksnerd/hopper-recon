import { spawn } from "child_process"
import { existsSync } from "fs"
import { homedir } from "os"

type McpTool = "passive_subdomains" | "resolve_dns" | "fetch_tls_cert" | "probe_http" | "map_asn" | "search_hosts" | "lookup_geoip"

interface McpResult {
  content: Array<{ type: string; text: string }>
  isError?: boolean
}

const TOOL_TIMEOUT_MS = 90_000

export async function callDockerTool(tool: McpTool, args: Record<string, string>): Promise<McpResult> {
  return new Promise((resolve, reject) => {
    const dockerArgs = ["run", "--rm", "-i"]
    if (tool === "passive_subdomains") {
      const cfgDir = `${homedir()}/.config/subfinder`
      if (existsSync(`${cfgDir}/provider-config.yaml`)) {
        dockerArgs.push("-v", `${cfgDir}:/root/.config/subfinder:ro`)
      }
    }
    if (tool === "search_hosts") {
      const cfgDir = `${homedir()}/.config/uncover`
      if (existsSync(`${cfgDir}/provider-config.yaml`)) {
        dockerArgs.push("-v", `${cfgDir}:/root/.config/uncover:ro`)
      }
    }
    if (tool === "lookup_geoip") {
      const mmdb = `${homedir()}/.config/hopper-recon/GeoLite2-Country.mmdb`
      if (existsSync(mmdb)) {
        dockerArgs.push("-v", `${mmdb}:/root/.config/hopper-recon/GeoLite2-Country.mmdb:ro`)
      }
    }
    dockerArgs.push("hopper-recon:latest")
    const proc = spawn("docker", dockerArgs)

    let stdout = ""
    let stderr = ""
    let msgId = 1
    let settled = false

    const settle = (result: McpResult) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      proc.stdin.end()
      resolve(result)
    }

    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      proc.kill("SIGKILL")
      resolve({ content: [{ type: "text", text: `Tool timed out after ${TOOL_TIMEOUT_MS / 1000}s` }], isError: true })
    }, TOOL_TIMEOUT_MS)

    const send = (msg: object) => {
      proc.stdin.write(JSON.stringify(msg) + "\n")
    }

    proc.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString()
      const lines = stdout.split("\n")
      stdout = lines.pop() ?? ""

      for (const line of lines) {
        if (!line.trim()) continue
        try {
          const msg = JSON.parse(line)

          // After initialize response, send initialized + tool call
          if (msg.id === 1 && msg.result) {
            send({ jsonrpc: "2.0", method: "notifications/initialized", params: {} })
            send({
              jsonrpc: "2.0",
              id: ++msgId,
              method: "tools/call",
              params: { name: tool, arguments: args },
            })
          }

          // Tool call response
          if (msg.id === 2 && (msg.result || msg.error)) {
            if (msg.error) {
              settle({ content: [{ type: "text", text: msg.error.message }], isError: true })
            } else {
              settle(msg.result as McpResult)
            }
          }
        } catch {
          // incomplete JSON, wait for more data
        }
      }
    })

    proc.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString()
    })

    proc.on("error", (err) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      reject(new Error(`Docker spawn failed: ${err.message}`))
    })
    proc.on("close", (code) => {
      if (settled) return
      if (code !== 0) {
        settled = true
        clearTimeout(timer)
        reject(new Error(`Container exited ${code}: ${stderr}`))
      }
      // code === 0 but no tool result — let the 90 s timer resolve this
    })

    // Kick off MCP handshake
    send({
      jsonrpc: "2.0",
      id: msgId,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "hopper-recon-web", version: "0.1" },
      },
    })
  })
}

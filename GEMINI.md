# GEMINI.md - hopper-recon

## Project Overview
**hopper-recon** is an "Agent-First Recon SaaS" designed to provide automated security reconnaissance. The system architecture consists of:
- **Recon Engine (`/engine`):** A custom Go-based MCP (Model Context Protocol) server that wraps safe, non-invasive security tools from ProjectDiscovery.
- **Frontend & API (`/web`):** A Next.js application (planned) deployed to Cloudflare Pages.
- **Infrastructure:** Cloudflare Sandboxes for executing the recon engine in isolated containers.

## Core Technologies
- **Language:** Go 1.26+ (Engine), TypeScript (Web)
- **Security Tools (Zero Impact Policy):** 
  - `subfinder` (Tier 1 Passive: OSINT subdomain enumeration)
  - `dnsx` (Tier 2 Safe: Standard DNS resolution)
  - `tlsx` (Tier 2 Safe: SSL/TLS certificate fetching)
  - `httpx` (Tier 2 Safe: Rate-limited HTTP probing)
- **Protocols:** MCP (Model Context Protocol) for tool/agent interaction.
- **Virtualization:** Docker for local development and Cloudflare Sandbox deployment.

## Building and Running

### Recon Engine (Docker)
To build and run the recon engine locally using Docker, navigate to the `engine` directory:

```bash
cd engine

# Build the image
docker build -t hopper-recon .

# Run the MCP server (interactively via stdio)
docker run -i hopper-recon
```

### Recon Engine (Local Go)
Ensure `subfinder`, `dnsx`, `tlsx`, and `httpx` are installed and in your PATH.
```bash
cd engine

# Add dependencies
go mod tidy

# Run the server
go run main.go
```

### Next.js Frontend (TODO)
The Next.js application will live in the `/web` directory.
```bash
cd web
# (Future Next.js setup commands)
```

## Local Testing (MCP)
Since the server communicates via JSON-RPC over stdio, you can test it manually or via an MCP client.

**Example 1: passive_subdomains (subfinder)**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "passive_subdomains",
    "arguments": {
      "domain": "example.com"
    }
  }
}
```

**Example 2: resolve_dns (dnsx)**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "resolve_dns",
    "arguments": {
      "target": "example.com"
    }
  }
}
```

**Example 3: fetch_tls_cert (tlsx)**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "fetch_tls_cert",
    "arguments": {
      "target": "example.com"
    }
  }
}
```

**Example 4: probe_http (httpx)**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "probe_http",
    "arguments": {
      "target": "example.com"
    }
  }
}
```

## Development Conventions
- **Zero Impact Policy:** Any tool added to the recon engine MUST be Tier 1 (passive OSINT) or Tier 2 (safe probing with strict rate limits), as defined in `pd-tools.md`. Highly invasive tools like `nuclei` (without specific passive tags) or active crawlers like `katana` are strictly prohibited.
- **Tool Wrapping:** New recon tools should be implemented as Go handlers and registered with the MCP server in `engine/main.go`.
- **Statelessness:** The engine should remain stateless, relying on the caller (or database) to persist results.
- **Standard Input/Output:** Always use `mcp.StdioTransport` for the engine to remain compatible with MCP hosts.

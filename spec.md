Here is the complete, end-to-end Technical Specification for building your "Agent-First Recon SaaS" on the 2026 Cloudflare stack.

This spec covers the database schema, the Next.js architecture, the API orchestration, and the deployment configuration.

---

## 1. System Architecture Overview

*   **Frontend & API:** Next.js (App Router) deployed to Cloudflare Pages.
*   **Database:** Cloudflare D1 (Serverless SQLite).
*   **Execution Engine:** Cloudflare Sandboxes running your custom Go/MCP Docker image.
*   **Authentication:** NextAuth.js (Auth.js) using GitHub/Google OAuth.

---

## 2. Database Schema (Cloudflare D1)
Save this as `schema.sql`. You will run this to initialize your database. We need three primary tables: Users, Targets, and Scans.

```sql
-- schema.sql
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    mcp_secret TEXT UNIQUE NOT NULL, -- Used for their IDE Agent to authenticate
    tier TEXT DEFAULT 'free',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE targets (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE scans (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    status TEXT DEFAULT 'pending', -- pending, running, completed, failed
    results_json TEXT,             -- The raw MCP/ProjectDiscovery output
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    FOREIGN KEY(target_id) REFERENCES targets(id)
);

CREATE INDEX idx_scans_target ON scans(target_id);
```

---

## 3. Next.js Application Structure
Initialize a standard Next.js 15+ App Router project (`npx create-next-app@latest`).

### Key Directory Layout
```text
/app
  /api
    /mcp              # The endpoint IDE agents talk to
      route.ts
    /scan             # The internal API for the Web Dashboard
      route.ts
  /dashboard          # Web UI for humans
    page.tsx
/lib
  /db.ts              # D1 database wrapper
  /sandbox.ts         # Cloudflare Sandbox trigger logic
wrangler.toml         # The master configuration file
```

---

## 4. The Core Logic: Triggering the Sandbox
This is the bridge between Next.js and your Docker image.

```typescript
// lib/sandbox.ts
import { Sandbox } from "@cloudflare/sandbox-sdk";

export async function triggerReconScan(domain: string, scanId: string, env: any) {
  // 1. Spin up the isolated environment using your Docker image
  const sb = await Sandbox.create({
    image: "registry.cloudflare.com/your-account/recon-engine-go:latest",
    id: `scan-${scanId}`,
    limits: { cpu: 1, memory: "2GiB" } 
  });

  // 2. We use the MCP interface to trigger the scan
  // This is identical to how a local AI agent would call it
  const mcpPayload = {
    method: "tools/call",
    params: {
      name: "passive_recon",
      arguments: { domain: domain }
    }
  };

  // 3. Send the command to the Sandbox via stdio
  const result = await sb.exec(`echo '${JSON.stringify(mcpPayload)}' | mcp-recon-server`);
  
  return result.stdout;
}
```

---

## 5. The API Routes

### Route A: The Agent Endpoint (`/api/mcp/route.ts`)
This is the URL your users will give to Cursor or Claude. It authenticates via a Bearer token (their `mcp_secret`).

```typescript
// app/api/mcp/route.ts
import { triggerReconScan } from "@/lib/sandbox";

export async function POST(req: Request) {
  // 1. Authenticate the Agent
  const authHeader = req.headers.get("Authorization");
  if (!authHeader) return new Response("Unauthorized", { status: 401 });
  
  // (In a real app, verify the mcp_secret against D1 here)

  // 2. Parse the MCP Request
  const body = await req.json();
  const domain = body.params.arguments.domain;

  // 3. Run the scan in the Sandbox
  const scanId = crypto.randomUUID();
  const scanResults = await triggerReconScan(domain, scanId, process.env);

  // 4. Return standard MCP format to the Agent
  return Response.json(JSON.parse(scanResults));
}
```

### Route B: The Web Dashboard Endpoint (`/api/scan/route.ts`)
This is used if the user clicks "Scan Now" in your web UI. Because scans take time, this should return immediately and update the database in the background.

```typescript
// app/api/scan/route.ts
// (Requires Next.js Edge Runtime for Cloudflare)
export const runtime = 'edge';

export async function POST(req: Request) {
  const { domain, targetId } = await req.json();
  const scanId = crypto.randomUUID();

  // 1. Insert 'pending' record into D1
  await req.env.DB.prepare(
    "INSERT INTO scans (id, target_id, status) VALUES (?, ?, ?)"
  ).bind(scanId, targetId, 'pending').run();

  // 2. Trigger background execution (Cloudflare ctx.waitUntil)
  // This keeps the function running after responding to the user
  req.ctx.waitUntil(async () => {
    try {
      const results = await triggerReconScan(domain, scanId, req.env);
      
      // Update D1 with success
      await req.env.DB.prepare(
        "UPDATE scans SET status = 'completed', results_json = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?"
      ).bind(results, scanId).run();
      
    } catch (e) {
      // Update D1 with failure
      await req.env.DB.prepare(
        "UPDATE scans SET status = 'failed' WHERE id = ?"
      ).bind(scanId).run();
    }
  }());

  return Response.json({ status: "started", scanId });
}
```

---

## 6. The Deployment Configuration (`wrangler.toml`)
This is the most critical file. It tells Cloudflare how to connect Next.js, the D1 database, and the Container Registry.

```toml
# wrangler.toml
name = "agent-recon-saas"
pages_build_output_dir = ".vercel/output/static"
compatibility_date = "2026-05-01"
compatibility_flags = ["nodejs_compat"]

# 1. Bind your D1 Database
[[d1_databases]]
binding = "DB"
database_name = "recon-db-prod"
database_id = "YOUR-D1-UUID-HERE"

# 2. Enable Sandbox permissions for the Worker/Pages app
[[sandboxes]]
binding = "SCANNER_ENV"
registry = "registry.cloudflare.com/your-account"

# 3. Environment Variables
[vars]
ENVIRONMENT = "production"
```

---

## 7. Build and Deployment Steps

Here is your exact workflow to get this live:

1.  **Initialize Database:**
    `npx wrangler d1 create recon-db-prod`
    `npx wrangler d1 execute recon-db-prod --file=./schema.sql`
2.  **Push the Docker Image to Cloudflare Registry:**
    `docker build -t recon-engine-go .`
    `docker tag recon-engine-go [registry.cloudflare.com/your-account/recon-engine-go:latest](https://registry.cloudflare.com/your-account/recon-engine-go:latest)`
    `docker push [registry.cloudflare.com/your-account/recon-engine-go:latest](https://registry.cloudflare.com/your-account/recon-engine-go:latest)`
3.  **Deploy the Next.js App:**
    Use `@cloudflare/next-on-pages` to build and deploy.
    `npx @cloudflare/next-on-pages`
    `npx wrangler pages deploy .vercel/output/static`

**Next steps for you:** Set up the Next.js project and test the UI using local mock data before wiring up the D1 database. Let me know when you are ready to write the UI components.
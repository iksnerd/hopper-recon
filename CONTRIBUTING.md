# Contributing to Hopper Recon

Thanks for the interest. Hopper Recon is small, opinionated, and meant to
stay that way. This guide is aimed at someone landing a first PR.

## Authorized-use posture

Before reading further: **don't use this project against unauthorized
infrastructure.** See [SECURITY.md](./SECURITY.md). PRs that exist to make
unauthorized scanning easier (stripping built-in protections, hiding the
custom User-Agent, defeating audit logging, etc.) will not be merged.

## Quick start

```bash
git clone https://github.com/iksnerd/hopper-recon
cd hopper-recon

# Optional: drop in a GeoLite2 mmdb so the geo-globe renders
mkdir -p ~/.config/hopper-recon
curl -L https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb \
     -o ~/.config/hopper-recon/GeoLite2-Country.mmdb

# Bring up the stack (engine + web + Litestream sidecars)
docker compose up -d --build

# Web at http://localhost:9120
# Engine REST + MCP at http://127.0.0.1:9119 (loopback only)
```

For tighter web iteration:

```bash
docker compose up -d engine
cd web && npm install && npm run dev
```

## Pre-commit checks

These run in CI on every PR. Run them locally before pushing — failing CI
slows everyone down.

**Engine (`engine/`)**

```bash
gofmt -w .
go vet ./...
go build ./...
go mod tidy            # after import changes
docker compose build engine    # after any Go change
```

**Web (`web/`)**

```bash
npx tsc --noEmit       # must pass clean — no any, no @ts-ignore
npm run lint           # fix warnings, don't disable rules
npm test               # parser smoke tests
```

If you touched UI: also start the dev server and click through the affected
flows in a browser. Type-check + tests verify code correctness, not feature
correctness. Screenshots help reviewers a lot.

## Pull requests

- **One concern per PR.** A scope expansion (e.g. "while I was here, I also
  refactored …") makes review hard and bisect impossible. Land cleanups in
  separate PRs against `main`.
- **Commit messages: imperative, present tense, no period.** First line ≤72
  chars, captures the *why* (not just *what*). Body wraps at 80. Example:
  `Add per-target cooldown to /scan to defang mash-the-button automation`.
- **Update the relevant docs in the same PR.** New env var? Add to
  `.env.example` and the README. New tool? Follow the eight-step "Adding a
  tool" checklist in `CLAUDE.md`. New protection? Update `SECURITY.md` and
  the README's "Built-in protections" table.
- **Tests where they buy something.** Pure parsing / formatting / config →
  yes, please. End-to-end recon-binary integration → no, the upstream
  binaries are the integration test.

We don't currently require a CLA. We may add one before v1.0; if so, past
contributors will be contacted before any relicense.

## Adding a recon tool

See the eight-step checklist in [`CLAUDE.md`](./CLAUDE.md) under "Adding a
tool". Two non-obvious things:

1. The tool must produce useful output for an **unconfigured** first-time
   user. Tools that *require* an API key (PDCP, Shodan, Censys, FOFA, etc.)
   to function are rejected — that's the v0.2 admission rule. API keys are
   fine as **optional enrichment**, never as a hard prerequisite.
2. The engine's `Policy.Check` gate runs on **every** tool, active or
   passive — both the dashboard's `/scan` and the MCP path. Don't try to
   route around it. If a passive tool is producing too many false-positive
   blocks, fix the policy, not the tool.

## Reporting bugs

Use the **Bug report** issue template. Include:

- Hopper Recon version (`/api/config` returns `version`) or commit SHA
- How you're running it (compose, k8s, dev `npm run dev`, …)
- What you did, what you expected, what happened
- Engine logs (`docker compose logs engine --tail 200`) and web console
  output where relevant

Security-relevant bugs go to **iksnerd@users.noreply.github.com**, not GitHub issues. See
[SECURITY.md](./SECURITY.md).

## Code of Conduct

By participating, you agree to abide by the
[Code of Conduct](./CODE_OF_CONDUCT.md).

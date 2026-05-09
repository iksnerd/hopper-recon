# Security policy — Hopper Recon

## Authorized-use posture

Hopper Recon sends DNS queries, TLS handshakes, and HTTP requests to whatever
target you supply. **You are the operator.** Run only against assets you own
or have written authorization to test.

The maintainers do not consent to use of this software against unauthorized
third-party infrastructure. We will not provide debugging help, troubleshoot
deployment, or accept feature requests that are clearly oriented at attacking
targets the requester does not control.

### Outbound footprint per scan

A single full scan of one target sends roughly:

- ~5 DNS queries (A, AAAA, CNAME, NS, MX, TXT, plus `_dmarc.<host>`)
- 1 TLS handshake (cert fetch via `tlsx`)
- 1 HTTP GET (probe via `httpx`, identified with the `hopper-recon/<version>` User-Agent at 50 req/s cap)
- 0 packets to the target from the passive tools (`subfinder`, `urlfinder`, `cdncheck`, `lookup_geoip`) — those query third-party OSINT services or read a bundled database

That is roughly equivalent to opening one browser tab.

### Built-in protections

The engine refuses active probes (`probe_http`, `fetch_tls_cert`) against
restricted suffixes by default — `*.gov`, `*.mil`, `*.gouv.fr`, `*.gov.uk`,
`*.go.jp`, `*.gc.ca`, `*.gov.au`. Override requires both
`HOPPER_OVERRIDE_BLOCKLIST=true` and a non-empty
`HOPPER_BLOCKLIST_OVERRIDE_REASON`, and the override reason is written to
`audit_log` for after-the-fact review.

The engine also enforces a 60-second per-(target, tool) cooldown (returning
HTTP 429 with `Retry-After`) and a per-request audit log capturing source
IP, User-Agent, tool, target, decision, and reason.

When `HOPPER_ALLOWED_DOMAINS` is set, the engine refuses targets outside the
list with HTTP 403. When unset, the dashboard shows a persistent banner
nudging the operator to set scope.

These protections live at the engine, not the web layer, so direct MCP
callers (Claude Code, Cline, stdio agents) hit the same gates as the
dashboard.

## Reporting a vulnerability

Email **iksnerd@users.noreply.github.com** with:

- A clear description of the issue
- Reproduction steps (or a proof-of-concept payload, if applicable)
- The Hopper Recon version (`/api/config` returns `version`) or commit SHA
- Your assessment of impact

Please do **not** open a public GitHub issue for unpatched vulnerabilities.

We aim to:

- Acknowledge receipt within **3 working days**
- Provide an initial assessment within **10 working days**
- Ship a fix or mitigation within **30 days** for high-severity issues, or
  agree on a longer disclosure timeline if the fix requires deeper changes

We do not currently run a paid bug bounty programme. We do credit reporters
in release notes by name (or pseudonym, your choice) once a fix has shipped,
unless you ask us not to.

## Out of scope

The following are intentionally out of scope for the security disclosure
programme:

- **The recon tools themselves** misbehaving against a target you supplied —
  that is the operator's responsibility, not a Hopper Recon bug.
- **Scans of third-party infrastructure you don't own** — see the
  authorized-use posture above. We will not fix "feature" requests that
  enable easier scanning of unauthorized targets.
- **Self-DoS** by deliberately crafting pathological inputs or running in a
  resource-starved environment.
- **Vulnerabilities in upstream projectdiscovery binaries** (`subfinder`,
  `dnsx`, `tlsx`, `httpx`, `cdncheck`, `urlfinder`) — those should be
  reported directly to <https://github.com/projectdiscovery>. We will
  bump our pinned versions promptly when upstream ships a patch.

## Supported versions

Hopper Recon is pre-1.0. The latest tagged release is the only supported
version. Security fixes are not back-ported to earlier tags.

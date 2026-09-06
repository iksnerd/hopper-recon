---
name: release
description: Cut a hopper-recon release — decide the semver bump, sync the version strings in engine/tools.go and web/package.json, run the engine and web checks, write the CHANGELOG entry, commit, annotated-tag, push, and rebuild the Docker images so the baked-in version matches the tag. Use when asked to release, cut a version, tag a version, bump the version, or ship a new version of hopper-recon.
---

# hopper-recon release skill

Cut a new release: bump versions, commit, tag, push, and rebuild Docker images.

## How versioning works

- `engine/tools.go` — `var Version = "vX.Y.Z"` and the ldflags comment above it
- `web/package.json` — `"version": "X.Y.Z"`

Both must match. The git tag is the single source of truth for releases.

## Determine the next version

Look at the staged/uncommitted changes and the most recent tag to decide the bump:

```bash
git describe --tags --abbrev=0          # current latest tag
git log --oneline $(git describe --tags --abbrev=0)..HEAD  # commits since last tag
```

Bump rules (semver, all releases are v0.x.y for now):
- **patch** (Z): bug fixes, docs, refactors, test additions, style tweaks
- **minor** (Y): new user-visible features, new scan tools, new UI pages
- **major** (X): breaking API change, major architecture shift

Propose the bump to the user and confirm before proceeding if ambiguous.

## Steps

### 1. Confirm clean or staged state

```bash
git status --short
git diff --stat
```

If there are unstaged changes the user hasn't mentioned, ask whether to include them.

### 2. Determine the new version (see above). Ask if ambiguous.

### 3. Bump versions in both places

In `engine/tools.go`:
```go
// time with `-ldflags "-X main.Version=vX.Y.Z"` for tagged releases.
var Version = "vX.Y.Z"
```

In `web/package.json`:
```json
"version": "X.Y.Z",
```

Use sed rather than Edit (package.json may not have been read):
```bash
sed -i '' 's/"version": "OLD"/"version": "NEW"/' web/package.json
```

### 4. Run checks

```bash
cd engine && go build ./... && go test ./...
cd ../web && npx tsc --noEmit && npm run lint
```

Fix any failures before continuing.

### 5. Stage all changed files (source only — no screenshots, no build artefacts)

```bash
cd ..  # back to repo root
git add engine/ web/src/ web/package.json
git status --short  # verify
```

### 6. Commit

```
chore: vX.Y.Z — <one-line summary of what changed>

Engine:
- <bullet per engine change>

Web:
- <bullet per web change>
```

### 7. Tag (annotated)

```bash
git tag -a vX.Y.Z -m "vX.Y.Z — <same one-liner>"
```

### 8. Push branch and tag

```bash
git push origin main --tags
```

Pre-existing tags rejected as "already exists" are harmless — only the new tag matters.

### 9. Rebuild Docker images

The engine version string is baked at compile time; the web version appears in the sidebar footer. Both need a rebuild after a version bump.

```bash
docker compose build engine web
docker compose up -d --force-recreate engine web
```

**Build performance notes (important):**
- First build after a `go install` layer change is slow (~5–10 min) — Go modules are downloaded and cached via BuildKit cache mounts in `engine/Dockerfile`.
- Subsequent builds are fast (~1 min) — module cache and build artifacts are reused.
- The web build context should be small (< 5 MB) because `web/.dockerignore` excludes `node_modules` and `.next`. If a build is sending >100 MB of context, check that `.dockerignore` exists in `web/`.
- Both Dockerfiles use `# syntax=docker/dockerfile:1.7` and `--mount=type=cache` — DOCKER_BUILDKIT=1 is the default in Docker Desktop but set it explicitly if builds are ignoring caches.

### 10. Confirm

Show the tag URL:
```
https://github.com/iksnerd/hopper-recon/releases/tag/vX.Y.Z
```

And verify the running containers picked up the new version:
```bash
curl -s http://localhost:9119/config | grep version
```

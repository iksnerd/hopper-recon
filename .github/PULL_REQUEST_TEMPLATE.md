<!--
Thanks for the PR. A few quick orientation notes:
- One concern per PR. Cleanups land separately.
- Commit messages: imperative, present tense, no period; first line ≤72 chars; explain *why*.
- Update docs in the same PR (.env.example, README, SECURITY.md, CLAUDE.md as relevant).
- Run pre-commit checks locally before pushing (see CONTRIBUTING.md).
-->

## What

<!-- One-paragraph summary. What changed and why. -->

## Why

<!-- The motivating problem. Link the issue if there is one. -->

## How

<!-- Anything load-bearing in the implementation. Trade-offs. Things you considered and rejected. -->

## Test plan

- [ ] `gofmt -l .` clean (engine)
- [ ] `go vet ./...` clean (engine)
- [ ] `go build ./...` succeeds (engine)
- [ ] `npx tsc --noEmit` clean (web)
- [ ] `npm run lint` clean (web)
- [ ] `npm test` passes (web)
- [ ] Manually verified the affected flow in the dashboard / on the engine

<!-- Screenshots or short clips for UI changes are very helpful. -->

## Authorized-use confirmation

- [ ] This change does not weaken the built-in protections (blocklist / cooldown / audit log / scope filter / loopback bind / X-Hopper-Recon header / custom UA).
- [ ] This change does not introduce a tool that requires an API key as a hard prerequisite.

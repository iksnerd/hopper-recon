import { describe, it, expect } from "vitest"
import { readFileSync } from "node:fs"
import { join } from "node:path"

// The mock engine (mocks/engine.mjs) has to grow a case for every scan tool,
// otherwise `npm run dev:mock` silently returns [] for the new one and the new
// panel looks broken for reasons that have nothing to do with the panel.
//
// Reading both files as text rather than importing them keeps this a pure
// drift check: mocks/ stays outside the bundle and VALID_TOOLS stays a private
// const in the route, neither has to be reshaped to be testable.

const repoWeb = join(__dirname, "..", "..", "..")

function arrayLiteral(source: string, name: string): string[] {
  const m = new RegExp(`(?:const|let)\\s+${name}\\s*=\\s*\\[([^\\]]*)\\]`).exec(source)
  if (!m) throw new Error(`could not find ${name} array literal`)
  return [...m[1].matchAll(/["']([^"']+)["']/g)].map((x) => x[1])
}

describe("mock engine stays in sync with the real tool list", () => {
  const routeSrc = readFileSync(join(repoWeb, "src/app/api/scan/route.ts"), "utf8")
  const mockSrc = readFileSync(join(repoWeb, "mocks/engine.mjs"), "utf8")

  const validTools = arrayLiteral(routeSrc, "VALID_TOOLS")
  const mockTools = arrayLiteral(mockSrc, "TOOLS")

  it("accepts every tool the scan route accepts", () => {
    expect([...mockTools].sort()).toEqual([...validTools].sort())
  })

  it("synthesises a result for every tool", () => {
    // Each tool needs its own `case "<tool>":` in synthesise(), or an unknown
    // target falls through to the default [] and the panel renders empty.
    const missing = validTools.filter((t) => !mockSrc.includes(`case "${t}":`))
    expect(missing).toEqual([])
  })
})

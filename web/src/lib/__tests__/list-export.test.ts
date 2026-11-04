import { afterEach, describe, it, expect, vi } from "vitest"
import { filterRows, rowsToText, exportFileName, downloadText, REVOKE_DELAY_MS } from "../list-export"

const rows = ["b.example.com", "a.example.com", "api.other.test", "C.Example.com"].map((text) => ({ text }))

describe("filterRows", () => {
  it("keeps every row for a blank or whitespace query", () => {
    expect(filterRows(rows, "")).toBe(rows)
    expect(filterRows(rows, "   ")).toBe(rows)
  })
  it("matches case-insensitively on a trimmed substring", () => {
    expect(filterRows(rows, " EXAMPLE ").map((r) => r.text)).toEqual(["b.example.com", "a.example.com", "C.Example.com"])
  })
  it("returns nothing when no row matches", () => {
    expect(filterRows(rows, "zzz")).toEqual([])
  })
})

describe("rowsToText", () => {
  it("writes one entry per line in input order with a trailing newline", () => {
    expect(rowsToText(rows)).toBe("b.example.com\na.example.com\napi.other.test\nC.Example.com\n")
  })
  it("exports only the filtered set", () => {
    expect(rowsToText(filterRows(rows, "other"))).toBe("api.other.test\n")
  })
  it("is the empty string for an empty list", () => {
    expect(rowsToText([])).toBe("")
    expect(rowsToText(filterRows(rows, "zzz"))).toBe("")
  })
  it("does not truncate a 25k-row list", () => {
    const big = Array.from({ length: 25_000 }, (_, i) => ({ text: `h${i}.big.test` }))
    const out = rowsToText(big)
    const lines = out.split("\n")
    expect(lines).toHaveLength(25_001) // 25k entries + the empty string after the final newline
    expect(lines[0]).toBe("h0.big.test")
    expect(lines[24_999]).toBe("h24999.big.test")
    expect(out.endsWith("\n")).toBe(true)
  })
  it("exports every match of a filter that matches beyond the 200-row render cap", () => {
    const big = Array.from({ length: 5_000 }, (_, i) => ({ text: `${i % 2 ? "x" : "y"}${i}.big.test` }))
    expect(rowsToText(filterRows(big, "x")).split("\n").filter(Boolean)).toHaveLength(2_500)
  })
})

describe("exportFileName", () => {
  it("derives a plain name", () => {
    expect(exportFileName("subdomains-example.com")).toBe("subdomains-example.com.txt")
  })
  it("sanitises separators, spaces, and traversal", () => {
    expect(exportFileName("../../etc/passwd")).toBe("etc-passwd.txt")
    expect(exportFileName("Live Hosts: a/b\\c")).toBe("live-hosts-a-b-c.txt")
  })
  it("strips leading dots and dashes", () => {
    expect(exportFileName(".hidden")).toBe("hidden.txt")
    expect(exportFileName("--rf")).toBe("rf.txt")
  })
  it("falls back when nothing survives", () => {
    expect(exportFileName("///")).toBe("export.txt")
    expect(exportFileName("")).toBe("export.txt")
  })
  it("caps the length", () => {
    expect(exportFileName("a".repeat(500)).length).toBeLessThanOrEqual(84)
  })
  it("honours the extension", () => {
    expect(exportFileName("x", "csv")).toBe("x.csv")
  })
})

describe("downloadText", () => {
  afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks() })

  function stubDom(click: () => void) {
    const a = { href: "", download: "", rel: "", click, remove: vi.fn() }
    vi.stubGlobal("document", { createElement: vi.fn(() => a), body: { appendChild: vi.fn() } })
    const revoke = vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {})
    vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:fake")
    return { a, revoke }
  }

  it("keeps the object URL alive until the browser has started the download", () => {
    vi.useFakeTimers()
    const { a, revoke } = stubDom(() => {})
    downloadText("hosts.txt", "a\nb\n")
    expect(a.download).toBe("hosts.txt")
    expect(a.href).toBe("blob:fake")
    expect(revoke).not.toHaveBeenCalled()
    vi.advanceTimersByTime(REVOKE_DELAY_MS - 1)
    expect(revoke).not.toHaveBeenCalled()
    vi.advanceTimersByTime(1)
    expect(revoke).toHaveBeenCalledWith("blob:fake")
  })

  it("revokes at once and rethrows when the click fails", () => {
    vi.useFakeTimers()
    const { revoke } = stubDom(() => { throw new Error("blocked") })
    expect(() => downloadText("hosts.txt", "a\n")).toThrow("blocked")
    expect(revoke).toHaveBeenCalledWith("blob:fake")
  })
})

import { describe, it, expect } from "vitest"
import { progressPercent } from "../recon-display"

describe("progressPercent", () => {
  it("is 0 before anything settles", () => expect(progressPercent(0, 8)).toBe(0))
  it("rounds to whole percent", () => {
    expect(progressPercent(4, 8)).toBe(50)
    expect(progressPercent(1, 3)).toBe(33)
  })
  it("reaches 100 when every tool settled", () => expect(progressPercent(8, 8)).toBe(100))
  it("clamps overshoot and rejects nonsense", () => {
    expect(progressPercent(9, 8)).toBe(100)
    expect(progressPercent(-1, 8)).toBe(0)
    expect(progressPercent(3, 0)).toBe(0)
    expect(progressPercent(Number.NaN, 8)).toBe(0)
  })
})

// Shared recharts styling. Hex values mirror the CSS tokens in globals.css
// because recharts' inline-style API does not resolve CSS variables.

export const TOOLTIP_STYLE = {
  background: "#111111",          // --card
  border: "1px solid #1f1f1f",    // --border
  borderRadius: 0,
  fontFamily: "var(--font-geist-mono)",
  fontSize: 11,
  color: "#d4d4d4",               // --foreground
} as const

export const CHART_FILLS = [
  "#f0f0f0", // --primary       (chart-1)
  "#888888", // --muted-foreground-2 (chart-2)
  "#555555", // --muted-foreground   (chart-3)
  "#333333", // --muted-foreground-3 (chart-4)
  "#222222", // chart-5
] as const

export const CHART_TICK = {
  fontSize: 11,
  fill: "#555555",
  fontFamily: "var(--font-geist-mono)",
} as const

export const CHART_TICK_SM = {
  fontSize: 10,
  fill: "#555555",
  fontFamily: "var(--font-geist-mono)",
} as const

export const CHART_CURSOR = { fill: "#1a1a1a" } as const

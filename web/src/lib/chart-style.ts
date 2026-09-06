// Shared recharts styling.
//
// These reference the CSS custom properties in globals.css rather than baking
// in hex values, so charts follow the active theme. `var()` resolves in both
// places recharts puts these: React inline styles (tooltip `contentStyle`) and
// SVG presentation attributes (`fill` on Cell, `tick` on an axis). An earlier
// version hardcoded dark-theme hexes on the assumption that recharts could not
// resolve variables — it can, and the hardcoded palette rendered the bars
// invisible in light mode (#f0f0f0 on the light card is 1.08:1).

export const TOOLTIP_STYLE = {
  background: "var(--card)",
  border: "1px solid var(--border)",
  borderRadius: 0,
  fontFamily: "var(--font-geist-mono)",
  fontSize: 11,
  color: "var(--foreground)",
} as const

/**
 * Categorical bar fills, in descending prominence.
 *
 * Cycle these with `i % CHART_FILLS.length` — never clamp with `Math.min`,
 * which collapses every series past the last index onto one colour. The ramp
 * is tuned in globals.css so every step clears 3:1 against `--card` in both
 * themes, meaning a repeated colour is still readable but a bar is never
 * invisible. Fill carries no meaning in these charts (each bar is labelled on
 * the axis), so repetition across a long series is fine.
 */
export const CHART_FILLS = [
  "var(--chart-1)",
  "var(--chart-2)",
  "var(--chart-3)",
  "var(--chart-4)",
  "var(--chart-5)",
] as const

/** Pick a fill by series index, cycling rather than clamping. */
export function chartFill(i: number): string {
  return CHART_FILLS[i % CHART_FILLS.length]
}

export const CHART_TICK = {
  fontSize: 11,
  fill: "var(--muted-foreground-3)",
  fontFamily: "var(--font-geist-mono)",
} as const

export const CHART_TICK_SM = {
  fontSize: 10,
  fill: "var(--muted-foreground-3)",
  fontFamily: "var(--font-geist-mono)",
} as const

export const CHART_CURSOR = { fill: "var(--card-hover)" } as const

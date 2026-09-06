// Shared display utilities for cert age and HTTP status colouring.
// Three pages (dashboard, history, history/[domain]) use the same thresholds;
// keeping them here prevents threshold drift across copies.

export function certDaysCls(days: number): string {
  if (days < 14) return "text-destructive"
  if (days < 30) return "text-muted-foreground-2"
  return "text-terminal-green"
}

export function certDaysLabel(days: number): { label: string; cls: string } {
  const label = days < 0 ? `expired ${-days}d ago` : `${days}d`
  return { label, cls: certDaysCls(days) }
}

/** Same as `certDaysLabel`, but the non-expired case reads "Nd remaining" — for the validity-bar caption rather than a compact stat chip. */
export function certValidityLabel(days: number): { label: string; cls: string } {
  if (days < 0) return certDaysLabel(days)
  return { label: `${days}d remaining`, cls: certDaysCls(days) }
}

export function httpStatusCls(code: number): string {
  if (code < 300) return "text-terminal-green"
  if (code < 400) return "text-muted-foreground-2"
  return "text-destructive"
}

export function httpStatusBracket(code: number): { label: string; cls: string } {
  return { label: `[${code}]`, cls: httpStatusCls(code) }
}

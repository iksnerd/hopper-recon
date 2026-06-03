// Shared display utilities for cert age and HTTP status colouring.
// Three pages (dashboard, history, history/[domain]) use the same thresholds;
// keeping them here prevents threshold drift across copies.

export function certDaysCls(days: number): string {
  if (days < 14) return "text-destructive"
  if (days < 30) return "text-muted-foreground-2"
  return "text-terminal-green"
}

export function certDaysLabel(days: number): { label: string; cls: string } {
  return { label: `${days}d`, cls: certDaysCls(days) }
}

export function httpStatusCls(code: number): string {
  if (code < 300) return "text-terminal-green"
  if (code < 400) return "text-muted-foreground-2"
  return "text-destructive"
}

export function httpStatusBracket(code: number): { label: string; cls: string } {
  return { label: `[${code}]`, cls: httpStatusCls(code) }
}

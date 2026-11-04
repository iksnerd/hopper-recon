// Pure helpers behind HostList's "copy all" / "download .txt". Kept out of the
// component so the one rule that matters — export every filtered match, not the
// rendered page — is unit-tested rather than implied by a React closure.

export interface ExportRow {
  text: string
}

/** Case-insensitive substring filter on `text`. A blank query keeps every row. */
export function filterRows<T extends ExportRow>(rows: readonly T[], query: string): readonly T[] {
  const q = query.trim().toLowerCase()
  if (!q) return rows
  return rows.filter((r) => r.text.toLowerCase().includes(q))
}

/** One entry per line, in input order, newline-terminated. An empty list is the empty string (not a lone "\n"). */
export function rowsToText(rows: readonly ExportRow[]): string {
  if (rows.length === 0) return ""
  // Joins the whole array: no slice, no cap.
  return rows.map((r) => r.text).join("\n") + "\n"
}

/**
 * `<label>.<ext>` safe on every filesystem: lowercased, anything outside
 * [a-z0-9._-] collapsed to "-", leading dots/dashes stripped (no hidden files,
 * no "-rf" lookalikes), length-capped. Falls back to "export" when nothing is left.
 */
export function exportFileName(label: string, ext = "txt"): string {
  const base = label
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/\.{2,}/g, ".")
    .replace(/-{2,}/g, "-")
    .replace(/^[.-]+/, "")
    .slice(0, 80)
    .replace(/[.-]+$/, "")
  return `${base || "export"}.${ext}`
}

/** How long the object URL stays valid after the click. Revoking in the same tick can cancel a large download in Safari and Firefox. */
export const REVOKE_DELAY_MS = 10_000

/** Saves `text` as a file through a Blob + object URL, revoked a few seconds after the click so the browser has started reading it. */
export function downloadText(filename: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }))
  try {
    const a = document.createElement("a")
    a.href = url
    a.download = filename
    a.rel = "noopener"
    document.body.appendChild(a)
    a.click()
    a.remove()
  } catch (err) {
    URL.revokeObjectURL(url) // nothing will read it
    throw err
  }
  setTimeout(() => URL.revokeObjectURL(url), REVOKE_DELAY_MS)
}

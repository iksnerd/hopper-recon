/**
 * Subtle "via toolname ↗" caption for the right-side action slot of a Panel.
 * Used on each tab's primary result panel so users can jump from a finding
 * straight to the upstream binary's source.
 */
export function ToolSourceLink({ name, url }: { name: string; url: string }) {
  return (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      title={`source: ${url}`}
      className="inline-flex items-baseline gap-1 text-micro tracking-wider uppercase text-muted-foreground-3 transition-colors hover:text-terminal-green"
    >
      <span>via {name}</span>
      <span aria-hidden>↗</span>
    </a>
  )
}

---
name: frontend-design
description: Cyberpunk terminal aesthetic for hopper-recon. Use when building UI components, pages, or styling. Enforces monospace-only fonts, dark achromatic palette accented with terminal phosphor green, and Palantir-inspired card/header hierarchy. Applies to all frontend work in this security recon SaaS.
---

# Frontend Design System — hopper-recon

Apply these guidelines for all UI work. This is a hacker tool — the UI must feel like a terminal first, an inspector dashboard second. Visual reference: Palantir Foundry/Gotham (information density, header strips, accent rails, action slots) — but executed in a phosphor-green terminal palette, not Palantir blue.

Use shadcn primitives as the foundation. Two recon-specific composables wrap them:
- `Panel` (`components/recon/panel.tsx`) — single-label shorthand
- `ReconCard` + `ReconCardHeader/HeaderText/Title/Action/Content` (`components/recon/recon-card.tsx`) — composable when you need a count, action button, or extra slot

Both render a distinct header strip with a green left rail and a separator border below the header — that's the load-bearing pattern, not a stylistic flourish. Don't ship cards without it.

## Typography

**Every glyph is monospace.** No exceptions.

Layout is already configured with `Geist_Mono` as `--font-geist-mono`. Tailwind tokens `--font-sans`, `--font-mono`, `--font-heading` all alias to it.

Role classes (defined in `globals.css`):

| Class | Use | Notes |
|-------|-----|-------|
| `text-micro` | section eyebrow, label, status pill | 11px, tracking 0.12em |
| `text-data` | IPs, IDs, ports, hashes | 13px, tabular-nums |
| `text-body` | default body / table cell | 14px |
| `text-emphasis` | input value, large prompt | 16px |
| `text-metric` | summary cell numbers (e.g. "63d", "[200]") | 30px, bold, tabular-nums |

**Card titles** are `text-body uppercase tracking-widest font-bold` — the title sits in the header strip, big enough to be the room's signpost. Section eyebrow `//` rides next to it in `text-muted-foreground-3`.

**NEVER use**: Geist Sans, Inter, Roboto, system-ui, or any variable font without `_Mono` suffix.

## Color Palette

Dark achromatic surfaces + brighter foreground tiers + two semantic accents (terminal-green, destructive-red). All tokens are OKLCH-defined in `globals.css`.

```
Surface tiers (oklch):
  --background        0.06   #080808   page bg
  --card-inset        0.08             panels-on-panels, code blocks
  --card              0.10             cards / panels
  --card-hover        0.14             hover surface
  --secondary         0.18             gap fill behind grid lines

Foreground tiers:
  --muted-foreground-3  0.70           dim but visible (timestamps, eyebrow //)
  --muted-foreground    0.80           label / icon
  --muted-foreground-2  0.85           readable secondary
  --foreground          0.92           body / data
  --primary             0.96           extra-bright (rare)

Borders:
  --border              0.22           visible — every card has one

Semantic accents:
  --terminal-green      oklch(0.85 0.19 145)   accent / active / OK
  --terminal-green-dim  oklch(0.55 0.10 145)   muted variant
  --destructive         oklch(0.52 0.14 27)    errors / dangerous state
```

### Where green goes (and where it doesn't)

Terminal green is **a signal, not a palette**. It's the only chromatic color in normal use; if you reach for it on chrome, you've gone too far. Use it for:

- `>_` prompt sigils (input prefixes, recent-target tile, sidebar nav inactive prompt)
- Cursor blink during running/scanning state
- Active tab underline + active tab text
- Active sidebar item (text + glyph + bottom dot)
- ReconCard left accent rail (`before:bg-terminal-green/70`)
- Success status: HTTP 2xx, cert > 30d, SPF/DMARC/DKIM ✓
- Status pills: `[DONE n/n]`, `[SCANNING n/n]`
- Logo dot, footer pulse

**Don't**: paint card backgrounds, large headlines, body text, table rows, charts, or borders green. Don't introduce other hues — no emerald, amber, blue, sky, violet, pink, purple. The two-color system (green for live/affordance, red for danger) is the whole vocabulary.

## Backgrounds

```css
.grid-bg {
  background-color: var(--background);
  background-image:
    linear-gradient(oklch(0.15 0 0) 1px, transparent 1px),
    linear-gradient(90deg, oklch(0.15 0 0) 1px, transparent 1px);
  background-size: 40px 40px;
}

.scanlines::after {
  content: '';
  position: fixed;
  inset: 0;
  background: repeating-linear-gradient(
    transparent, transparent 2px,
    rgba(0,0,0,0.06) 2px, rgba(0,0,0,0.06) 4px
  );
  pointer-events: none;
  z-index: 9999;
}
```

**NEVER use**: mesh gradients, glassmorphism, blob shapes, radial spotlight effects.

## Card pattern (load-bearing)

The Palantir-style header strip is the chassis for every information block. Use `Panel` for a single label or `ReconCard` directly when you need full composition:

```tsx
import { Panel } from "@/components/recon/panel"

<Panel label="// SUBDOMAINS [12]">
  {/* content */}
</Panel>

// → renders:
//   <div border bg-card>
//     <div header  ← left rail, py-2, border-b>
//       // SUBDOMAINS              [12]
//     </div>
//     <div content  ← p-4>...</div>
//   </div>
```

```tsx
import { ReconCard, ReconCardHeader, ReconCardHeaderText, ReconCardTitle, ReconCardAction, ReconCardContent } from "@/components/recon/recon-card"

<ReconCard>
  <ReconCardHeader>
    <ReconCardHeaderText className="flex-row items-baseline gap-2">
      <span className="text-muted-foreground-3 font-bold tracking-widest" aria-hidden>{"//"}</span>
      <ReconCardTitle>TARGET</ReconCardTitle>
    </ReconCardHeaderText>
    <ReconCardAction>
      <Button>...</Button>
    </ReconCardAction>
  </ReconCardHeader>
  <ReconCardContent>...</ReconCardContent>
</ReconCard>
```

**`ReconCard` props**:
- `variant`: `"default"` (bg-card), `"inset"` (bg-card-inset, slightly darker), `"outline"` (transparent)
- `tone`: `"neutral"` (default border) or `"danger"` (subtle red border — use on findings/alerts when an issue exists)

**`Panel` props**: `variant`, `contentClassName` (override inner padding, e.g. `"p-3"` or `"p-0"`), `action` (extra header content beyond the auto-detected `[count]`).

`Panel` parses `// LABEL [N]` into title + count automatically — count rides in the action slot, not in the title. Don't manually inline counts in titles.

## Page shell

Use `PageHeader` from `components/recon/page-header.tsx` on every authenticated page — same chrome everywhere:

```tsx
<div className="min-h-screen font-mono text-foreground scanlines">
  <PageHeader
    segments={["DASHBOARD", scan?.target]}
    right={<ScanStatusPill .../>}  // or any short status chip
  />
  <div className="px-4 sm:px-8 lg:px-12 py-6 sm:py-8 space-y-6">
    {/* cards */}
  </div>
</div>
```

`PageHeader` renders a sidebar toggle with a visible border + bg-card-inset (so it's clearly tappable on mobile and not an "icon ghost"), then a breadcrumb that starts with `HOPPER-RECON / ...`, then an optional right slot. Don't roll your own page header.

## Status pills, indicators, prompts

Bracket notation in monospace. Color follows the palette rules above.

```tsx
// status pill
<span className="font-mono text-micro tracking-widest uppercase text-terminal-green border border-terminal-green/40 bg-card-inset px-2 py-1">
  [DONE 5/5]
</span>

// idle / dim
<span className="font-mono text-micro tracking-widest uppercase text-muted-foreground-3 border border-border bg-card-inset px-2 py-1">
  [IDLE]
</span>

// inline status
<span className="text-terminal-green text-micro">[200]</span>
<span className="text-destructive text-micro">[503]</span>

// running cursor
<span className="cursor-blink text-terminal-green">█</span>

// prompt sigil — only for affordances (inputs, buttons, links)
<span className="text-terminal-green font-bold shrink-0">&gt;_</span>
```

## Tables — dense, collapsed borders

```tsx
<Table className="text-body">
  <TableBody>
    <TableRow className="border-b border-card-hover hover:bg-transparent">
      <TableCell className="p-0 py-1.5 pr-4 text-muted-foreground tracking-widest uppercase whitespace-nowrap">SERVER</TableCell>
      <TableCell className="p-0 py-1.5 text-foreground">cloudflare</TableCell>
    </TableRow>
  </TableBody>
</Table>
```

Labels are `text-muted-foreground tracking-widest uppercase`; values are `text-foreground`. Right-align values when the label column has a fixed width and you want the eye to scan the data column.

## Tabs

```tsx
<TabsList className="bg-card border border-border rounded-none w-full justify-start h-auto p-0 gap-0 overflow-x-auto">
  {TOOLS.map(({ id, label }) => (
    <TabsTrigger
      key={id}
      value={id}
      className="font-mono text-body text-muted-foreground rounded-none border-r border-border last:border-r-0 px-4 py-2.5
                 data-[state=active]:text-terminal-green data-[state=active]:bg-card-hover data-[state=active]:font-bold
                 hover:text-foreground hover:bg-card-hover transition-colors duration-100 gap-2 whitespace-nowrap relative
                 data-[state=active]:after:absolute data-[state=active]:after:left-0 data-[state=active]:after:right-0
                 data-[state=active]:after:bottom-0 data-[state=active]:after:h-[2px]
                 data-[state=active]:after:bg-terminal-green"
    >
      <span className="tracking-wider uppercase">{label}</span>
    </TabsTrigger>
  ))}
</TabsList>
```

Whole-card tabs (with border + bg-card) → not just an underline strip. The 2px green bar at the bottom of the active tab is the affordance cue.

## Charts (Recharts) — grayscale only

```tsx
// chart-style.ts
export const CHART_FILLS = ["#f0f0f0", "#888888", "#444444", "#2a2a2a", "#1a1a1a"]
// stroke: oklch(0.42 0 0); grid: var(--border); tick text: var(--muted-foreground)
```

Don't introduce colored series — including green. Charts are pure data; the chrome around them carries the accents.

## Motion

```css
@keyframes blink { 0%,100% { opacity: 1 } 50% { opacity: 0 } }
.cursor-blink { animation: blink 1s step-end infinite; }

@keyframes reveal { from { opacity: 0; transform: translateY(4px) } to { opacity: 1; transform: none } }
.reveal { animation: reveal 0.15s linear forwards; }
```

- Timing: `linear` or `steps()` only — no `ease-in-out`, no spring
- Duration: ≤150ms for interactions, ≤300ms for reveals
- Hover: background shift only (`bg-card-hover`), never scale or color rotation

**NEVER use**: framer-motion bounces, scale transforms, color transitions on hover beyond the bg-shift.

## Sidebar / navigation

- Sidebar text: `text-muted-foreground-2` (readable, not muted-3)
- Active item: `data-[active=true]:text-terminal-green data-[active=true]:bg-card-hover data-[active=true]:font-bold`, with the prompt glyph swapped from `>_` (inactive) to `▶` (active, in green)
- Header logo dot: `<span className="size-2 bg-terminal-green" />` next to the wordmark
- Footer pulse: small green dot to indicate live process

The sidebar trigger is a real bordered button on every page (`PageHeader`'s `SidebarToggleButton`), not a free-floating icon — keeps it visible on mobile.

## Anti-Patterns

| Forbidden | Use instead |
|-----------|-------------|
| `rounded-lg`, `rounded-xl` | `rounded-none` (token `--radius: 0`) |
| `shadow-md`, `shadow-xl` | nothing |
| Card with no header strip | `Panel` or `ReconCard` (header is mandatory) |
| `bg-emerald-500`, `text-amber-400`, `text-blue-*` | `text-terminal-green` (active/OK) or `text-destructive` (errors) — those are the only hues |
| Painting card bg / borders / charts green | green is for prompts, active states, status indicators only |
| Geist Sans, Inter, Roboto | Geist Mono |
| Colorful badge variants | `[STATUS]` bracket text in semantic color |
| Multi-color Recharts | Grayscale fills array |
| `ease-in-out` spring | `linear`, `steps()` |
| Free-floating sidebar trigger icon | `PageHeader` w/ bordered toggle button |
| Tiny eyebrow as the only header | distinct header strip with `text-body` uppercase title + green rail |

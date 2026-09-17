# Design — AgentWazuh SOC Assistant

A locked design system for this app. Every page redesign reads this file before
emitting code. Do not regenerate per page — extend or amend this file when the
system needs to grow.

Scope: `designed-as-app`. All pages are app surfaces (an operations console), not
marketing. Reference idioms: Google Antigravity (editor + right-side Agent Panel)
and OpenAI Codex app (collapsible left rail, work area, dockable right panel,
thin status bar, command palette, mono for data).

## Genre

modern-minimal — developer-tool. Restraint over decoration. No glows, no
gradients-as-decoration, no ambient animation, no cyber ornament.

## Macrostructure family

- **App pages** (dashboard, network-map, device-inventory, drilldown): **Workbench**
  — thin persistent app bar → collapsible left rail (nav) → fluid work area →
  dockable right panel (tabs: *Advisor* / *Evidence*, or page-local equivalent).
  Variation knobs: work area may be a feed, a canvas, or a table; the right panel
  may hold chat, detail, or a form.
- **Auth page** (login): **Gateway** — single centred column, one primary action,
  no enrichment.

Pages within a family share the family shape; they vary only in component
archetypes.

## Theme

Dark, near-neutral (slate, low chroma), single accent. Anchored on the Codex dark
surface (`#181818`-class neutrality) with the project's blue-cyan accent.

- `--paper`      oklch(0.180 0.006 260)  · app background
- `--paper-2`    oklch(0.215 0.007 260)  · rails, bars, panels
- `--paper-3`    oklch(0.255 0.008 260)  · raised: cards, inputs
- `--paper-sunk` oklch(0.145 0.006 260)  · sunken: code, wells, tables
- `--rule`       oklch(0.300 0.010 260)  · borders
- `--rule-soft`  oklch(0.265 0.008 260)
- `--ink`        oklch(0.955 0.003 260)  · primary text
- `--ink-2`      oklch(0.720 0.010 260)  · secondary text
- `--ink-3`      oklch(0.560 0.010 260)  · tertiary / placeholder
- `--accent`     oklch(0.720 0.140 230)  · ≈ #3aa0ff, Codex-blue family
- `--focus`      oklch(0.780 0.140 230)

Semantic (severity — never decorative):

- `--ok`       oklch(0.760 0.140 155)   · low / success / online
- `--info`     oklch(0.720 0.140 230)   · informational
- `--medium`   oklch(0.800 0.140 85)    · medium
- `--high`     oklch(0.720 0.170 50)    · high
- `--critical` oklch(0.660 0.200 25)    · critical / offline / error

Rule: the accent appears in ≤ 5 % of any viewport. Severity colours are data, not
decoration, and may exceed that budget when the data demands it.

Light theme is **not** in scope for this pass. Tokens are declared under `:root`
only; a future `[data-theme="light"]` block may extend the same names.

## Typography

- Display / UI: `Inter`, weights 400 / 500 / 600 / 700
- Body: `Inter`, weight 400
- Mono: `JetBrains Mono`, weight 400 / 500 — **required** for IPs, hostnames,
  rule IDs, timestamps, log lines, XML/JSON, payloads
- Display tracking: `-0.02em` on sizes ≥ `--text-lg`
- Type scale anchor: `--text-md` = 0.9375rem (15px) base UI size

Fonts load from Google Fonts on every page, with `system-ui` / `ui-monospace`
fallbacks so the UI degrades cleanly offline.

## Spacing

4-point named scale, defined in `tokens.css`. Pages must use named tokens
(`var(--space-md)`), never raw values.

## Radius

Small and restrained (Codex-like): `--radius-sm` 6px (controls), `--radius-md`
10px (cards/panels), `--radius-lg` 14px (modals), `--radius-pill` 999px (chips,
status pills).

## Motion

- Easings: `--ease-out` cubic-bezier(0.16, 1, 0.3, 1); `--ease-in-out`
  cubic-bezier(0.65, 0, 0.35, 1)
- Durations: `--dur-short` 140ms (hover/active), `--dur-med` 220ms (panels,
  drawers), `--dur-long` 320ms (modals, dock)
- Reveal pattern: fade only for content; fade + 4px slide for panels/drawers.
- Reduced-motion fallback: opacity-only, ≤ 150 ms, transforms disabled.

## Microinteractions stance

- Silent success. Never toasts, confetti, or celebratory animation.
- No box-shadow glows on hover. Hover = surface + border change only.
- Hover delay 0 ms; focus is immediate and always visible (2px `--focus` ring,
  2px offset). Keyboard focus is never removed.
- Loading uses skeletons or inline text, not bare spinners.
- Errors are inline, next to the affected control — not alerts.

## CTA voice

- Primary: solid `--accent` fill, `--radius-sm`, weight 600, no gradient, no glow.
- Secondary: transparent with `--rule` border; hover raises to `--paper-3`.
- Destructive: `--critical` text/border, transparent fill.
- Icon-only buttons are square with a tooltip + `aria-label`.

## Per-page allowances

- App pages MUST NOT use enrichment. Function carries the page.
- Auth page MAY use at most one restrained background treatment (a single flat
  surface + hairline grid, no blur orb animation).

## What pages MUST share

- The wordmark (shield mark + `AgentWazuh` + role subtitle).
- The accent colour and its placement.
- The Inter + JetBrains Mono pairing.
- The CTA voice (button shape, radius, padding rhythm).
- Section heading rhythm (icon + label, uppercase mono eyebrow for group labels).
- The app bar (40px) + rail + right dock skeleton.

## What pages MAY differ on

- Work-area archetype (feed / canvas / table / split form).
- Right-panel content (chat, evidence, device detail, confirm form).
- The tab set inside the right dock.

## Contract notes (must not break)

The front-end JS (`app.js`, `network_map.js`, `drilldown.js`,
`device_inventory.js`, `login.js`) is the behavioural source of truth. The
following class/id contracts are load-bearing and must survive any markup change:

- `.header-status .status-indicator` (+ `online|offline|warning`) and
  `#status-wazuh-ip` / `#status-host`
- `.settings-sidebar .nav-item`, `.settings-tab-content`, `.input-setting-control`
- `.btn-primary`, `.mode-btn.active`, `.chip-btn`, `.alert-card` (+ `level-*`,
  `.selected`), `.badge-level`, `.chat-bubble.system|user`
- `#history-sidebar` toggled with `.collapsed`
- All ids consumed by `getElementById` in the page's controller.

## Exports

### tokens.css

See `web/tokens.css` — the canonical file. Drop-in copy:

```css
:root {
  --paper: oklch(0.180 0.006 260);
  --paper-2: oklch(0.215 0.007 260);
  --paper-3: oklch(0.255 0.008 260);
  --paper-sunk: oklch(0.145 0.006 260);
  --rule: oklch(0.300 0.010 260);
  --rule-soft: oklch(0.265 0.008 260);
  --ink: oklch(0.955 0.003 260);
  --ink-2: oklch(0.720 0.010 260);
  --ink-3: oklch(0.560 0.010 260);
  --accent: oklch(0.720 0.140 230);
  --accent-ink: oklch(0.200 0.030 230);
  --focus: oklch(0.780 0.140 230);
  --ok: oklch(0.760 0.140 155);
  --info: oklch(0.720 0.140 230);
  --medium: oklch(0.800 0.140 85);
  --high: oklch(0.720 0.170 50);
  --critical: oklch(0.660 0.200 25);
  --font-ui: "Inter", system-ui, -apple-system, "Segoe UI", sans-serif;
  --font-mono: "JetBrains Mono", ui-monospace, "SFMono-Regular", monospace;
  --ease-out: cubic-bezier(0.16, 1, 0.3, 1);
  --dur-short: 140ms;
  --dur-med: 220ms;
  --dur-long: 320ms;
  --radius-sm: 6px;
  --radius-md: 10px;
  --radius-lg: 14px;
  --radius-pill: 999px;
}
```

### DTCG tokens.json

```json
{
  "color": {
    "paper":  { "$value": "oklch(0.180 0.006 260)", "$type": "color" },
    "ink":    { "$value": "oklch(0.955 0.003 260)", "$type": "color" },
    "accent": { "$value": "oklch(0.720 0.140 230)", "$type": "color" }
  },
  "font": {
    "ui":   { "$value": "Inter", "$type": "fontFamily" },
    "mono": { "$value": "JetBrains Mono", "$type": "fontFamily" }
  },
  "space": {
    "md": { "$value": "1.5rem", "$type": "dimension" }
  }
}
```

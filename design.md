# Design — TFPS

This visual system is derived from the supplied TFPS logo. The logo provides the slate-blue
and neutral-gray foundation; the brighter blue and cyan are functional web accents added for
focus and system-state communication. These tokens assume screens, from mobile devices to
desktop monitors.

## Brand character

TFPS should feel like quiet infrastructure: technical, watchful, candid, and dependable.
The visual metaphor is a clean network boundary, not a cybersecurity dashboard. Large type,
strong alignment, sparse color, and visible technical evidence do more work than decoration.

## Colour roles

Each entry is `background / foreground`. Ratios were measured with WCAG relative luminance.
All foreground pairs exceed 4.5:1 and may carry body text.

| role | light | dark | measured contrast |
|---|---|---|---:|
| primary / on-primary | `#36516D` / `#FFFFFF` | `#9EC7EF` / `#102B43` | 8.22:1 / 8.19:1 |
| primary-container / on-primary-container | `#D8E7F5` / `#172B3E` | `#294965` / `#DCECFF` | 11.48:1 / 7.82:1 |
| secondary / on-secondary | `#56606A` / `#FFFFFF` | `#BDC8D2` / `#24313C` | 6.41:1 / 7.82:1 |
| surface / on-surface | `#F5F7F9` / `#101820` | `#0C1722` / `#E7EEF4` | 16.66:1 / 15.44:1 |
| surface-variant / on-surface-variant | `#E1E7EC` / `#34495C` | `#253442` / `#D6E0E8` | 7.47:1 / 9.52:1 |
| error / on-error | `#A52828` / `#FFFFFF` | `#FFB4AB` / `#690005` | 7.16:1 / 7.72:1 |
| outline | `#9AA8B4` | `#718494` | use for edges, not text |
| scrim | `#071019` at 72% | `#071019` at 78% | text uses `#FFFFFF`; ≥ 8.4:1 over the composited result |

The supporting signal accent is `#62D8E8`. Use it only for a single active state, diagram
checkpoint, or short eyebrow—not for body text on light surfaces. Links on the light surface
use `#155EA8`; links on the dark surface use `#9EC7EF`.

## Scrim

Any text over a photograph or packet capture requires the scrim across the entire image.
Use 72% black-slate in light mode and 78% in dark mode. Text over images is always white,
semibold or heavier, and at least 18px. If the image remains busy after the scrim, move the
text outside the image; never increase the opacity until the picture becomes decorative mud.

## Type scale

Use `Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif` for prose and
`ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace` for commands, counters, packet
paths, and small technical labels. Do not download a webfont for the landing page.

| role | size L / M / S | weight | line height | letter spacing |
|---|---|---:|---:|---:|
| display | 108 / 84 / 64px | 800 | 0.92 | -0.06em |
| headline | 72 / 52 / 40px | 750 | 1.00 | -0.045em |
| title | 32 / 26 / 21px | 700 | 1.15 | -0.025em |
| body | 20 / 18 / 16px | 400 | 1.60 | 0 |
| label | 14 / 12 / 11px | 700 | 1.35 | 0.10em uppercase |

The website body minimum is **16px**. Documentation prose must not go below 16px; small
labels may use 11–14px only when they are supplementary and never the sole carrier of a
decision or instruction. Code is 14px minimum on desktop and 13px on narrow mobile screens.

## Shape

| scale | radius | use |
|---|---:|---|
| none | 0 | section boundaries, diagrams, tables |
| extra-small | 3px | tags, status labels, inline code |
| small | 4px | buttons and compact controls |
| medium | 7px | terminals and code panels |
| large | 12px | rare grouped content panel |
| extra-large | 20px | not used on the landing page |
| full | 999px | tiny status dots only |

Cards use square corners or 4px at most. TFPS is infrastructure; a screen full of soft,
floating pills weakens the voice.

## Spacing

Use an 8px base step. Allowed spacing values are `4, 8, 12, 16, 24, 32, 40, 48, 64, 80,
96, 120px`. Use 120px for major desktop section padding, 48–64px between a section heading
and its content, 24–40px inside cards, and 8–16px within a control. On mobile, major section
padding becomes 80px. Do not invent intermediate values to make one section fit.

The maximum content width is 1160px; outer gutters are 24px on desktop and 15px on narrow
mobile. Long prose measures 620–720px.

## Logo

The supplied `docs/assets/tfps-logo.jpg` is the only approved full logo and currently has a
white background; there is no true dark or transparent variant.

- On light surfaces, place it directly on white or near-white with no mask or recoloring.
- On dark surfaces, place the unchanged image on a white rectangular tile. Never invert it:
  inversion changes the logo's face and tonal hierarchy.
- Clear space is at least the height of the lowercase `t` crossbar on all four sides,
  approximated as **10% of the rendered logo width**.
- Minimum full-logo width is 220px on screen. Below that, use the plain text wordmark `TFPS`
  in 800 weight with 0.14em tracking; do not crop the detective mark out of the JPEG.
- Preserve the nearly square aspect ratio. Never stretch, skew, rotate, shadow, or place the
  logo over a photograph.
- The logo tagline says “Telephony Fraud Prevention Service,” while the current project name
  is “Telephony Fraud Prevention System.” In prose and metadata, **System is canonical**;
  treat “Service” as legacy artwork until the logo is redrawn.

## Motion

The base site does not need entrance animation. Hover feedback may change color or translate
an arrow by no more than 4px over 120–180ms. Respect `prefers-reduced-motion`; content and
state must never depend on animation.

## Imagery and diagrams

Prefer structural diagrams, terminal excerpts, and real operator evidence. Network diagrams
use straight horizontal paths, the outline token for passive hops, primary for TFPS, cyan for
the single active drop point, and monospace labels. Product screenshots must be current and
captioned with what the reader should notice.

## This brand never

- Uses neon green “hacker” graphics, hooded stock-photo figures, locks, shields, or matrix rain.
- Uses gradients as a background or button fill; the logo's existing tonal blend is legacy
  artwork, not permission to add new gradients.
- Uses cyan for paragraphs, large surfaces, or multiple competing calls to action.
- Uses red decoratively. Error is reserved for destructive actions and confirmed failures.
- Uses glassmorphism, heavy shadows, glowing borders, or a dashboard grid as atmosphere.
- Makes unsupported promises such as “stops all fraud,” “AI-powered,” or “zero false positives.”
- Hides the experimental status of behavioural detection or the absence of TLS/IPv6 parsing.
- Shrinks text to fit. Reduce copy or split the component instead.
- Places more than one primary action in the same visual group.
- Mixes “Service” and “System” in prose; System is the product name.

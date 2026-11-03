# Explorer Style Guide

The explorer is a terminal: one monospace face on a near-black page, square 1px rules, dim labels,
full-contrast values, and yellow for anything you can act on. This guide is the reference for new
and changed UI. [`src/styles.css`](src/styles.css) implements it with the tokens below; change both
together.

## Foundations

| Token | Value | Use |
| --- | --- | --- |
| `--font-family-mono` | ui-monospace, SF Mono, Menlo, … | The only typeface. Figures are tabular (`tabular-nums lining-nums`). |
| `--font-size` | 21px | Root size, so `1rem` below is 21px. |
| `--line-height` | 1.4 | Body text. Statistics use 1.1 and the histogram 1. |
| `--theme-background` | #0e0f10 | Page, popups, grid cells. |
| `--theme-row-alt` | #131415 | Fields and row hover. |
| `--theme-border` | #2a2a2a | Every rule, grid gap, and outline. |
| `--theme-text` | #eeeeee | Titles and values. |
| `--theme-text-dim` | #8a8a8a | Labels, metadata, help, empty and pending states. |
| `--theme-accent` | #ffb200 | Actions, links, focus, live figures, histogram marks. |
| `--theme-success` | #3fb950 | Verified evidence labels, checks, and proof values. |
| `--theme-verified-surface` | 7% success over background | Verified proof panels and historical account evidence. |
| `--theme-error` | #ff6b6b | Connection errors and submission verification failures. |

Corners are always square, and borders are always 1px `--theme-border`. Shadows belong only to
popups and the toast.

### Type scale

Three sizes, all in `rem` so nested elements never compound:

| Token | Default | Popups ≤760px | Role |
| --- | --- | --- | --- |
| `--text-md` | 1rem (21px) | 0.7rem (~15px) | Body, values, titles, controls |
| `--text-sm` | 0.85rem (~18px) | 0.6rem (~13px) | Labels and hints |
| `--text-lg` | clamp(1rem, 1.3vw, 1.2rem) | 1rem | Headline statistics |

Outside popups on narrow screens, `--text-lg` becomes `clamp(1rem, 5vw, 1.5rem)`. Popups use
the default scale on desktop and override these tokens on narrow screens; descendants select
a token and never set `em` or pixel sizes. Weight is always 400, except the 700 proof check mark.

### Spacing

| Token | Value | Use |
| --- | --- | --- |
| `--space-xs` | 0.3ch | Label to value; wrapped row gap |
| `--space-sm` | 0.5ch | Heading rule padding; small stacks |
| `--space-md` | 1ch | Default gap between controls and inline items |
| `--space-lg` | 1.5ch | Between blocks inside a popup |
| `--gutter` | 2ch; 1rem ≤760px | Horizontal inset of the header, popup header, and popup sections |
| `--pad-control` | 0.35ch 1ch | Buttons, selects, segmented tabs |
| `--pad-field` | 0.35ch 0.7ch | Text inputs |
| `--pad-cell` | 0.7ch 1ch | Datum-grid cells, toast |
| `--pad-row` | 0.8ch 0 | Transaction rows, address line |

Spacing is in `ch`, so it scales with the surface's text size. Page-level insets on the homepage
and account pages use viewport `clamp()` values.

## Text roles

**Casing.** Author UI text in lowercase: titles, labels, buttons, status words, and empty states.
Complete sentences (help, notices, errors) use sentence case. Acronyms keep their case.
Identifiers keep their authored case and are never transformed by styling.

| Role | Style | Where |
| --- | --- | --- |
| Title | `--text-md`, text color, lowercase as written | App title (`h1`), popup titles (`h2`), account and block page titles (`h2`) |
| Label | `--text-sm`, dim, uppercase, 0.06em tracking | Datum-grid labels, homepage stat labels, block-log column headers, form labels |
| Section heading | A label with a 1px rule below (0.5ch padding and margin) | Page title rows, transaction subheads (`h3`), submitted transactions (`h3`) |
| Value | `--text-md`, text color | Grid values and row data |
| Statistic | `--text-lg`, one line with ellipsis | Homepage statistics |
| Metadata | `--text-md`, dim | Row secondary lines, timestamps, inline from/to/value/nonce labels |
| Hint | `--text-sm`, dim | Keyboard shortcuts and field hints |
| Status | `--text-md`, dim | Search progress, no-match message, and errors |

Long hashes and addresses either truncate with a middle ellipsis (rows, block log) or wrap anywhere
(grid values, wallet address). They never widen a layout.

## Controls

- **Primary action:** accent fill, background-colored text, 1px accent border, `--pad-control`.
  The header wallet button, popup close, wallet actions, transfer submit, page refresh,
  account and block pagers, and the search submit button.
- **Segmented tabs:** a 1px-gap group of dim buttons; the active tab is inverted (text-color fill).
  Tabs preserve their labels' intrinsic width. Used for the account all/sent/received filter.
- **Links and copy targets:** buttons styled as text with no padding. Identity links that open an
  account or transaction page are accent; copy-only values are text color and turn accent on hover.
- **Fields:** row-alt fill, 1px border, `--pad-field`. Focus turns the border accent and adds an
  inset 1px accent outline.
- **Disabled:** opacity 0.45 and a default cursor, for every button and input.
- **Focus:** every focusable element shows a 1px accent outline on `:focus-visible`, offset 2px.
  Elements flush with a container edge (block rows, tabs, fields) use an inset
  outline (offset −1px).

Search lives in the app header as one identity field and a submit button. Matches open their
account or transaction page directly.

## Components

**Header.** Title at left (`constantinople` in accent, then `/ explorer` as a link home), search
centered in the viewport, and wallet actions at right separated from the height by a dim `⬝`.
Equal side columns keep search centered as the height and wallet contents change. On wide screens
the title, search controls and actions share a baseline; search feedback sits below its field.
Account, block, and transaction pages show the latest height (dim word, accent
figure); the homepage hides it because the live block feed already shows activity. Connection
states take its place: a braille spinner while connecting, or error text with a dot in
`--theme-error`. At ≤1800px the wallet key is omitted. At ≤1300px search occupies its own centered
row. At ≤760px the title centers on its own line. At
≤480px separators hide, and the height or connection status occupies a full row above the actions.

**Datum grid.** Cells separated by 1px border-colored gaps inside a 1px border, `--pad-cell`
padding, a label above a value. Homepage statistics use 5 equal columns, then 2 at ≤760px (an odd last
cell spans the row) and 1 at ≤360px. The wallet's address, balance, and nonce use 3:1:1, stacking
at ≤760px. Account, block, and transaction summaries show the data row first, with certificates
and inclusion proofs grouped in a second row. Each row has equal-width
cells. The account's three proof cells stack when the summary is narrower than 60ch; two-cell rows
stack below 44ch. Grouping stays the same while evidence loads.

**Verified evidence.** A green check precedes a green label wherever the browser has verified
a certificate, ancestry, or inclusion proof. Proof panels also use a subtle green background and
green values. Pending and missing evidence stay dim, without a check or tinted panel. Retained
verified evidence keeps its styling during refresh; request errors remain separate. Green marks
describe the specific evidence, not the authenticity of the site or the freshness of account state.

**Shared proof.** Account, block, and transaction pages show their shared TRANSACTION PROOF once
beside CERT: the authenticated root operation and covered-leaf count written together
(`op<index> / <n>L`). There are no byte sizes, averages, per-row proof badges, or tooltips. The
ACCOUNT PROOF cell shows the account update's proven location (`loc <n>`). Empty pages have no
multiproof to mark as verified. Proof values never break across lines.

**Transaction rows.** A primary line (accent `h<height>:<index>` on account pages, the digest, dim
from/to labels, address links) and a dim metadata line (value, nonce, location). Submitted
transactions add a right-aligned timestamp and a secondary line of compact, wrapping groups.
Pending submissions show `awaiting proof` beside a braille spinner and any reported height or delivery
detail. Verification failures show their reason in error color; certificate and proof labels use
the shared green check treatment only when verified. Each from/to label is grouped
with its address so the two wrap together; a label never ends a line alone. Rows wrap rather than scroll, and digests and
addresses in rows truncate at 20ch, or less when a narrow row needs it, keeping the last eight
characters visible.

**Wallet popup.** Actions sit at the right above the datum grid, followed by the transfer form
(recipient, amount, and submit on one row; stacked at ≤760px). The header shows only a sign-in
prompt, pending action or error. The data row shows BALANCE and LOCAL DRAFT NONCE.
The balance stays unknown until an account update is verified. Account evidence
occupies a full-width summary cell below: a missing proof, loading or error message, or an
ACCOUNT PROOF label with the proven nonce, location and covering snapshot. The proof label and
fields share the verified green text and panel background. Status messages remain dim and inside
their related group. Submitted transactions follow under a section heading.

**Header search.** A single field and accent search button sit between the title and wallet
actions. The field has an accessible address-or-transaction-hash label. A dim status line below
reserves one line for progress, no match or an error. At ≤760px the form occupies its own full-width
row. Enter submits; Escape cancels the pending search and clears its status. Editing the query
also cancels its request. Page navigation and opening the wallet cancel a pending lookup. The
button is disabled while loading or when the field is empty.

**Pagination.** Account and block transaction lists show `PAGE <number>` at the left of the
controls. The number describes the displayed page and changes when its verified rows arrive.

**Block log.** A sticky, label-styled column header over full-width row buttons (height, dim hash,
count, dim time). Beneath the height, the shared green check accompanies `cert v<view>` for a direct
certificate or `via h<height>` for verified ancestry. Rows fade in on arrival unless reduced motion
is requested; hover and focus use row-alt. At ≤760px each row stacks into two lines, height with the
transaction count at right, then the dim hash with the time at right. The header labels follow the
same layout. Hashes and timestamps truncate to fit, and the whole row stays one click target.

## States

- **Loading:** an accent braille spinner before a dim lowercase message (`connecting`, `loading
  certified transactions`). Search shows the dim word `searching` without a spinner.
- **Empty:** a dim lowercase line in the row position (`no transactions indexed`). Search notices
  use the dim lowercase message `no indexed match`.
- **Error:** connection errors and submission verification failures use `--theme-error`. A
  failed submission verification shows its reason beside an exclamation mark. Page and search
  errors use the dim status line. Storage warnings sit under the header in accent.
- **Copied:** the bottom toast with an accent `+` prompt.

## Intended exceptions

- **ASCII histogram.** Its glyph grid is sized in pixels (14px; 7px ≤760px; 6px ≤480px) with line
  height 1. Each observed block occupies one column; new batches append at the right without
  interpolated sliding. Unobserved history stays blank, actual empty blocks use dim dots, and
  positive counts use amber. The chart has no visible key. It does not use the text tokens.
- **Block-log time column.** On desktop, an 8px right inset keeps it clear of the scrollbar.

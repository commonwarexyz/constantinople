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
| `--line-height` | 1.4 | Body text. Statistics use 1.1, the SQL editor 1.5, the histogram 1. |
| `--theme-background` | #0e0f10 | Page, popups, grid cells. |
| `--theme-row-alt` | #131415 | Fields, table headers, row hover. |
| `--theme-border` | #2a2a2a | Every rule, grid gap, and outline. |
| `--theme-text` | #eeeeee | Titles and values. |
| `--theme-text-dim` | #8a8a8a | Labels, metadata, help, empty and pending states. |
| `--theme-accent` | #ffb200 | Actions, links, focus, live figures, chart marks. |
| `--theme-success` | #3fb950 | Verified proof check marks only. |
| `--theme-error` | #ff6b6b | Connection and query errors only. |

Corners are always square, and borders are always 1px `--theme-border`. Shadows belong only to
popups and the toast.

### Type scale

Three sizes, all in `rem` so nested elements never compound:

| Token | Default | Search popup | Popups ≤760px | Role |
| --- | --- | --- | --- | --- |
| `--text-md` | 1rem (21px) | 0.75rem (~16px) | 0.7rem (~15px) | Body, values, titles, controls |
| `--text-sm` | 0.85rem (~18px) | 0.65rem (~14px) | 0.6rem (~13px) | Labels, hints, axis text |
| `--text-lg` | clamp(1rem, 1.3vw, 1.2rem) | 1.25rem | 1rem | Headline statistics |

Outside popups on narrow screens, `--text-lg` becomes `clamp(1rem, 5vw, 1.5rem)`. Dense surfaces
override these tokens on their panel; descendants select a token and never set `em` or pixel
sizes. Weight is always 400, except the 700 proof check mark.

### Spacing

| Token | Value | Use |
| --- | --- | --- |
| `--space-xs` | 0.3ch | Label to value; wrapped row gap |
| `--space-sm` | 0.5ch | Heading rule padding; small stacks |
| `--space-md` | 1ch | Default gap between controls and inline items |
| `--space-lg` | 1.5ch | Between blocks inside a popup |
| `--gutter` | 2ch; 1rem ≤760px | Horizontal inset of the header, popup header, and popup sections |
| `--pad-control` | 0.35ch 1ch | Buttons, selects, segmented tabs |
| `--pad-field` | 0.35ch 0.7ch | Text inputs (the SQL editor uses 1ch) |
| `--pad-cell` | 0.7ch 1ch | Datum-grid cells, toast |
| `--pad-row` | 0.8ch 0 | Transaction rows, address line |

Spacing is in `ch`, so it scales with the surface's text size. Page-level insets on the homepage
and account pages use viewport `clamp()` values.

## Text roles

**Casing.** Author UI text in lowercase: titles, labels, buttons, status words, and empty states.
Complete sentences (help, notices, errors) use sentence case. Acronyms keep their case (`SQL`).
SQL identifiers (table names, column names, aliases) keep their authored case and are never
transformed, so result headers, totals, and chart captions show exactly what the query returned.

| Role | Style | Where |
| --- | --- | --- |
| Title | `--text-md`, text color, lowercase as written | App title (`h1`), popup titles (`h2`), account and block page titles (`h2`) |
| Label | `--text-sm`, dim, uppercase, 0.06em tracking | Datum-grid labels, homepage stat labels, block-log column headers, form labels, Search field labels and stats |
| Section heading | A label with a 1px rule below (0.5ch padding and margin) | Page title rows, transaction subheads (`h3`), submitted transactions (`h3`) |
| Value | `--text-md`, text color | Grid values, row data, table cells |
| Statistic | `--text-lg`, one line with ellipsis | Homepage statistics, Search totals |
| Metadata | `--text-md`, dim | Row secondary lines, timestamps, inline from/to/value/nonce labels |
| Hint | `--text-sm`, dim | Keyboard shortcut, chart range and caption, y-axis, column types |
| Help | `--text-md`, dim, sentence case | Search intro, query guide, result notices |

Long hashes and addresses either truncate with an ellipsis (rows, block log) or wrap anywhere
(grid values, wallet address). They never widen a layout.

## Controls

- **Primary action:** accent fill, background-colored text, 1px accent border, `--pad-control`.
  Header triggers (search, wallet), popup close, wallet actions, transfer submit, page refresh,
  every pager (account, block, Search results), and Search's run button.
- **Secondary option:** background fill, text color, 1px border that turns accent on hover and
  focus. Search example presets, cancel, chart toggle, and chart selects. Preset titles display
  lowercase.
- **Segmented tabs:** a 1px-gap group of dim buttons; the active tab is inverted (text-color fill).
  Tabs preserve their labels' intrinsic width. Used for the account all/sent/received filter.
- **Links and copy targets:** buttons styled as text with no padding. Address links that open an
  account page are accent; copy-only values (digests, your own address) are text color and turn
  accent on hover. Search result links are accent and underlined because they sit in table cells.
- **Fields:** row-alt fill, 1px border, `--pad-field`. Focus turns the border accent and adds an
  inset 1px accent outline.
- **Disabled:** opacity 0.45 and a default cursor, for every button and input.
- **Focus:** every focusable element shows a 1px accent outline on `:focus-visible`, offset 2px.
  Elements flush with a container edge (block rows, tabs, the result table, fields) use an inset
  outline (offset −1px).

Search is the only search entry point: a popup named search, opened from the header and styled
like the wallet popup. There is no search toolbar and no separate search page.

## Components

**Header.** Title at left (`constantinople` in accent, then `/ explorer` as a link home), actions at
right separated by a dim `⬝`. Account and block pages show the latest height (dim word, accent
figure); the homepage hides it because the live block feed already shows activity. Connection
states take its place: a braille spinner while connecting, or error text with a dot in
`--theme-error`. At ≤760px the title centers on its own line and the wallet key is omitted. At
≤480px separators hide, and the height or connection status occupies a full row above the actions.

**Datum grid.** Cells separated by 1px border-colored gaps inside a 1px border, `--pad-cell`
padding, a label above a value. Homepage statistics use 5 equal columns, then 2 at ≤760px (an odd last
cell spans the row) and 1 at ≤360px. The wallet's address, balance, and nonce use 3:1:1, stacking
at ≤760px. Account and block proof grids wrap whole cells instead of fixing a column count: each
cell has an 18ch basis, wraps as a unit, and stretches to fill its row. A partially filled row has
no empty cell.

**Shared proof.** Account and block pages show their page's shared proof once, in the PROOF cell
beside CERT, in the same plain value style: the authenticated root operation and covered-leaf count
written together (`op<index> / <n>L`). There are no byte sizes, averages, per-row proof badges, or
tooltips. The account STATE PROOF cell shows a plain success check followed by the proven
location (`loc <n>`). Proof values never break across lines.

**Transaction rows.** A primary line (accent `h<height>:<index>` on account pages, the digest, dim
from/to labels, address links) and a dim metadata line (value, nonce, location). Submitted
transactions add a right-aligned timestamp and a secondary line joined by dim `·` separators.
Inline certificate and proof checks stay plain glyphs in the line: a success check, a braille
spinner while pending, dim text when not requested. Each from/to label is grouped with its address so the
two wrap together; a label never ends a line alone. Rows wrap rather than scroll, and digests and
addresses in rows truncate at 20ch, or less when a narrow row needs it.

**Wallet popup.** A status label and message with actions at right, the datum grid, a dim account
message, then the transfer form (recipient, amount, and submit on one row; stacked at ≤760px).
Pending work shows the braille spinner before its dim message. Submitted transactions follow under
a section heading.

**Search popup.** A dense surface (see the type scale). In order: help intro, account field with an
inline label, preset buttons, the QUERY label and editor, run and cancel with the shortcut hint at
right, the collapsible query guide (table names in text color, columns dim), status, and results.
Results show a stats row (ROWS, COLUMNS, BATCHES, STORE SEQ), a totals box for single-row numeric
results, chart controls and chart, the scrollable table with sticky headers, and pagination.

**Charts.** A square-bordered figure with an accent line (2px, non-scaling) and 2px dots, or accent
bars, over border-colored grid lines at the top, middle, and bottom. Y-axis bounds sit at left in
hint text, aligned to the plot insets; the x range sits beneath; the caption names y / x and the
point count. Native SVG `<title>` elements carry point values; add no custom hover UI.

**Block log.** A sticky, label-styled column header over full-width row buttons (height, dim hash,
count, dim time). Rows fade in on arrival unless reduced motion is requested; hover and focus use
row-alt. At ≤760px each row stacks into two lines, height with the transaction count at right,
then the dim hash with the time at right, and the header labels follow the same layout. Only the
hash truncates, and the whole row stays one click target.

## States

- **Loading:** an accent braille spinner before a dim lowercase message (`connecting`, `loading
  certified transactions`). Search shows a 4px accent progress bar and the elapsed time.
- **Empty:** a dim lowercase line in the row position (`no transactions indexed`). Search notices
  are dim sentences.
- **Error:** connection and query errors use `--theme-error`. Proof failures stay in text color with
  dim detail, so a failed check reads plainly within its row. Storage warnings sit under the header
  in accent.
- **Copied:** the bottom toast with an accent `+` prompt.

## Intended exceptions

- **ASCII histogram.** Its glyph grid is sized in pixels (14px; 7px ≤760px; 6px ≤480px) with line
  height 1 so its columns fit the frame. It does not use the text tokens.
- **Chart geometry.** The y-axis padding (15px top, 25px bottom) matches the SVG viewBox insets.
- **Block-log time column.** On desktop, an 8px right inset keeps it clear of the scrollbar.

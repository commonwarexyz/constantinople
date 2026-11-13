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
| `--line-height` | 1.4 | Body text. Statistics use 1.1. |
| `--theme-background` | #0e0f10 | Page, popups, grid cells. |
| `--theme-row-alt` | #131415 | Fields and row hover. |
| `--theme-border` | #2a2a2a | Every rule, grid gap, and outline. |
| `--theme-text` | #eeeeee | Titles and values. |
| `--theme-text-dim` | #8a8a8a | Labels, metadata, help, empty and pending states. |
| `--theme-accent` | #ffb200 | Actions, links, focus, live figures, histogram marks. |
| `--theme-success` | #3fb950 | Verified evidence labels, checks, and proof values. |
| `--theme-verified-surface` | 7% success over background | Verified proof panels and account evidence. |
| `--theme-error` | #ff6b6b | Stale markers, connection errors, and submission verification failures. |

Corners are always square, and borders are always 1px `--theme-border`. Shadows belong only to
popups, the search feedback line, and the toast.

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
| `--pad-control` | 0.35ch 1ch | Buttons and selects |
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
| Metadata | `--text-md`, dim | Row secondary lines, clock times, inline from/to/value/nonce labels |
| Hint | `--text-sm`, dim | Keyboard shortcuts and field hints; field placeholders at ≤760px |
| Status | `--text-md`, dim | Search progress, not-found message, and errors |

**Clock times.** Every time of day uses one format from `src/time.ts`: 24-hour local time with
milliseconds (`23:19:56.505`), whether it is a block's certified timestamp in the block log or a
submission's local time in the wallet. Ages (`12s ago`) are the only other time wording.

Long hashes and addresses either truncate with a middle ellipsis (rows, block log) or wrap anywhere
(grid values, wallet address). They never widen a layout.

## Controls

- **Primary action:** accent fill, background-colored text, 1px accent border, `--pad-control`.
  The header wallet button, popup close, wallet actions, transfer submit, page refresh,
  account and block pagers, and the search submit button.
- **Links and copy targets:** buttons styled as text with no padding. Identity links that open an
  account or transaction page are accent; copy-only values are text color and turn accent on hover.
- **Fields:** row-alt fill, 1px border, `--pad-field`. Focus turns the border accent and adds an
  inset 1px accent outline.
- **Disabled:** opacity 0.45 and a default cursor, for every button and input.
- **Focus:** every focusable element shows a 1px accent outline on `:focus-visible`, offset 2px.
  Elements flush with a container edge (block rows, fields) use an inset
  outline (offset −1px).

Search lives in the app header as one identity field and a submit button. Matches open their
account or transaction page directly.

## Components

**Header.** Title at left (`constantinople` in accent, then `/ explorer` as a link home), search
centered in the viewport, and wallet actions at right separated from the height by a dim `⬝`.
Equal side columns keep search centered as the height and wallet contents change. On wide screens
the title, search controls and actions share a baseline; search feedback drops below its field
without adding height.
Account, block, and transaction pages show the latest height (dim word, accent
figure); the homepage hides it because the live block feed already shows activity. Connection
states take its place: a braille spinner while connecting, or error text with a dot in
`--theme-error`. At ≤1800px the wallet key is omitted. At ≤1300px search occupies its own centered
row. At ≤760px the title centers on its own line, the height, separator and wallet actions center
together on the next, and search takes the last row, so its feedback drops over the page rather
than the actions. At ≤480px separators hide, and the height or connection status occupies a full
centered row above the actions.

**Datum grid.** Cells separated by 1px border-colored gaps inside a 1px border, `--pad-cell`
padding, a label above a value. Homepage statistics use 5 equal columns, then 2 at ≤760px (an odd last
cell spans the row) and 1 at ≤360px. The wallet shows its address on the same address line as the account page, then a
2-column grid (balance and local nonce; certificate and account proof once the account is
verified), stacking at ≤760px. Account, block, and transaction summaries show the data row first, with certificates
and inclusion proofs grouped in a second row; the wallet's full-width evidence row is the same
two-cell group. Each row has equal-width
cells. The account's three proof cells stack when the summary is narrower than 60ch; two-cell rows
stack below 44ch and in the wallet at ≤760px. Grouping stays the same while evidence loads.

A cell may carry one secondary line: a label-sized dim line that never wraps, such as the
wallet balance's `nonce <n> / <n> txs`. The line keeps its height while empty, so the grid does
not move when the value it describes arrives.

**Certified age.** Every BLOCK CERT cell shows `h<height> / v<view>` followed by a live
parenthetical age counting up from the certified timestamp, on the same line: `h202 / v216
(14s ago)`. No cell carries a date. Where the certificate stands for the latest state (the
account page and the wallet), the age is judged against the browser clock: green with the value
while recent, red once older than a minute, and amber for a browser clock mismatch
(`<n>s ahead`); the wording never changes, only the color. Block and transaction pages show the
same age dim and unjudged, because
their certificate is not a freshness claim. The homepage carries no age: its block log shows
each block's timestamp. Age never invalidates a proof: the cell keeps its verified tint and label.

**Verified evidence.** A green check precedes a green label wherever the browser has verified
a certificate, ancestry, or account inclusion proof. Proof panels also use a subtle green background and
green values. Pending and missing evidence stay dim, without a check or tinted panel. Retained
verified evidence keeps its styling during refresh; request errors remain separate. Green marks
describe the specific evidence, not the authenticity of the site or the freshness of account state.

**Shared proof.** Account, block, and transaction pages show their shared TRANSACTION PROOF once
beside BLOCK CERT: the authenticated root operation and covered-leaf count written together
(`op<index> / <n>L`). There are no byte sizes, averages, per-row proof badges, or tooltips. The
ACCOUNT PROOF cell shows the account update's proven location and writing height
(`loc <n> / h<height>`). The covering snapshot is the BLOCK CERT beside it.
Empty pages have no multiproof to mark as verified. Proof values never break across lines.

**Transaction rows.** One row design everywhere: a primary line (the accent digest link, dim
from/to labels, address links; the page's own address is a plain copy target) and a dim metadata
line (value, nonce, then account index and location on account pages). The wallet's submitted
transactions use the same rows under a SUBMITTED TRANSACTIONS heading with a `view account`
action; their metadata line adds the local submission clock time and ends with a right-aligned
**timeline** in label size: `reported h<n> 640ms › ✓ cert h<n> / loc <n> 1.2s`. Each step
shows the local time since submission in text color; the relayer's report stays dim because it is
unauthenticated, and only the verified step carries the green check. The timeline ends at the
first pending step (braille spinner, `awaiting report` or `awaiting proof`) or failed step
(`!` and `rejected` or `verification failed` in error color); only a failure's reason goes on
the metadata line, so the left side stays short. Timings are local history metadata and survive a reload; chain evidence
is re-verified before its step turns green. Each from/to label is grouped
with its address so the two wrap together; a label never ends a line alone. Rows wrap rather than scroll, and digests and
addresses in rows truncate at 20ch, or less when a narrow row needs it, keeping the last eight
characters visible.

**Wallet popup.** The popup hangs from a fixed top inset (8vh) rather than centering, so evidence
and submitted transactions that arrive later extend it downward without moving what is already
shown; at ≤760px it fills the screen. Actions sit at the right above the datum grid, followed by the transfer form
(recipient, amount, and submit on one row; stacked at ≤760px). The header shows only a sign-in
prompt, pending action or error. The address line precedes the grid; the data row shows BALANCE and LOCAL NONCE (the browser's
next draft nonce; the proven account nonce sits under the balance).
The balance stays unknown until an account update is verified, then carries the proven nonce
and transaction count on its secondary line. An account the indexer reports as missing holds the
chain's default balance, so BALANCE shows it with `new account` on the secondary line; the value
is not authenticated and carries no check or tint. While the wallet has verified a transaction
that the shown account state predates, the secondary line reads `updating` behind a spinner until
state certified at or above that transaction's block arrives. The evidence row below repeats the account
page's BLOCK CERT and ACCOUNT PROOF cells, including the certified age, and appears only with a
verified account update. Loading and error messages
use the dim status line beneath the grid. Submitted transactions follow under a section heading.

**Header search.** A single field and accent search button sit between the title and wallet
actions. The field has an accessible address-or-transaction-hash label. Progress or an error
appears in a dim popup-styled line dropped beneath the field (bordered, with the popup shadow),
so the header never changes height. At ≤760px the form occupies its own full-width
row. Enter submits; Escape cancels the pending search and clears its status. Editing the query
also cancels its request. Page navigation and opening the wallet cancel a pending lookup. The
button is disabled while loading or when the field is empty.

**Pagination.** Account and block transaction lists show `PAGE <number>` at the left of the
controls. The number describes the displayed page and changes when its verified rows arrive.
Account history is always the complete interval; there is no sent/received filter, because a
filtered page could not prove that it omitted nothing.

**Block log.** A sticky, label-styled column header over full-width row buttons (height, dim hash,
count, dim time). Beneath the height, the shared green check accompanies `cert v<view>` for a direct
certificate or `via h<height>` for verified ancestry. Rows fade in on arrival unless reduced motion
is requested. The fade shortens to two arrivals when blocks are quick, and rows that arrive faster
than a fade can show enter without one, so the top rows never sit dim or blank. Hover and focus use
row-alt. At ≤760px each row stacks into two lines, height with the transaction count at right, then
the dim hash with the time at right. The header labels follow the same layout. Hashes and timestamps
truncate to fit, and the whole row stays one click target.

**Block arrival.** The indexer delivers blocks in batches. The homepage releases a batch one block
at a time at the rate blocks have been arriving, so the histogram, statistics and block log advance
together instead of replacing every visible row at once. A block that arrives with nothing waiting
appears immediately. With reduced motion each batch appears whole.

## States

- **Loading:** an accent braille spinner before a dim lowercase message (`connecting`, `loading
  certified transactions`). Search shows the dim word `searching` without a spinner.
- **Empty:** a dim lowercase line in the row position (`no transactions in this block`). A search
  the indexer cannot match as a transaction opens the account page for that key.
- **Not found:** the account page for an account the indexer reports as missing shows the address
  and `account not found` in the dim status line, with no balance, certificate, proof or history,
  because the answer is unauthenticated. The wallet shows such an account as a new account instead.
- **Error:** connection errors and submission verification failures use `--theme-error`. A
  failed submission verification shows its reason beside an exclamation mark. Page and search
  errors use the dim status line; input that is neither an address nor a transaction hash reads
  `not an address or transaction hash`. Storage warnings sit under the header in accent.
- **Copied:** the bottom toast with an accent `+` prompt.

## Intended exceptions

- **Favicon.** [`public/favicon.svg`](public/favicon.svg) draws five amber histogram bars on the
  page background, separated by 1px gaps so they stay distinct at 16px. As a static asset it
  repeats the `--theme-background` and `--theme-accent` values rather than reading the tokens;
  change them together.
- **Histogram.** A row of fixed-pixel-width columns (`--histogram-column`: 8px; 4px ≤760px;
  3px ≤480px), one per observed block, drawn as boxes so adjacent bars meet without seams. A new
  block appends at the right as one whole column, without interpolated sliding. Unobserved
  history stays blank, actual empty blocks are 2px dim baseline ticks, and positive counts use
  amber bars scaled to the visible peak. The chart has no visible key. It does not use the text
  tokens.
- **Block-log time column.** On desktop, an 8px right inset keeps it clear of the scrollbar.

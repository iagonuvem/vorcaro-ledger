# Vorcaro Sovereign Finance Ledger — Design Guidelines

Companion to `PLAN.md`, `APP_IMPLEMENTATION_PLAN.md`, `SERVER_IMPLEMENTATION_PLAN.md`,
and `COMMON_TYPES.md`. These guidelines govern every executive-facing surface (the
Electron app and the admin console). Structure and principles are adapted from
Apple's Human Interface Guidelines — Design Principles.

---

## 0. North Star

> **Simplicity is the highest level of sophistication.**

This is a financial command system for C-level executives. Its job is to make
**truth legible**: what happened, who signed it, whether it is verified, and what
still needs a decision. Every pixel either increases confidence in the data or
gets out of the way. If a visual element exists for decoration, delete it.

Corollaries:

* The interface is **dark, quiet, and typographic**. Data is the interface.
* Color is **meaning, never mood**. If a color doesn't encode a state, it isn't used.
* No gradients, no glassmorphism, no decorative motion, no illustration in the
  workspace. Visual effects compete with data confidence — they lose.
* When in doubt, remove. A screen you can't simplify further is done.

---

## 1. Design Principles (per Apple HIG)

Apple's eight principles — Purpose, Agency, Responsibility, Familiarity,
Flexibility, Simplicity, Craft, Delight — each interpreted for a financial
command system where the product is confidence in the data.

### 1.1 Purpose — make something meaningful

Design starts with intention. What matters most to a Vorcaro executive is
knowing the truth and acting on it safely.

* Every screen answers one of four questions: *What is our position? What needs
  my decision? What is disputed? What is proven?* A screen that answers none of
  these doesn't ship.
* One focal value per screen region — the number the executive came for (cash
  position, pending approval amount, conflict count). Everything else is
  subordinate in size, weight, and contrast.
* Don't re-create a generic finance dashboard. What sets this product apart is
  verifiability — so verification status is promoted everywhere, not tucked
  into a detail view.

### 1.2 Agency — let people do things their own way

The interface helps executives accomplish goals; it stays out of the way,
keeps them informed, and makes recovery easy.

* Get people directly to the task: unlock → dashboard, no tours, no modals in
  the way. Guided flows (enrollment, recovery) are skippable-forward only where
  the security model allows; never add ceremony the protocol doesn't require.
* Recovery from mistakes is structural: nothing is final until server-accepted,
  so pending events can be withdrawn before push, and every accepted action's
  history remains inspectable. The UI must surface these reversal paths, not
  bury them.
* The exceptions are deliberate: security acknowledgements (checkpoint
  tripwire, quarantine) cannot be skipped or auto-dismissed, and acknowledging
  them is itself audited (`APP_IMPLEMENTATION_PLAN.md` §11). Where the truth
  model constrains freedom, say so honestly rather than hiding the control.
* AI content is advisory and opt-in to act on: it renders only inside the
  labeled "AI analysis — advisory" container and never pre-fills a signature
  path. Executives decide; the system informs.

### 1.3 Responsibility — act in people's best interest

Trust is the product. Be transparent about what the system does and why, and
keep information safe.

* Every action shows its consequence before signing: what will be signed, which
  policy applies, who must co-approve. No hidden side effects, ever.
* Feedback is honest, not optimistic: *signed locally → submitted →
  acknowledged (accepted / rejected / conflicted)*. No "Done!" before the
  server ack. Verification results are facts, not celebrations: "Chain verified
  to sequence 912,388."
* Destructive or high-risk actions (revocation, export, override) always show a
  typed confirmation naming the exact object.
* Privacy is architectural and the UI must not undermine it: no plaintext
  finance data in exports without policy approval, no telemetry, nothing
  leaves the device without a signed, audited event.

### 1.4 Familiarity — build on what people know

Ground the experience in established patterns and apply them consistently.

* Native menu bar, native shortcuts, native window controls per OS. The app
  must feel like a serious desktop instrument, not a web page in a frame.
* Draw on concepts executives already trust: bank-statement tables, ledgers,
  audit trails. Novel concepts (checkpoints, quarantine) borrow familiar
  metaphors and always carry an inline explanation on first encounter.
* Consistency is how familiarity compounds: one component per concept — one
  badge system, one table style, one empty state, one confirmation dialog. No
  screen-local variants. Status colors are global constants (§3): conflicted is
  amber on the dashboard, in the ledger, and in the sync widget — always.
* The UI vocabulary mirrors the ledger vocabulary from `COMMON_TYPES.md`:
  screens say *pending*, *accepted*, *rejected*, *conflicted*, *quarantined* —
  the exact `EventStatus` values. Never invent softer synonyms ("in review",
  "syncing up") that blur the truth model.
* Provide clear feedback through system patterns: show when controls are
  available, indicate when content changes, use one alert/banner system.

### 1.5 Flexibility — adapt to diverse contexts and needs

Design for everyone who will sit in front of this ledger, in every state the
system can be in.

* Accessibility is a priority from the start, not a retrofit — see §7. Never
  rely on color alone; every state pairs color with a label or glyph.
* Support keyboard, mouse, and trackpad fully; every action is reachable by
  keyboard. (Voice and touch are out of scope for the v1 desktop platform.)
* Preserve context across window sizes and platforms (macOS/Windows/Linux):
  content and controls keep consistent, predictable positions; transitions are
  eased with the minimal motion vocabulary of §6.
* Design for offline as a first-class context, not an error state: the offline
  workspace looks calm and capable, with pending intentions clearly marked —
  not a degraded "no connection" experience.

### 1.6 Simplicity — be clear and direct

The north star lives here. Simplicity isn't minimalism — it's a focused
experience where every element earns its place.

* Include just what's necessary: the important things stay close; the rest
  falls away. If a visual element doesn't increase data confidence, delete it.
* Be concise: choose exactly the words needed for a label or message (§8).
* Establish hierarchy: elevation via **surface lightness**, not shadows — black
  canvas → charcoal surface → subtle-gray hairlines, never more than three
  levels. Recognizable controls and consistent structure tell people where
  they are and what comes next. Status (verified / pending / conflicted)
  always outranks decoration; a `PENDING` badge is never smaller or fainter
  than the value it qualifies.

### 1.7 Craft — care about every detail

Quality sets the tone; in this product, sloppiness reads as untrustworthiness.

* Financial figures always render in **tabular numerals**, right-aligned in
  tables, with explicit currency codes. Never truncate an amount; wrap the
  label instead.
* Timestamps show the human-relative form with the exact UTC value one hover
  away — auditability requires the exact value to be one gesture away.
* Iconography: one icon set, one stroke width, monochrome (inherits text
  color). Icons never carry meaning alone; they pair with a label or tooltip.
* Prototype, test in real-world settings, and keep the bar high after
  shipping: hardening asserts, contrast checks, and grayscale checks run in CI
  alongside the code (`APP_IMPLEMENTATION_PLAN.md` §13). Design is an ongoing
  commitment, not a launch artifact.

### 1.8 Delight — make it human

Not all software should feel the same. The right emotion here is **calm
certainty** — the feeling of a locked vault, not a celebration.

* The defining moments are moments of proof: a clean chain verification, an
  approval reaching quorum, a conflict resolved with a signed event. Give these
  states quiet weight (the earned green dot, the exact sequence number) rather
  than animation.
* Don't mistake delight for decoration: no confetti, no mascots, no whimsy.
  Pursuit of charm must never get in the way of the core purpose — truth.
* Delight emerges from the whole: instant unlock, honest feedback, offline
  freedom, familiar patterns, and the accumulated feeling that this system
  never lies. When executives stop double-checking the numbers elsewhere, the
  design has delivered its emotion.

---

## 2. The Truth-State System (this product's signature pattern)

The core UI problem is distinguishing **verified truth** from **intention** from
**dispute**. This mapping is law:

| State | Meaning | Color | Treatment |
|---|---|---|---|
| `accepted` (verified) | Server-acknowledged, chain-verified | Green `#10A37F` | Solid dot + label; the only "calm" state |
| `pending` | Signed local intention, not yet truth | Subtle Gray `#ECECF1` at 60% | Hollow dot + label; visually "unsettled" — never bold |
| `rejected` | Server refused; retained as evidence | Red `#EF4146` | Dot + label; row stays visible, never hidden |
| `conflicted` | Two truths collided; governance needed | Amber `#E0A458` | Dot + label + banner slot eligibility |
| `quarantined` | Held for security review | Amber `#E0A458` + lock glyph | As conflicted, plus lock glyph |

Rules:

* Pending and accepted content must be distinguishable **at a glance and in
  grayscale** — separate list sections, hollow vs. solid markers, muted vs.
  full-contrast figures.
* A pending figure never contributes silently to a headline total. Totals are
  computed from accepted events; pending impact shows as a separate annotated
  delta ("+ $120,000 pending").
* Verification metadata (key version, device, sequence, chain-hash status) is
  always reachable from any event row in one interaction.

---

## 3. Color

### 3.1 Palette (ChatGPT-derived, dark-first)

The palette keeps the recognizable ChatGPT feel — green as the single accent,
charcoal for depth, soft neutrals for text and hairlines — on a black canvas.

| Token | Hex | Name | Role |
|---|---|---|---|
| `--color-canvas` | `#000000` | True Black | App background. Non-negotiable: the black canvas keeps focus on data, not chrome. |
| `--color-surface` | `#202123` | Deep Interface Charcoal | Cards, panels, table headers, modals. |
| `--color-surface-raised` | `#2A2B2E` | Raised Charcoal | Hover states, active rows, popovers (derived: surface +5% lightness). |
| `--color-text-primary` | `#F7F7F8` | Soft Canvas White | Primary text, headline figures. |
| `--color-text-secondary` | `#ECECF1` | Subtle UI Gray | Secondary text at 100%; muted/disabled at 60%/38% opacity. |
| `--color-border` | `#ECECF1` @ 12% | Hairline | All borders and dividers. One weight: 1px. |
| `--color-accent` | `#10A37F` | ChatGPT Green | Verified state, primary action, live-connection anchor. Nothing else. |
| `--color-accent-hover` | `#1A7F64` | Deep Green | Accent hover/pressed. |
| `--color-caution` | `#E0A458` | Muted Amber | Conflicted, quarantined, stale-policy warnings. |
| `--color-danger` | `#EF4146` | Signal Red | Rejected, revoked, checkpoint-tripwire, destructive confirms. |

### 3.2 Usage rules

* **Background is black.** Surfaces are charcoal. Text is soft white. That is
  90% of every screen; the remaining 10% is semantic color.
* Light mode is out of scope for v1. The product is dark-only by design — one
  environment, one contrast model, zero theme drift.
* No color ramps, no chart rainbows. Charts use: accent green for the primary
  series, `#ECECF1` at 60%/35% for comparison series, semantic colors only for
  semantic annotations (a conflict marker, a rejected point).

### 3.3 Green discipline (the accent is earned)

`#10A37F` may appear as exactly three things:

1. The **verified/accepted** state marker.
2. The **single primary action** per screen (one green button, maximum).
3. The **live connection** anchor (sync dot when connected and chain-verified).

Green is never a heading color, an icon tint, a hover flourish, a link color, or
a background wash. If green stops meaning "verified or act here," the truth
model loses its strongest visual signal.

### 3.4 Contrast (measured, not vibed)

* `#F7F7F8` on `#000000` ≈ 20:1 — headline figures.
* `#F7F7F8` on `#202123` ≈ 15:1 — card content.
* `#ECECF1` @ 60% on `#202123` ≥ 4.5:1 — the floor for any readable text.
* `#10A37F` on `#000000` ≈ 5.6:1 — passes AA for text and UI components; on
  charcoal use it for markers/buttons (with `#F7F7F8` label text), not body text.

Minimum standard: **WCAG 2.1 AA** everywhere; AAA for financial figures.

---

## 4. Typography

* **UI type**: system stack (`-apple-system, "SF Pro", "Segoe UI", system-ui`).
  Native rendering, zero webfont loading — consistent with the no-external-
  resources startup rule (`PLAN.md` §4.1).
* **Figures & identifiers**: `"SF Mono", "Cascadia Mono", monospace` for
  amounts, sequences, hashes, key versions, and ULIDs. Monospace signals
  "machine-verifiable fact."
* Scale (4 sizes only): 24px headline figure · 15px body · 13px secondary ·
  11px caption/badge. Weights: 600 for figures and section titles, 400 for
  everything else. No thin weights on dark backgrounds.
* All numerals set with `font-variant-numeric: tabular-nums`.
* Hashes and signatures render truncated middle-out (`sha256:3fa8…c91d`) with
  copy-full-value on click.

---

## 5. Layout & Spacing

* 8px base grid; spacing steps: 4 / 8 / 12 / 16 / 24 / 32 / 48.
* Content max-width 1200px, left-aligned. Financial tables may extend full-width.
* Card anatomy (the only card): charcoal surface, 1px hairline border, 8px
  radius, 16px padding, title row (13px/600) with optional status dot, content.
  No card shadows — elevation via `--color-surface-raised` only.
* Density: tables default to compact (36px rows). Executives scan; they don't
  scroll for sport.
* Empty states: one shared component — 13px secondary text + the single action
  that fills the state. No illustrations.

---

## 6. Motion

Motion confirms causality; it never entertains.

* Durations: 120ms (state/hover) and 200ms (panel/modal), `ease-out`. Nothing
  longer, nothing looping except the sync-in-progress indicator.
* Permitted: fade/4px-slide of panels, badge state cross-fade, sync spinner.
* Forbidden: parallax, springs and bounces, skeleton shimmer (use static muted
  placeholders), number count-up animations — a figure that "rolls" reads as
  approximate, which is the opposite of this product.
* Respect `prefers-reduced-motion`: all transitions collapse to instant.

---

## 7. Accessibility

* WCAG 2.1 AA minimum (§3.4). Full keyboard operability: every action reachable
  by keyboard; visible focus ring (`#F7F7F8` @ 40%, 2px, never green).
* Color is never the only channel: every status pairs a dot shape/fill with a
  text label (hollow=pending, solid=accepted, lock=quarantined).
* Hit targets ≥ 28px in compact tables, ≥ 36px elsewhere.
* All banners and status changes announced via ARIA live regions — the
  checkpoint tripwire must be perceivable to a screen-reader user immediately.

---

## 8. Voice & Content

* Terse, factual, unembellished: "Event accepted. Sequence 912,389." Not
  "Great news! Your event was synced successfully!"
* Errors state fact + consequence + next action, using `ErrorCode` semantics
  from `COMMON_TYPES.md`: "Signature rejected (`BAD_SIGNATURE`). This event was
  not appended. Contact Vorcaro Security if this repeats."
* Never anthropomorphize the system or the AI. AI output is always introduced
  as "AI analysis — advisory" and never speaks in first person plural with the
  executive ("we recommend…" → "Analysis suggests…").
* No exclamation marks. No marketing adjectives inside the workspace.

---

## 9. Do / Don't

**Do**

* Black canvas, charcoal surfaces, hairline borders, typographic hierarchy.
* One green primary action per screen; green = verified, always.
* Tabular numerals, explicit currency, exact timestamps one hover away.
* Show pending vs. accepted as structurally different, not just tinted.
* Keep rejected and quarantined items visible — evidence is never hidden.

**Don't**

* Gradients, shadows, glass, glows, decorative icons, or illustration in the
  workspace.
* Use green for links, headings, icons, or positivity theater.
* Animate numbers, auto-dismiss security banners, or soften status vocabulary.
* Introduce a second accent color "for variety."
* Add any visual element you can't justify as increasing data confidence.

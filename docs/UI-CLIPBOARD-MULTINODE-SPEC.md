# TheKVM Specification — UI Cohesion, Device Roster, Multi-Node, Clipboard

**Status:** normative. **Scope:** desktop UI/UX, Settings, Devices, Connect overlay, multi-node topology, clipboard for text and files. **Agnostic rule:** this document defines observable behavior, states, invariants, and acceptance criteria. It does not prescribe frameworks, languages, file names, or internal APIs. Platform constraints are named only where behavior must adapt. Every numbered requirement is a task; IDs are stable and are used by the verification protocol.

## 0. Reading rules and definitions

"Must" is mandatory; "should" is expected unless a documented platform constraint prevents it. Priority: P0 blocks release, P1 blocks "cohesive and modern" sign-off, P2 is polish. Acceptance criteria are observable by a black-box tester, a vision reviewer, and a code reviewer. Each task inherits its section's acceptance criteria; unique criteria are stated inline.

- **Local** — the computer whose screen is being viewed.
- **Peer** — another trusted computer.
- **Node** — any computer in the topology, including local, desktop peers, and Android peers.
- **Roster** — the complete list of known nodes with identity and state.
- **Session** — an authenticated, encrypted control channel between two nodes.
- **Last-copied-wins** — the newest user-initiated copy on any connected node becomes the clipboard everywhere.
- **Vision pass** — screenshot inspection at defined sizes, themes, and states.
- **White-box pass** — code and protocol inspection against this specification.
- **Black-box pass** — behavior observed only through the UI and operating system.

**Agnostic boundary.** OS clipboard ownership, file-manager paste formats, permission prompts, and display servers differ by platform. Each platform must implement an explicit adaptation and document it. Silent failure is not acceptable.

**Success metrics.** A first-time user can identify the local computer, the connected peer, and every known node without opening a second screen. A returning user can add, inspect, and remove an allowed connection in three actions or fewer. A multi-node user can place, cross, and recover a node without reading documentation. A clipboard user can copy on either machine and paste on the other within one second, repeatedly, with no settings change after connect.

## 1. Global design system and cohesion

The product has one strong reference — Settings typography — and several weaker areas. The goal is one system, not per-tab styling.

**DS-01 — Type scale.** One semantic scale: display 28, page title 20, section title 16, body 14, caption 12, micro 10 (px at 100% scale, scaled with DPI). Settings is the reference; every tab must use the same body and caption sizes. No tab may introduce a smaller body size. Essential text is never below 13; captions never below 12; micro is only for non-essential metadata.

**DS-02 — Alignment grid.** Use a 4/8 px spacing grid, one content gutter, and a small row-height family (32, 36, 40, 48). Within a pane, section titles, row labels, and the first content column share one left edge. Trailing actions share one right edge. Nothing is positioned by eyeballed offsets.

**DS-03 — Color and status.** One token set per theme. Body contrast at least 4.5:1; large text and icons at least 3:1. Semantic colors are fixed: green = connected, allowed, or live; teal = peer or remote; amber = pending or warning; red = destructive or error; yellow = Android or mobile. Color is never the only signal; pair it with text, icon, or shape.

**DS-04 — Icons.** One family and one stroke weight. Optical sizes: 16 inline, 18 row actions, 20-24 primary. Icons are optically centered in hit targets of at least 32x32, preferably 36x36. Trash and overflow glyphs are centered by bounding box, not by baseline arithmetic.

**DS-05 — Components.** One button, toggle, dropdown, row, card, dialog, toast, and menu. Shared height, radius, border, padding, type, and interaction states. Native widgets are allowed only when fully themed; otherwise use the shared component.

**DS-06 — States.** Every interactive element defines default, hover, focus-visible, pressed, disabled, loading, empty, error, and success. Disabled controls state why through a tooltip or caption. Focus is visible for keyboard users.

**DS-07 — Motion.** 120-200 ms easing for state changes. No motion that delays input. Spinners appear only for real work. Reduced-motion preferences are respected.

**DS-08 — Overflow and density.** Text elides with a tooltip or wraps by rule; never clipped mid-glyph; never overlapping; no accidental horizontal scrolling; no decorative text. Long names, IPs, fingerprints, and paths follow the same rule everywhere.

**DS-09 — Cross-platform parity.** Same information architecture, labels, and states on Windows, Linux, and the Android controller. Only platform idioms such as file dialogs and menu placement differ.

**DS-10 — Accessibility.** Keyboard order matches visual order. Icon-only actions have accessible names. Toggles expose checked state. Lists expose count and position. Text scales without clipping.

**DS-11 — Autonomous critique.** Every vision or usability loop must produce suggestions, evaluate each suggestion, and then keep, fix, remove, or add the affected element. Decisions and evidence are recorded; reporting without action does not satisfy this task.

**DS-12 — Responsive rules.** Below 900 px, collapse secondary columns before shrinking type. Below 760 px, stack label and value pairs and keep actions on their own row. Never hide the only action for a state. The window minimum is 720x560, and content remains usable there.

**Acceptance:** vision passes at 720x560, 1024x768, 1440x900, and maximized, in both themes, show one type scale, one grid, no clipping, and consistent component states. A white-box pass finds tokens and components rather than ad-hoc values.

## 2. Settings — Allowed connections

The list must read as a precise table-like list, not a stack of loose text.

**SET-01 — Header alignment.** The plus control and the "Allowed connections" title form one header row: same vertical center, same baseline, one consistent gap, aligned to the content gutter. The plus is a 36x36 target with an optically centered glyph. The title uses the section type size. There is no unexplained top padding and no floating placement.

**SET-02 — Row anatomy, fixed order.** Left to right: index number; computer name; a short vertical separator; IP address; flexible spacer; 3-dot overflow button at the far right edge. The order never changes. There is no separate trash button: **Remove lives inside the 3-dot menu** as its last item. The 3-dot is the last element on the right edge, set apart from the left-aligned text columns.

**SET-03 — Index.** One-based ("1.", "2.", ...), left-aligned in a fixed-width column so every name starts on the same left edge. Renumber after deletion. Muted color, **one type level above body (16 px bold)**, so the index reads as the row's anchor. The index is not part of the name and is not selectable as content.

**SET-04 — Separator.** A single 1 px **vertical** hairline, 24 px tall, vertically centered between name and IP, identical in every row. It is a separator, not an underline or a full-width divider. On a narrow pane, hide it before truncating the name.

**SET-05 — Remove.** There is no trash icon button. Row-local deletion is the "Remove" item in the 3-dot menu; it opens a confirmation that names the computer. Confirm removes; cancel restores focus.

**SET-06 — Overflow (3 dots).** An 18-20 px glyph in a 36x36 target at the far right edge of the row. It opens a menu anchored to the button containing View details, Device keys and fingerprint, Copy address, Rename, and Remove. It is keyboard navigable, closes on Escape or outside click, and never overflows the window.

**SET-07 — Details.** "View details" shows name, address, fingerprint and device keys, trust state, last seen, role and capabilities, and removal. Read-only by default; destructive actions are separated from informational content.

**SET-08 — Empty, loading, error.** Empty: one-line explanation plus the add action. Loading: skeleton rows or a spinner, never a blank area. Error: message plus retry. Only one add control exists.

**SET-09 — List behavior.** Row height is 44-52 px and identical across rows. Adjacent blocks keep one 8px grid step of separation. Hover highlights the row without turning destructive actions red prematurely. Scrolling is vertical only. The header stays visible or scrolls predictably; the list never pushes the header off-screen.

**SET-10 — Focus and confirmation.** Tabbing moves through the row, overflow, and menu in visual order. Enter or Space activates. The delete confirmation traps focus, defaults to Cancel, and returns focus to the row's 3-dot button on close. Screen readers announce "row N of M".

**Acceptance:** at every supported viewport, index, name, vertical separator, IP, and the rightmost 3-dot align on shared columns in every row. The header plus and title align. Deletion renumbers. Long values elide with tooltips. Keyboard and screen-reader passes succeed.

## 3. Devices

This tab is the weakest: misalignment, overflow, redundant text, and non-functional controls. It must become a trustworthy inventory and arrangement surface.

**DEV-01 — Information architecture.** Order: title and actions header; roster summary; per-computer rows or cards with name, address, state, role, and actions; arrangement and edges; multi-node entry; diagnostics and advanced. Remove duplicate status prose and any text that does not help a decision.

**DEV-02 — Layout discipline.** Every row and card uses the grid: equal padding, aligned label and value columns, one action column, equal gaps. No text overflows its container. No control overlaps another. Nothing clips at 720 px width or at maximized size.

**DEV-03 — State model.** Each computer shows exactly one primary state: live or connected, connecting, idle or trusted, discovered or unpaired, or error. Secondary facts such as address, role, fingerprint, and last seen are subordinate. Status colors follow DS-03. Stale data is never shown as live.

**DEV-04 — Actions.** Show only actions valid for the current state: connect, disconnect, view details, remove, place in topology. Disabled actions explain why. No dead buttons. Every action acknowledges input immediately and ends in a visible success or error.

**DEV-05 — Details.** A details surface shows identity, address, fingerprint and device keys, capabilities for control, clipboard, and files, topology placement, latency, and last error. It is reachable from the row, closable, and keyboard accessible.

**DEV-06 — Empty, loading, error.** Empty states explain the next step. Scans show progress and a result count. Failures offer retry. No perpetual spinner without a timeout and message.

**DEV-07 — Overflow.** Long names, IPs, fingerprints, and paths wrap or elide by rule; tooltips reveal full values. Data arrival must not cause layout jumps or horizontal page scrolling.

**DEV-08 — GUI-backend contract.** The UI renders backend-confirmed state. Optimistic updates are marked pending and reconciled. Backend errors surface as actionable messages, never silent no-ops. State-changing controls are idempotent or confirmed.

**DEV-09 — Multi-node entry.** The grid editor is reachable from Devices, explained in one line, and shares the same roster and state as the tab. Opening or closing it preserves placement and selection.

**DEV-10 — Status vocabulary.** Use one label per state everywhere: Live, Connecting, Idle, Discovered, Error. Do not alternate between synonyms such as connected, linked, online, and active for the same condition. The roster and the Connect overlay share this vocabulary. Exception: the Connect two-row grid (CON-02) shows Live by dot color only, with no "Live" text.

**Acceptance:** a component-by-component vision pass and a white-box state-mapping review find no overflow, misalignment, dead control, or misleading label. Every action produces the correct visible result. Backend failures are visible and recoverable.

## 4. Connect section and overlay

The mapping is good; the execution is not yet cohesive.

**CON-01 — Type size.** Keep the mapping, but raise essential text to the body scale of at least 14 px. Section title 16, body 14, metadata 12. No essential label below 13.

**CON-02 — Status alignment.** "This computer" and "Connected computer", or the peer name, are two rows that start on the same vertical line. Their status dots share one fixed column flush left at the content gutter and one baseline (box left = "Computers" left = dot left). The dot, label, and value form one aligned grid across both rows. Live is shown by the green dot alone: the Connect grid never renders a green "Live" text label (user decision, 2026-11-27); Connecting/Idle text shows only until the link is verified. All other gates of this spec (DEV-10 vocabulary in the roster) still apply.

**CON-03 — Complete roster.** The overlay lists every known computer, one per row: local first, then connected peers, then other trusted or multi-node peers, then discovered devices. Android devices are separate rows with yellow status dots and a platform label. The list scrolls when long. The connected row is primary but never the only row.

**CON-04 — Row anatomy.** Fixed columns: status dot, name, address or transport, state label, optional action. Same height and gaps for local, peer, Android, and multi-node rows. No duplicated "this PC" wording and no grey filler text duplicating the name next to the address.

**CON-05 — State feedback.** Connecting shows progress on the affected row only. Failure shows retry. Disconnected shows idle. Android shows yellow. Multi-node peers show their own link state. No ambiguous global spinner.

**CON-06 — Actions.** Connect and disconnect are contextual to the selected or connected row. Destructive actions confirm. All actions are keyboard reachable and announce results.

**CON-07 — Empty state and truncation.** With no peers, the overlay still shows the local row and a one-line prompt to add a computer. Names and addresses elide with tooltips. The roster never collapses to a single row merely because only one peer is connected.

**CON-08 — Instant switching by number.** Pressing Ctrl+Shift+<number> (digit row or numpad) switches control without any cursor travel: 1 returns to this computer; 2..N drives the Nth trusted computer in Devices order that has a placed screen. It works identically in a two-node link and in multi-node topology, in both directions (every computer that may drive can do it from its own keyboard; a ClientOnly machine opens nothing, exactly like an edge crossing). It is consumed by the daemon (never typed into the peer), and can be turned off in Settings ("Switch computers with Ctrl+Shift+number"). An unplaced or out-of-range number is a logged no-op, never a wrong drive. The Connect grid numbers its rows (1. This computer, 2. Connected computer) with the same one-based indexing.

**CON-09 — Two-view navigation.** The app has exactly two top-level views. The main view carries one visible Settings entry (sliders icon + "Settings" label, 36px target). Settings is a single view with a straight left-arrow back control that returns to the main view, and two sections chosen by one segmented control: Devices (computers, details, arrangement, multi-node) and General (policies, clipboard, and the same allowed-connections block). There is no tab bar. Section switches never lose scroll-independent state, and the back arrow is always in the same place.

**Acceptance:** vision passes confirm same-line starts, a shared dot column, body-size text, and a complete roster including Android and multi-node peers. Black-box passes connect and disconnect each row type. No row overflows at any supported size.

## 5. Multi-node: a real, usable protocol

The current multi-node surface is described as a facade. The requirement is an end-to-end capability, not a grid drawing.

**MN-01 — No facade rule.** Every advertised capability must have a working path: discovery, trust, session, topology, input routing, clipboard and files, teardown. The UI must not imply multi-node if the backend cannot route to each node.

**MN-02 — Topology model.** Up to 15 cells on a 5x3 grid, including the local node. Each node has stable identity (fingerprint), addresses, trust state, role and capabilities, and coordinates. Placement persists locally and is shared consistently. Duplicate coordinates are rejected or resolved deterministically and visibly.

**MN-03 — Adjacency and routing.** Edges derive from grid adjacency: left, right, up, down. Wrap behavior is explicit; the right edge wraps to the left only when enabled. Input crossing targets the active neighbor in the direction of travel. Routing is unambiguous when multiple peers are adjacent. A non-adjacent node is not directly crossable.

**MN-04 — Sessions.** One authenticated, encrypted session per peer. Sessions survive transient UI closure, reconnect with backoff, and expire when stale. Revocation is immediate and propagated. A peer cannot spoof another's identity or coordinates.

**MN-05 — Arbitration.** Exactly one computer drives at a time per crossing. Handoff is atomic: no double input, no lost first click. Returning across the edge restores local control. Idle time does not drop a live drive. Conflicts resolve by explicit priority and are logged.

**MN-06 — Failure handling.** Peer loss dims or removes the node, preserves placement, notifies, and blocks or reroutes crossings safely. Partial failure never corrupts topology. Recovery is automatic when the peer returns.

**MN-07 — Security.** Pairing and trust precede routing. Per-peer authorization covers control, clipboard, and files. Replay protection, encrypted transport, least privilege, and an audit log of topology changes are required.

**MN-08 — Persistence.** Topology, placement, trust, and capabilities survive restart. Corrupt state falls back safely with a visible warning.

**MN-09 — Observability.** Each node exposes state, last error, latency, and routing decisions in diagnostics; logs correlate by node ID.

**MN-10 — Grid editor UX.** Supports select-then-place and drag-then-drop, shows occupied, empty, and conflict cells, supports unplace, applies atomically with progress, and reports per-node results. It never claims success before every node acknowledges.

**MN-11 — Scale and performance.** Fifteen nodes stay responsive; the UI holds at least 30 fps; a routing decision takes at most 5 ms; handoff takes at most 150 ms on LAN; no quadratic UI stalls.

**MN-12 — Explicit state machine.** Each node exposes a documented state machine: Discovered, Trusted, Connecting, Live, Degraded, Revoked, Offline. Transitions are driven by confirmed events, not timers alone. The UI renders the state machine, and every transition is testable and logged.

**Acceptance:** white-box review of routing, sessions, and arbitration. Black-box test with three or more nodes, including Android, covering place, cross, return, disconnect one node, reconnect, restart, duplicate placement, and revocation. An adversarial review finds no fake path.

## 6. Clipboard: text and files

Clipboard is a security-sensitive, stateful, bidirectional feature. The contract below is exact.

**CB-01 — Activation.** Clipboard sync is inactive on a fresh connection. Connecting, or reconnecting after either app restarted, must not copy either machine's existing clipboard to the other. Sync begins only after the connection is established and a user-initiated copy occurs on either machine. Once activated, a transient reconnect may deliver the latest post-activation copy under CB-09, never pre-existing content.

**CB-02 — Last-copied-wins.** After activation, the newest user copy on any connected computer becomes the clipboard on all connected computers, continuously, in both directions. Alternating copies must keep propagating. No direction may go stale. One-shot or first-copy-only behavior fails this requirement.

**CB-03 — Text.** Text syncs within the configured limit. Paste on any peer yields exactly the last-copied text. Empty or whitespace-only copies follow a defined rule. Text over the limit is refused with the same notification policy as files.

**CB-04 — Files.** A file copy under the configured MB limit is offered to peers as a pasteable file. The receiving computer must be able to paste it into a file manager or app, not merely receive bytes. Transfer uses a direct, efficient local connection over the LAN, encrypted, with progress and completion. The receiver materializes a local path and exposes it on the clipboard as a file list. Multi-file copies follow the same rule with an aggregate limit.

**CB-05 — Over-limit files.** If a file or aggregate exceeds the limit, do not transfer and do not replace the peer clipboard. Show a smart, temporary, auto-dismissing notification on the computer where the copy occurred: the file is too big for copying in TheKVM, with the limit. The notification is non-modal, accessible, and never loops.

**CB-06 — Echo and loop suppression.** Applying a peer paste must not re-broadcast it as a new local copy. Sync-originated copies are tagged. Rapid alternating copies converge to the truly latest one; stale arrivals are discarded by ordering, not by first-arrival wins.

**CB-07 — Ordering and idempotency.** Every clipboard event carries a globally comparable version, using a per-sender sequence plus tie-break or an equivalent. Receivers apply only newer events, deduplicate repeats, and recover gaps by requesting the latest state. No event applies twice.

**CB-08 — Security.** Payloads are encrypted in transit and authorized per peer. Limits are enforced before allocation. Malformed payloads are rejected. Content is never logged. A revoked peer receives nothing.

**CB-09 — Offline queue.** After activation, if a peer is temporarily unreachable, retain only the latest copy and deliver it on reconnect if it is still latest. Drop stale queued copies. Never grow an unbounded queue.

**CB-10 — Performance.** Copy-to-pasteable on LAN is well under one second for text and small files. Large files report progress. The UI never blocks.

**CB-11 — Platform adaptation.** Where a headless service cannot own the OS clipboard, the logged-in session agent applies pastes. Where a platform lacks file-list clipboard support, provide an equivalent documented path, such as a paste-path action, rather than failing silently.

**CB-12 — Observability.** Logs record event ID, kind, size, direction, apply or refuse reason, and latency, without content. Diagnostics show last sync time and last error per peer.

**CB-13 — Notification behavior.** The over-limit notification appears once per copy attempt, states the configured limit, auto-dismisses after a short readable interval, and can be dismissed manually. It must not steal focus or block the copy dialog. The same pattern covers oversized text.

**Clipboard acceptance sequence.**
1. Connect both machines with different clipboards already present. Confirm no sync.
2. Copy text on A; paste on B; verify exact content.
3. Copy different text on B; paste on A; verify the reverse leg.
4. Alternate five or more times, including while driving from either side; every paste matches the latest copy within one second.
5. Copy a file under the limit on A; paste on B into a file manager; verify name, size, and content.
6. Copy a file over the limit; verify no transfer, no clipboard replacement, and one auto-dismissing notification on A only.
7. Disconnect and reconnect; verify no stale replay and no automatic sync at connect.
8. Revoke the peer; verify no clipboard delivery.
9. Restart both; verify the activation rule still holds.

## 7. Verification protocol: five loops minimum

Verification is evidence-based and iterative. Each loop ends with a defect list and a re-run of all prior loops after fixes.

**Loop 1 — Traceability, white-box.** Map every statement in the source critique to a task ID. No statement may be orphaned; no task may lack acceptance criteria.

**Loop 2 — Design and static review, white-box.** Check token, component, and grid usage, state coverage, and GUI-backend contract mapping. Record every deviation.

**Loop 3 — Functional black-box.** Execute every acceptance sequence on real machines. Include Android and three-node cases. Capture logs and recordings.

**Loop 4 — Vision review.** Screenshot every tab, overlay, dialog, menu, and empty, loading, or error state at 720x560, 1024x768, 1440x900, and maximized, in both themes. Inspect alignment, type size, overflow, hierarchy, contrast, and spacing. Compare with modern reference patterns. File defects with location and severity.

**Loop 5 — Adversarial and regression.** Review as a hostile critic: fake states, dead controls, misleading labels, races, stale data, accessibility gaps. Run clipboard alternation, topology failure and recovery, and a soak test. Fix, then re-run Loops 1-5.

**Verification responsibilities.** GUI and UX are verified by vision and physical use on the Mint machine, using both black-box and white-box methods. Backend features are tested end-to-end by the user; the agent may run code-level, iterative critique loops and subtle checks, especially clipboard continuity across both machines. Multi-node must not be accepted on backend claims; it is proven by iterative code testing and adversarial review.

**Evidence.** Each loop produces a dated record: requirement IDs tested, environment and versions, steps, observed result, pass or fail, defect IDs, and artifacts such as screenshots, recordings, and logs. A loop is not complete without evidence for every task it claims to cover.

**Exit gate.** All P0 and P1 tasks pass. Zero known misalignment or overflow. Clipboard continuity is proven beyond the first copy. Multi-node is proven with real routing. Five consecutive clean loops. Documented confidence against the task register is at least 99 percent. Residual risks are documented.

## 8. Traceability, risks, and definition of done

**Traceability.** Settings critique maps to SET-01 through SET-10. Devices critique maps to DEV-01 through DEV-10. Connect critique maps to CON-01 through CON-07. Theme and typography critique maps to DS-01 through DS-12. Multi-node critique maps to MN-01 through MN-12. Clipboard critique maps to CB-01 through CB-13. Verification requirements map to Loops 1-5.

**Assumptions and limits.** The product supports at least two desktop platforms and one Android controller. "Agnostic" means behavior-level, not implementation-level. Platform clipboard and file-manager constraints require documented adaptations. The configured clipboard limit is user-visible and enforced consistently. Notifications are local to the copying machine.

**Risks.** OS clipboard ownership races; file-manager paste format differences; routing ambiguity at grid corners; stale-state regressions; subjectivity in vision review. Each risk has an owner and a test in Loops 3-5.

**Definition of done.** Every task above is implemented and evidenced. The UI is cohesive at every supported size and theme. The roster is complete and honest. Multi-node routes input to real nodes. Clipboard is secure, bidirectional, last-copied-wins, file-capable, limit-aware, and inactive until the first copy after connection.

**Document verification record for this draft.**
1. Completeness pass: every source critique point is mapped to a task.
2. Task pass: every requirement has an ID and acceptance criteria.
3. Count pass: the document stays under 4,000 words.
4. Consistency pass: status colors, ordering, and activation rules agree.
5. Agnosticism pass: requirements are observable without prescribing implementation.


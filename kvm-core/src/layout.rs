use crate::InputEvent;
use crate::EdgeMode;
use serde::{Deserialize, Serialize};

/// Screen arrangement, like MWB's topology grid / Deskflow's layout editor.
///
/// Screen ids are LOCAL ONLY: each machine numbers itself 1 and its first
/// peer 2 (Swap sides only moves grid positions, never ids). Handoffs name
/// screens by device name across the wire — numbers must never decide
/// identity, because one side's numbering says nothing about the other's.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Layout {
    pub screens: Vec<Screen>,
    /// Which screen is "me" (the one this config lives on).
    pub self_screen: Option<ScreenId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScreenId(pub u32);

/// Screen-id convention for a fresh pairing: self is always 1, first peer
/// is always 2, on EVERY machine. Positions (left/right) are per-machine
/// user arrangement and carry no identity.
pub const SELF_SCREEN_ID: ScreenId = ScreenId(1);
pub const FIRST_PEER_SCREEN_ID: ScreenId = ScreenId(2);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Screen {
    pub id: ScreenId,
    pub name: String,
    /// Grid position in units of screens (0,0 top-left).
    pub x: i32,
    pub y: i32,
    /// Logical width used by the edge router. Physical pixel density remains
    /// a platform concern; this is the coordinate span used for handoff.
    #[serde(default = "default_screen_width")]
    pub width: u32,
    #[serde(default = "default_screen_height")]
    pub height: u32,
    /// Fingerprint of the paired peer occupying this screen. The local
    /// screen has no peer fingerprint.
    #[serde(default)]
    pub peer_fingerprint: Option<String>,
}

const fn default_screen_width() -> u32 {
    1920
}

const fn default_screen_height() -> u32 {
    1080
}

impl Layout {
    pub fn validate(&self) -> Result<(), String> {
        if self.screens.len() > 64 {
            return Err("layout contains more than 64 screens".into());
        }
        let mut ids = std::collections::HashSet::new();
        let mut positions = std::collections::HashSet::new();
        for screen in &self.screens {
            if screen.name.trim().is_empty() {
                return Err(format!("screen {:?} has an empty name", screen.id));
            }
            if screen.width == 0 || screen.height == 0 {
                return Err(format!("screen {:?} has an empty geometry", screen.id));
            }
            if !ids.insert(screen.id) {
                return Err(format!("duplicate screen id {:?}", screen.id));
            }
            if !positions.insert((screen.x, screen.y)) {
                return Err(format!(
                    "duplicate screen position ({}, {})",
                    screen.x, screen.y
                ));
            }
        }
        if let Some(self_screen) = self.self_screen {
            if !ids.contains(&self_screen) {
                return Err(format!(
                    "self screen {:?} is not in the layout",
                    self_screen
                ));
            }
        }
        Ok(())
    }

    /// Given my current cursor position and a movement crossing my edge,
    /// decide which neighbouring screen (if any) receives control.
    pub fn neighbor_for_edge(&self, me: ScreenId, edge: Edge) -> Option<ScreenId> {
        let mine = self.screens.iter().find(|s| s.id == me)?;
        let (dx, dy) = match edge {
            Edge::Left => (-1, 0),
            Edge::Right => (1, 0),
            Edge::Top => (0, -1),
            Edge::Bottom => (0, 1),
        };
        let tx = mine.x + dx;
        let ty = mine.y + dy;
        self.screens
            .iter()
            .find(|s| s.x == tx && s.y == ty)
            .map(|s| s.id)
    }

    /// True when the layout links exactly one peer screen (the normal
    /// two-machine link). This is a COUNTING helper for UI hints and the
    /// push-through return rule — it does NOT mean "any edge crosses".
    /// Routing is always strict grid (see [`Layout::edge_target`]).
    pub fn single_peer_screen(&self) -> Option<ScreenId> {
        let mut found = None;
        for screen in &self.screens {
            if screen.peer_fingerprint.is_some() {
                if found.is_some() {
                    return None;
                }
                found = Some(screen.id);
            }
        }
        found
    }

    /// Edge target on the arranged grid ONLY: a crossing opens solely
    /// through the edge that faces a real arranged neighbour
    /// (Deskflow/MWB parity). Brushing the top edge of a side-by-side
    /// link clamps the cursor — it must never fling control to the other
    /// computer — and motion off any unarranged edge stays local. The old
    /// single-peer "any edge crosses" fallback is gone on purpose: it
    /// turned every top-edge brush into a phantom crossing.
    pub fn edge_target(&self, me: ScreenId, edge: Edge) -> Option<ScreenId> {
        self.neighbor_for_edge(me, edge)
    }
    pub fn screen(&self, id: ScreenId) -> Option<&Screen> {
        self.screens.iter().find(|screen| screen.id == id)
    }

    /// Adopt measured pixel dims for one screen (Deskflow `getShape`
    /// parity: the platform reports its real geometry instead of trusting
    /// the 1920x1080 fallback). A virtual edge computed from wrong dims
    /// is the whole "exits while visibly far from the edge" class, on
    /// either computer. Returns false when the id is unknown or a dim
    /// is zero (layout left untouched).
    pub fn set_screen_size(&mut self, id: ScreenId, width: u32, height: u32) -> bool {
        if width == 0 || height == 0 {
            return false;
        }
        let Some(screen) = self.screens.iter_mut().find(|screen| screen.id == id) else {
            return false;
        };
        screen.width = width;
        screen.height = height;
        true
    }

    /// Look a screen up by device name. Handoff routing uses this — never a
    /// bare number — so both sides agree on WHO is driven even when their
    /// local numbering differs.
    pub fn screen_by_name(&self, name: &str) -> Option<&Screen> {
        self.screens.iter().find(|screen| screen.name == name)
    }

    pub fn self_screen(&self) -> Option<&Screen> {
        self.self_screen.and_then(|id| self.screen(id))
    }

    /// Default two-screen arrangement for a fresh pairing: this machine at
    /// (0,0), the peer at (1,0) on its RIGHT. This is the dialer-side
    /// (Machine-1) default; the station side mirrors it to the left (see
    /// the UI's inbound auto-arrangement). Every machine numbers itself 1
    /// and its first peer 2 — handoffs travel by device name and numbers
    /// are local-only.
    pub fn pair_default(
        self_name: &str,
        peer_name: &str,
        peer_fingerprint: &str,
    ) -> Self {
        Self {
            screens: vec![
                Screen {
                    id: SELF_SCREEN_ID,
                    name: display_name(self_name, "This computer"),
                    x: 0,
                    y: 0,
                    width: default_screen_width(),
                    height: default_screen_height(),
                    peer_fingerprint: None,
                },
                Screen {
                    id: FIRST_PEER_SCREEN_ID,
                    name: display_name(peer_name, "Other computer"),
                    x: 1,
                    y: 0,
                    width: default_screen_width(),
                    height: default_screen_height(),
                    peer_fingerprint: Some(peer_fingerprint.to_ascii_lowercase()),
                },
            ],
            self_screen: Some(SELF_SCREEN_ID),
        }
    }

    /// Which edge of the self screen leads to a linked peer screen, if any.
    /// (Display helper for icons and texts; the router crosses exactly
    /// these arranged facing edges — see [`Layout::edge_target`].)
    pub fn peer_exit_edge(&self) -> Option<Edge> {
        let me = self.self_screen?;
        [Edge::Left, Edge::Right, Edge::Top, Edge::Bottom]
            .into_iter()
            .find(|edge| {
                self.neighbor_for_edge(me, *edge).is_some_and(|id| {
                    self.screen(id)
                        .is_some_and(|screen| screen.peer_fingerprint.is_some())
                })
            })
    }

    /// Where the screen for one peer fingerprint sits relative to self.
    pub fn side_of_peer(&self, fingerprint: &str) -> Option<Edge> {
        let me = self.self_screen.and_then(|id| self.screen(id))?;
        let peer = self
            .screens
            .iter()
            .find(|screen| screen.peer_fingerprint.as_deref() == Some(fingerprint))?;
        if peer.x < me.x {
            Some(Edge::Left)
        } else if peer.x > me.x {
            Some(Edge::Right)
        } else if peer.y < me.y {
            Some(Edge::Top)
        } else if peer.y > me.y {
            Some(Edge::Bottom)
        } else {
            None
        }
    }

    /// Next free screen id (one past the current maximum, starting at 1).
    /// Arrangement edits use this so added screens never collide, on any
    /// machine, under the global-id convention.
    pub fn next_screen_id(&self) -> ScreenId {
        let max = self.screens.iter().map(|screen| screen.id.0).max().unwrap_or(0);
        ScreenId(max.saturating_add(1).max(1))
    }

    /// Move one linked peer screen to the given side of the self screen
    /// (the arrangement UI). The change is validated: colliding with
    /// another screen is refused instead of silently overlapping.
    pub fn place_peer(&mut self, fingerprint: &str, side: Edge) -> Result<(), String> {
        let me = self
            .self_screen
            .and_then(|id| self.screen(id))
            .ok_or_else(|| "layout has no local screen".to_string())?;
        let (x, y) = match side {
            Edge::Left => (me.x - 1, me.y),
            Edge::Right => (me.x + 1, me.y),
            Edge::Top => (me.x, me.y - 1),
            Edge::Bottom => (me.x, me.y + 1),
        };
        if self.screens.iter().any(|screen| {
            screen.peer_fingerprint.as_deref() != Some(fingerprint)
                && screen.x == x
                && screen.y == y
        }) {
            return Err("another screen already occupies that position".into());
        }
        let peer = self
            .screens
            .iter_mut()
            .find(|screen| screen.peer_fingerprint.as_deref() == Some(fingerprint))
            .ok_or_else(|| "layout has no linked peer screen".to_string())?;
        peer.x = x;
        peer.y = y;
        Ok(())
    }

    /// Shared mode-aware target rule (router + stateless receiver hop):
    /// the arranged grid neighbour wins; on a lone-peer link in Double
    /// mode the other horizontal outer edge also leads to the peer.
    fn crossing_target_for(
        &self,
        me: ScreenId,
        edge: Edge,
        edge_mode: EdgeMode,
    ) -> Option<ScreenId> {
        if let Some(neighbour) = self.neighbor_for_edge(me, edge) {
            return Some(neighbour);
        }
        if edge_mode == EdgeMode::Double && matches!(edge, Edge::Left | Edge::Right) {
            let peer = self.single_peer_screen()?;
            if peer != me {
                return Some(peer);
            }
        }
        None
    }

    /// Resolve a relative motion that would leave `screen_id`. This stateless
    /// form is used by a receiver to request the next network hop while the
    /// stateful `EdgeRouter` is used by the controller.
    pub fn handoff_for_motion(
        &self,
        screen_id: ScreenId,
        x: u32,
        y: u32,
        dx: i32,
        dy: i32,
        edge_mode: EdgeMode,
    ) -> Option<EdgeHandoff> {
        let screen = self.screen(screen_id)?;
        let x = x.min(screen.width - 1);
        let y = y.min(screen.height - 1);
        let next_x = i64::from(x) + i64::from(dx);
        let next_y = i64::from(y) + i64::from(dy);
        let edge = if next_x < 0 {
            Edge::Left
        } else if next_x >= i64::from(screen.width) {
            Edge::Right
        } else if next_y < 0 {
            Edge::Top
        } else if next_y >= i64::from(screen.height) {
            Edge::Bottom
        } else {
            return None;
        };
        let target = self.crossing_target_for(screen_id, edge, edge_mode)?;
        let target_screen = self.screen(target)?;
        let along = match edge {
            Edge::Left | Edge::Right => y,
            Edge::Top | Edge::Bottom => x,
        };
        let source_span = match edge {
            Edge::Left | Edge::Right => screen.height,
            Edge::Top | Edge::Bottom => screen.width,
        };
        let target_span = match edge {
            Edge::Left | Edge::Right => target_screen.height,
            Edge::Top | Edge::Bottom => target_screen.width,
        };
        let mapped = map_coordinate(along, source_span, target_span);
        let (target_x, target_y) = match edge {
            Edge::Left => (target_screen.width - 1, mapped),
            Edge::Right => (0, mapped),
            Edge::Top => (mapped, target_screen.height - 1),
            Edge::Bottom => (mapped, 0),
        };
        Some(EdgeHandoff {
            from: screen_id,
            target,
            edge,
            target_x,
            target_y,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeHandoff {
    pub from: ScreenId,
    pub target: ScreenId,
    pub edge: Edge,
    pub target_x: u32,
    pub target_y: u32,
}

/// Result of routing one physical input event through a configured topology.
/// Local events are intentionally returned to the caller rather than silently
/// discarded; the platform capture backend decides whether the local event is
/// suppressed after a remote handoff is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutedEvent {
    Local(InputEvent),
    Forward {
        target: ScreenId,
        event: InputEvent,
    },
    Handoff {
        from: ScreenId,
        target: ScreenId,
        edge: Edge,
        /// Position on the target screen at the moment of handoff.
        target_x: u32,
        target_y: u32,
        event: InputEvent,
    },
    /// The virtual remote cursor overflowed while a remote screen was
    /// driven: the caller ends the episode and restores the saved local
    /// position (edge return, no network round trip). Fires only for an
    /// ARMED home-facing overflow (see the router's Schmitt trigger), so
    /// post-entry jitter can never produce one.
    ReturnHome { from: ScreenId, edge: Edge },
}

/// Stateful edge router for a local controller. It tracks the cursor in the
/// configured logical geometry and keeps forwarding keyboard/button events to
/// the active remote screen until the caller explicitly returns control.
#[derive(Debug, Clone)]
pub struct EdgeRouter {
    layout: Layout,
    local_screen: ScreenId,
    current_screen: ScreenId,
    cursor_x: u32,
    cursor_y: u32,
    local_cursor_x: u32,
    local_cursor_y: u32,
    active_remote: Option<ScreenId>,
    /// Remote edge this drive entered through (the local exit edge's
    /// opposite). Starts DISARMED: overflow there clamps until the cursor
    /// settles inside (see SETTLE_PX), which arms the return. Entry always
    /// faces home by grid symmetry, so arming exactly this edge is the
    /// whole snap-back fix — and future modes only widen which edges are
    /// return-eligible.
    entry_edge: Option<Edge>,
    /// True once the cursor has moved SETTLE_PX inside from the entry
    /// edge (or the peer placed us while driving). Only an armed,
    /// home-facing overflow returns.
    return_armed: bool,
    /// Net home-ward overflow px accumulated while UNARMED (see
    /// RETURN_PUSH_PX): the escape hatch. Reset on any inside movement,
    /// on arming, and on every new handoff.
    return_accum: i64,
    /// Which edges may open a crossing (Single = arranged facing edge
    /// only; Double = both horizontal outer edges on a lone-peer link).
    /// Return hysteresis is identical in both modes.
    edge_mode: EdgeMode,
    /// Push-through streak toward one edge: the edge of the current
    /// outward run and the accumulated overflow px. A Handoff fires only
    /// once the run reaches EDGE_PUSH_PX (see above); coming back inside
    /// or switching edge restarts the run from zero.
    push_edge: Option<Edge>,
    push_accum: i64,
    /// Deskflow-style screen lock (ScrollLock): while set, no edge crossing
    /// opens a new handoff — the cursor stays where it is. Locking never
    /// strands control remotely: engaging it returns home first (see the
    /// daemon handoff arm), so the lock always means "held locally".
    locked: bool,
    /// Fresh-entry gate: a controller born with its cursor already parked
    /// at a facing edge must not cross on resting noise — the cursor has
    /// to come comfortably inside first, then push out deliberately.
    /// (Live shape: a respawned child inherits the pointer sitting at the
    /// edge from a previous session and instantly re-opens a zombie
    /// drive.) Cleared once the cursor is observed beyond EDGE_PUSH_PX
    /// of every crossable edge; set only by set_local_cursor_position.
    startup_gate: bool,
}

impl EdgeRouter {
    pub fn new(layout: Layout) -> Result<Self, String> {
        layout.validate()?;
        let current_screen = layout
            .self_screen
            .or_else(|| layout.screens.first().map(|screen| screen.id))
            .ok_or_else(|| "layout has no local screen".to_string())?;
        let (screen_width, screen_height) = layout
            .screen(current_screen)
            .map(|screen| (screen.width, screen.height))
            .ok_or_else(|| "local screen is missing from layout".to_string())?;
        Ok(Self {
            layout,
            local_screen: current_screen,
            current_screen,
            cursor_x: screen_width / 2,
            cursor_y: screen_height / 2,
            local_cursor_x: screen_width / 2,
            local_cursor_y: screen_height / 2,
            active_remote: None,
            entry_edge: None,
            return_armed: false,
            return_accum: 0,
            edge_mode: EdgeMode::Single,
            push_edge: None,
            push_accum: 0,
            locked: false,
            startup_gate: false,
        })
    }

    /// Engage or release the screen lock. Locking only affects FUTURE
    /// crossings (the caller returns home first); unlocking resumes.
    pub fn set_locked(&mut self, locked: bool) {
        self.locked = locked;
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }

    pub fn current_screen(&self) -> ScreenId {
        self.current_screen
    }

    pub fn local_screen(&self) -> ScreenId {
        self.local_screen
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    pub fn active_remote(&self) -> Option<ScreenId> {
        self.active_remote
    }

    /// Why the next home-facing overflow would (or would not) return:
    /// the entry edge and whether the cursor has settled inside since.
    /// Logged with every edge return so the journal proves design
    /// (armed brush of the boundary) versus bug (unarmed fire).
    pub fn return_state(&self) -> (Option<Edge>, bool) {
        (self.entry_edge, self.return_armed)
    }

    /// True when the virtual cursor sits within `margin_px` of an edge
    /// that would open a crossing. The daemon affords a per-event OS
    /// truth resync exactly there — near-edge overflow is computed from
    /// this position, so staleness there is what fires phantom
    /// crossings — while keeping the cheap throttle everywhere else.
    /// Only while local and unlocked; driving and locked states never
    /// cross.
    pub fn near_crossing_edge(&self, margin_px: u32) -> bool {
        if self.active_remote.is_some()
            || self.current_screen != self.local_screen
            || self.locked
        {
            return false;
        }
        let Some(screen) = self.layout.screen(self.current_screen) else {
            return false;
        };
        let margin = i64::from(margin_px);
        let distances = [
            (Edge::Left, i64::from(self.cursor_x)),
            (
                Edge::Right,
                i64::from(screen.width.saturating_sub(1)) - i64::from(self.cursor_x),
            ),
            (Edge::Top, i64::from(self.cursor_y)),
            (
                Edge::Bottom,
                i64::from(screen.height.saturating_sub(1)) - i64::from(self.cursor_y),
            ),
        ];
        distances.iter().any(|(edge, distance)| {
            *distance <= margin && self.crossing_target(self.current_screen, *edge).is_some()
        })
    }

    /// Switch the crossing discipline live (the Settings toggle): Single
    /// crosses only the arranged facing edge; Double additionally opens
    /// the other horizontal outer edge to the lone peer on a two-machine
    /// link. Applies to the NEXT handoff; an active drive keeps the edge
    /// it entered through.
    pub fn set_edge_mode(&mut self, mode: EdgeMode) {
        self.edge_mode = mode;
    }

    /// Mode-aware crossing target for the router: the arranged grid
    /// neighbour wins; on a lone-peer link in Double mode the other
    /// horizontal outer edge also leads to the peer. Top/bottom never
    /// cross implicitly, in any mode; grids are facing-only in both.
    fn crossing_target(&self, me: ScreenId, edge: Edge) -> Option<ScreenId> {
        self.layout.crossing_target_for(me, edge, self.edge_mode)
    }

    pub fn screen(&self, id: ScreenId) -> Option<&Screen> {
        self.layout.screen(id)
    }

    pub fn cursor_position(&self) -> (u32, u32) {
        (self.cursor_x, self.cursor_y)
    }

    /// Return the last position owned by the local screen. A failed network
    /// handoff must restore this position rather than jumping to an arbitrary
    /// corner of the desktop.
    pub fn local_cursor_position(&self) -> (u32, u32) {
        (self.local_cursor_x, self.local_cursor_y)
    }

    /// Seed the local cursor from the platform's current pointer position.
    /// This is intentionally allowed only while control is local; a remote
    /// handoff owns the router's current coordinate until it returns.
    pub fn set_local_cursor_position(&mut self, x: u32, y: u32) -> Result<(), String> {        if self.active_remote.is_some() {
            return Err("cannot seed cursor while a remote screen is active".into());
        }
        let (width, height) = self
            .layout
            .screen(self.local_screen)
            .map(|screen| (screen.width, screen.height))
            .ok_or_else(|| "local screen is missing from layout".to_string())?;
        self.cursor_x = x.min(width - 1);
        self.cursor_y = y.min(height - 1);
        self.local_cursor_x = self.cursor_x;
        self.local_cursor_y = self.cursor_y;
        self.push_edge = None;
        self.push_accum = 0;
        // Arm the fresh-entry gate when the seed sits at a facing edge
        // (see the field): the first gestures after (re)start must come
        // inside before any outward run can open a crossing.
        self.startup_gate = [Edge::Left, Edge::Right, Edge::Top, Edge::Bottom]
            .iter()
            .any(|edge| {
                self.crossing_target(self.local_screen, *edge).is_some()
                    && distance_from_edge(
                        *edge,
                        self.cursor_x,
                        self.cursor_y,
                        width,
                        height,
                    ) < EDGE_PUSH_PX as u32
            });
        Ok(())
    }

    /// Re-pin the virtual cursor to the OS pointer truth while local.
    /// Raw deltas keep arriving after the OS pointer has stopped at the
    /// edge, so pure integration runs AHEAD of the visible cursor — that
    /// drift is the "crosses while visibly near the edge" phantom. The
    /// daemon calls this from the live OS position ahead of routing local
    /// motion (throttled, and per-event near a crossing edge).
    ///
    /// The pin restarts a push run ONLY when it actually moves the cursor
    /// (beyond RESYNC_DIVERGE_PX): a jump means the integrated position
    /// ran away from truth (input scaling, warps, resolution change),
    /// and overflow accumulated from a phantom position is exactly what
    /// fires crossings the user sees as "far from any edge". But a pin
    /// that barely moves — the normal case, truth and virtual agreeing
    /// at the edge while the user leans into it — MUST keep the run:
    /// wiping it here made sustained pushes uncrossable (only single
    /// giant flings crossed), forcing the move-away-and-slam-back
    /// gesture. That was the 0.9.5 edge regression.
    pub fn resync_if_local(&mut self, x: u32, y: u32) {
        if self.active_remote.is_some() || self.current_screen != self.local_screen {
            return;
        }
        let Some(screen) = self.layout.screen(self.local_screen) else {
            return;
        };
        let pinned_x = x.min(screen.width - 1);
        let pinned_y = y.min(screen.height - 1);
        let moved = pinned_x
            .abs_diff(self.cursor_x)
            .max(pinned_y.abs_diff(self.cursor_y));
        self.cursor_x = pinned_x;
        self.cursor_y = pinned_y;
        self.local_cursor_x = self.cursor_x;
        self.local_cursor_y = self.cursor_y;
        if moved > RESYNC_DIVERGE_PX {
            self.push_edge = None;
            self.push_accum = 0;
        }
    }

    /// Adopt this machine's measured screen size into the layout (called
    /// once per controller start, before the cursor seed). Without it the
    /// router works in fallback dims while the pointer lives in physical
    /// ones, and the crossing edge sits where no visible edge is. Clamps
    /// the tracked cursors into the new dims and restarts any push run.
    /// Returns the dims now in force for the local screen.
    pub fn adopt_local_screen_size(&mut self, width: u32, height: u32) -> Option<(u32, u32)> {
        if !self.layout.set_screen_size(self.local_screen, width, height) {
            return None;
        }
        let screen = self
            .layout
            .screen(self.local_screen)
            .expect("EdgeRouter invariant: local screen exists");
        self.cursor_x = self.cursor_x.min(screen.width - 1);
        self.cursor_y = self.cursor_y.min(screen.height - 1);
        self.local_cursor_x = self.local_cursor_x.min(screen.width - 1);
        self.local_cursor_y = self.local_cursor_y.min(screen.height - 1);
        self.push_edge = None;
        self.push_accum = 0;
        Some((screen.width, screen.height))
    }

    pub fn route(&mut self, event: InputEvent) -> RoutedEvent {
        if let Some(target) = self.active_remote {
            // Virtual remote cursor with a Schmitt-trigger edge return.
            // Entry parks exactly on the boundary (1px from overflow), so
            // a naive "overflow returns" rule turns every trackpad jitter
            // into an instant snap-back. Instead the ENTRY edge starts
            // DISARMED: overflow there clamps until the cursor has settled
            // SETTLE_PX inside (armed), after which overflowing the
            // home-facing edge returns. Holding outward pressure can never
            // fire — the clamped state is stable, not accumulating — so
            // there is no bounce: to return you come inside, then push
            // back out, which is the natural motion. Only the edge facing
            // home ever returns; every other edge clamps, so a driven
            // screen exits exactly where the arrangement says.
            if let InputEvent::MouseMove { dx, dy } = event {
                let from = self.current_screen;
                let Some(remote) = self.layout.screen(from) else {
                    return RoutedEvent::Forward { target, event };
                };
                let next_x = self.cursor_x as i64 + i64::from(dx);
                let next_y = self.cursor_y as i64 + i64::from(dy);
                let edge = if next_x < 0 {
                    Some(Edge::Left)
                } else if next_x >= i64::from(remote.width) {
                    Some(Edge::Right)
                } else if next_y < 0 {
                    Some(Edge::Top)
                } else if next_y >= i64::from(remote.height) {
                    Some(Edge::Bottom)
                } else {
                    None
                };
                match edge {
                    None => {
                        self.cursor_x = next_x as u32;
                        self.cursor_y = next_y as u32;
                        // Inside movement cancels any unarmed escape run:
                        // only sustained home-ward pressure returns.
                        self.return_accum = 0;
                        // Settling inside arms the entry edge (see above):
                        // a firm flick arms in one event, resting noise
                        // never reaches the threshold.
                        if !self.return_armed {
                            if let Some(entry) = self.entry_edge {
                                if distance_from_edge(
                                    entry,
                                    self.cursor_x,
                                    self.cursor_y,
                                    remote.width,
                                    remote.height,
                                ) >= SETTLE_PX
                                {
                                    self.return_armed = true;
                                }
                            }
                        }
                    }
                    Some(edge) => {
                        // Unarmed entry edge: clamp, stay disarmed. This is
                        // the snap-back fix: post-entry jitter and fling
                        // tails pin at the boundary instead of firing.
                        let unarmed_entry =
                            self.entry_edge == Some(edge) && !self.return_armed;
                        let faces_home = self.layout.neighbor_for_edge(from, edge)
                            == Some(self.local_screen);
                        if faces_home && !unarmed_entry {
                            // Park on the saved local position
                            // (jump-position semantics): a return never
                            // lands mid-screen.
                            let _ = self.restore_local(target);
                            return RoutedEvent::ReturnHome { from, edge };
                        }
                        if faces_home {
                            // Escape hatch (see RETURN_PUSH_PX): sustained
                            // home-ward shove from a parked, unarmed cursor
                            // accumulates to a return. A deliberate escape
                            // crosses in a few events; jitter alternates
                            // with inside movement (reset above) and can
                            // never save up.
                            let overflow = match edge {
                                Edge::Left => -next_x,
                                Edge::Right => next_x - (i64::from(remote.width) - 1),
                                Edge::Top => -next_y,
                                Edge::Bottom => next_y - (i64::from(remote.height) - 1),
                            };
                            self.return_accum += overflow.max(0);
                            if self.return_accum >= RETURN_PUSH_PX {
                                let _ = self.restore_local(target);
                                return RoutedEvent::ReturnHome { from, edge };
                            }
                        } else {
                            self.return_accum = 0;
                        }
                        // Any other edge (or the still-disarmed entry):
                        // stop at the border and keep driving. Local
                        // overflow never auto-chains a third hop; the peer
                        // routes onwards by request.
                        self.cursor_x =
                            next_x.clamp(0, i64::from(remote.width) - 1) as u32;
                        self.cursor_y =
                            next_y.clamp(0, i64::from(remote.height) - 1) as u32;
                    }
                }
            }
            return RoutedEvent::Forward { target, event };
        }

        let InputEvent::MouseMove { dx, dy } = event else {
            return RoutedEvent::Local(event);
        };
        let screen = self
            .layout
            .screen(self.current_screen)
            .expect("EdgeRouter invariant: current screen exists");
        let next_x = self.cursor_x as i64 + i64::from(dx);
        let next_y = self.cursor_y as i64 + i64::from(dy);
        let (edge, overflow) = if next_x < 0 {
            (Some(Edge::Left), -next_x)
        } else if next_x >= i64::from(screen.width) {
            (Some(Edge::Right), next_x - i64::from(screen.width - 1))
        } else if next_y < 0 {
            (Some(Edge::Top), -next_y)
        } else if next_y >= i64::from(screen.height) {
            (Some(Edge::Bottom), next_y - i64::from(screen.height - 1))
        } else {
            (None, 0)
        };

        let Some(edge) = edge else {
            self.cursor_x = next_x as u32;
            self.cursor_y = next_y as u32;
            self.local_cursor_x = self.cursor_x;
            self.local_cursor_y = self.cursor_y;
            // Back inside: any outward run restarts from zero, so drift
            // and jitter can never save up for a phantom crossing.
            self.push_edge = None;
            self.push_accum = 0;
            // Comfortably inside (beyond push range of every crossable
            // edge) lifts the fresh-entry gate: the next deliberate
            // outward run may cross.
            if !self.near_crossing_edge(EDGE_PUSH_PX as u32) {
                self.startup_gate = false;
            }
            return RoutedEvent::Local(event);
        };
        // Locked screens never open a handoff: clamp like an unlinked edge
        // so local window controls stay reachable.
        if self.locked {
            self.push_edge = None;
            self.push_accum = 0;
            return self.clamp_to_edge(next_x, next_y, screen.width, screen.height);
        }
        let Some(target) = self.crossing_target(self.current_screen, edge) else {
            self.push_edge = None;
            self.push_accum = 0;
            return self.clamp_to_edge(next_x, next_y, screen.width, screen.height);
        };
        // Fresh-entry gate (see the field): a controller seeded at the
        // edge clamps until the cursor has come inside once. Resting
        // noise at the boundary can never open the first crossing.
        if self.startup_gate {
            self.push_edge = None;
            self.push_accum = 0;
            return self.clamp_to_edge(next_x, next_y, screen.width, screen.height);
        }
        // Push-through (Deskflow jump-zone + switch-delay spirit): one
        // stray delta never crosses. The outward run on THIS edge must
        // accumulate EDGE_PUSH_PX before the Handoff fires; a firm push
        // gets there in a couple of events, resting noise never does.
        // A fresh truth resync (see resync_if_local) already restarted
        // the run, so only genuinely sustained pressure opens the edge.
        if self.push_edge == Some(edge) {
            self.push_accum += overflow;
        } else {
            self.push_edge = Some(edge);
            self.push_accum = overflow;
        }
        if self.push_accum < EDGE_PUSH_PX {
            return self.clamp_to_edge(next_x, next_y, screen.width, screen.height);
        }
        self.push_edge = None;
        self.push_accum = 0;
        let target_screen = self
            .layout
            .screen(target)
            .expect("EdgeRouter invariant: neighbor exists");
        let along = match edge {
            Edge::Left | Edge::Right => self.cursor_y,
            Edge::Top | Edge::Bottom => self.cursor_x,
        };
        let source_span = match edge {
            Edge::Left | Edge::Right => screen.height,
            Edge::Top | Edge::Bottom => screen.width,
        };
        let target_span = match edge {
            Edge::Left | Edge::Right => target_screen.height,
            Edge::Top | Edge::Bottom => target_screen.width,
        };
        let mapped = map_coordinate(along, source_span, target_span);
        let (target_x, target_y) = match edge {
            Edge::Left => (target_screen.width.saturating_sub(1), mapped),
            Edge::Right => (0, mapped),
            Edge::Top => (mapped, target_screen.height.saturating_sub(1)),
            Edge::Bottom => (mapped, 0),
        };
        let from = self.current_screen;
        if from == self.local_screen {
            self.local_cursor_x = self.cursor_x;
            self.local_cursor_y = self.cursor_y;
        }
        self.current_screen = target;
        self.cursor_x = target_x;
        self.cursor_y = target_y;
        self.active_remote = Some(target);
        // Arm the Schmitt trigger: the remote entry edge is the local
        // exit edge's opposite, and it starts disarmed (see route()).
        self.entry_edge = Some(edge.opposite());
        self.return_armed = false;
        self.return_accum = 0;
        // Preserve the overshoot as a relative event. The receiver can use
        // the handoff coordinates to establish its own logical pointer and
        // then apply this small remainder.
        let remainder = match edge {
            Edge::Left => InputEvent::MouseMove {
                dx: -saturating_i32(overflow),
                dy: 0,
            },
            Edge::Right => InputEvent::MouseMove {
                dx: saturating_i32(overflow),
                dy: 0,
            },
            Edge::Top => InputEvent::MouseMove {
                dx: 0,
                dy: -saturating_i32(overflow),
            },
            Edge::Bottom => InputEvent::MouseMove {
                dx: 0,
                dy: saturating_i32(overflow),
            },
        };
        RoutedEvent::Handoff {
            from,
            target,
            edge,
            target_x,
            target_y,
            event: remainder,
        }
    }

    /// Clamp an out-of-bounds motion back inside the current screen and
    /// report the surviving remainder as a local event (unlinked edges and
    /// the screen lock behave identically: the cursor stops, nothing
    /// crosses).
    fn clamp_to_edge(&mut self, next_x: i64, next_y: i64, width: u32, height: u32) -> RoutedEvent {
        let previous_x = self.cursor_x;
        let previous_y = self.cursor_y;
        let clamped_x = next_x.clamp(0, i64::from(width - 1));
        let clamped_y = next_y.clamp(0, i64::from(height - 1));
        self.cursor_x = clamped_x as u32;
        self.cursor_y = clamped_y as u32;
        self.local_cursor_x = self.cursor_x;
        self.local_cursor_y = self.cursor_y;
        RoutedEvent::Local(InputEvent::MouseMove {
            dx: (clamped_x - i64::from(previous_x))
                .clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32,
            dy: (clamped_y - i64::from(previous_y))
                .clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32,
        })
    }

    pub fn return_to_local(&mut self, from: ScreenId, x: u32, y: u32) -> Result<(), String> {
        if self.active_remote != Some(from) {
            return Err(format!(
                "cannot return control from {:?}; active remote is {:?}",
                from, self.active_remote
            ));
        }
        let local = self.local_screen;
        let screen = self
            .layout
            .screen(local)
            .ok_or_else(|| "local screen is missing from layout".to_string())?;
        self.current_screen = local;
        self.cursor_x = x.min(screen.width - 1);
        self.cursor_y = y.min(screen.height - 1);
        self.local_cursor_x = self.cursor_x;
        self.local_cursor_y = self.cursor_y;
        self.active_remote = None;
        self.entry_edge = None;
        self.return_armed = false;
        self.push_edge = None;
        self.push_accum = 0;
        Ok(())
    }

    /// Return control to the local screen using the position saved immediately
    /// before the active remote handoff. This is used when a peer disconnects
    /// or cannot be opened, where no trustworthy remote cursor coordinate is
    /// available.
    pub fn restore_local(&mut self, from: ScreenId) -> Result<(u32, u32), String> {
        if self.active_remote != Some(from) {
            return Err(format!(
                "cannot restore control from {:?}; active remote is {:?}",
                from, self.active_remote
            ));
        }
        let local = self.local_screen;
        let screen = self
            .layout
            .screen(local)
            .ok_or_else(|| "local screen is missing from layout".to_string())?;
        self.current_screen = local;
        self.cursor_x = self.local_cursor_x.min(screen.width - 1);
        self.cursor_y = self.local_cursor_y.min(screen.height - 1);
        self.local_cursor_x = self.cursor_x;
        self.local_cursor_y = self.cursor_y;
        self.active_remote = None;
        self.entry_edge = None;
        self.return_armed = false;
        self.push_edge = None;
        self.push_accum = 0;
        Ok((self.cursor_x, self.cursor_y))
    }

    /// Apply a handoff request received from the currently active peer. A
    /// request naming this node's local screen returns control locally; any
    /// other validated screen becomes the next remote target.
    pub fn handoff_to(&mut self, target: ScreenId, x: u32, y: u32) -> Result<bool, String> {
        let target_screen = self
            .layout
            .screen(target)
            .ok_or_else(|| format!("handoff target {:?} is not in the layout", target))?;
        if self.local_screen == target {
            self.current_screen = target;
            self.cursor_x = x.min(target_screen.width - 1);
            self.cursor_y = y.min(target_screen.height - 1);
            self.local_cursor_x = self.cursor_x;
            self.local_cursor_y = self.cursor_y;
            self.active_remote = None;
            self.entry_edge = None;
            self.return_armed = false;
            self.push_edge = None;
            self.push_accum = 0;
            return Ok(false);
        }
        if self.current_screen == self.local_screen {
            self.local_cursor_x = self.cursor_x;
            self.local_cursor_y = self.cursor_y;
        }
        self.current_screen = target;
        self.cursor_x = x.min(target_screen.width - 1);
        self.cursor_y = y.min(target_screen.height - 1);
        self.active_remote = Some(target);
        // Peer-placed drive: no entry edge is known, so arm the return —
        // any home-facing overflow comes home; anything else clamps.
        self.entry_edge = None;
        self.return_armed = true;
        Ok(true)
    }
}

/// Inward settle distance that arms the entry edge for return (px). Below
/// this, post-entry jitter and fling tails can never fire a return; above
/// it, one deliberate push back out comes home. Deliberately generous:
/// a twitchy threshold (12px) armed on the entry shove itself, so every
/// corrective pullback instantly killed the drive and humans could never
/// hold a crossing — each micro-correction re-warped the cursor to the
/// edge, which reads as "pinned". A firm deliberate roam exceeds 48px in
/// one gesture; resting trackpad noise never reaches it.
const SETTLE_PX: u32 = 48;

/// Sustained outward pressure (px of accumulated edge overflow) required
/// to OPEN a crossing. Deskflow's half of this is the jump zone (the
/// cursor must truly be at the edge, not near it); the other half is its
/// switch delay / double-tap (a stray event never crosses). Ours: the
/// daemon re-pins the virtual cursor to the OS pointer so "near" can
/// never read as "at", and overflow must accumulate to this depth on one
/// edge streak before a Handoff fires. One firm push crosses instantly;
/// resting noise, single stray deltas and fling tails pin at the border.
/// The streak resets the moment motion comes back inside or changes
/// edge, so drift can never save up for a phantom crossing.
pub const EDGE_PUSH_PX: i64 = 24;

/// Sustained home-ward pressure (px of net edge overflow) that returns an
/// UNARMED drive. Entry parks disarmed so post-entry jitter and fling
/// tails pin instead of snapping back — but a parked cursor whose owner
/// shoves home-ward must get out: every escape attempt would otherwise
/// clamp forever and the drive wedges with the cursor visible (the whole
/// freeze class). Net accumulation (not a streak): jitter self-cancels
/// across inside/outside alternation, while a deliberate shove crosses
/// the threshold in a few events. Armed returns stay instant; this only
/// adds the escape hatch the disarmed state was missing.
pub const RETURN_PUSH_PX: i64 = 64;

/// A truth re-pin that moves the cursor further than this keeps the
/// position but restarts the push run (the old position was phantom);
/// anything smaller is rounding noise on an agreeing cursor and keeps
/// the run accumulating.
const RESYNC_DIVERGE_PX: u32 = 2;

/// Overflow of one motion step past a screen edge (the Deskflow
/// jump-zone primitive both crossing paths share): None while the step
/// stays inside, else the edge and how far past it the step lands. The
/// stateful router and the stateless receiver hop use the same math so a
/// crossing costs identical sustained pressure in both directions.
pub fn edge_overflow(
    width: u32,
    height: u32,
    x: u32,
    y: u32,
    dx: i32,
    dy: i32,
) -> Option<(Edge, i64)> {
    let next_x = i64::from(x) + i64::from(dx);
    let next_y = i64::from(y) + i64::from(dy);
    if next_x < 0 {
        Some((Edge::Left, -next_x))
    } else if next_x >= i64::from(width) {
        Some((Edge::Right, next_x - i64::from(width.saturating_sub(1))))
    } else if next_y < 0 {
        Some((Edge::Top, -next_y))
    } else if next_y >= i64::from(height) {
        Some((Edge::Bottom, next_y - i64::from(height.saturating_sub(1))))
    } else {
        None
    }
}

/// Pixels between a cursor position and one screen edge (inward distance).
fn distance_from_edge(edge: Edge, x: u32, y: u32, width: u32, height: u32) -> u32 {
    match edge {
        Edge::Left => x,
        Edge::Right => width.saturating_sub(1).saturating_sub(x),
        Edge::Top => y,
        Edge::Bottom => height.saturating_sub(1).saturating_sub(y),
    }
}

fn map_coordinate(value: u32, source_span: u32, target_span: u32) -> u32 {    if source_span <= 1 || target_span <= 1 {
        return 0;
    }
    (u64::from(value.min(source_span - 1)) * u64::from(target_span - 1)
        / u64::from(source_span - 1)) as u32
}

fn saturating_i32(value: i64) -> i32 {
    value.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

fn display_name(name: &str, fallback: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        fallback.into()
    } else {
        trimmed.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn screen(id: u32, name: &str, x: i32, y: i32) -> Screen {
        Screen {
            id: ScreenId(id),
            name: name.into(),
            x,
            y,
            width: 1920,
            height: 1080,
            peer_fingerprint: None,
        }
    }

    #[test]
    fn finds_grid_neighbors() {
        let layout = Layout {
            screens: vec![screen(1, "main", 0, 0), screen(2, "right", 1, 0)],
            self_screen: Some(ScreenId(1)),
        };
        assert_eq!(layout.validate(), Ok(()));
        assert_eq!(
            layout.neighbor_for_edge(ScreenId(1), Edge::Right),
            Some(ScreenId(2))
        );
        assert_eq!(layout.neighbor_for_edge(ScreenId(1), Edge::Left), None);
    }

    #[test]
    fn rejects_duplicate_positions_and_missing_self() {
        let duplicate = Layout {
            screens: vec![screen(1, "one", 0, 0), screen(2, "two", 0, 0)],
            self_screen: None,
        };
        assert!(duplicate.validate().is_err());

        let missing_self = Layout {
            screens: vec![screen(1, "one", 0, 0)],
            self_screen: Some(ScreenId(9)),
        };
        assert!(missing_self.validate().is_err());
    }

    #[test]
    fn edge_router_maps_handoff_between_different_sizes() {
        let mut right = screen(2, "right", 1, 0);
        right.width = 1280;
        right.height = 720;
        let layout = Layout {
            screens: vec![screen(1, "main", 0, 0), right],
            self_screen: Some(ScreenId(1)),
        };
        let mut router = EdgeRouter::new(layout).unwrap();
        let result = router.route(InputEvent::MouseMove { dx: 1000, dy: 0 });
        assert!(matches!(
            result,
            RoutedEvent::Handoff {
                from: ScreenId(1),
                target: ScreenId(2),
                edge: Edge::Right,
                target_x: 0,
                ..
            }
        ));
        assert_eq!(router.active_remote(), Some(ScreenId(2)));
        assert!(matches!(
            router.route(InputEvent::Key(crate::KeyEvent {
                usage: 0x04,
                pressed: true,
            })),
            RoutedEvent::Forward {
                target: ScreenId(2),
                ..
            }
        ));
        router.return_to_local(ScreenId(2), 10, 20).unwrap();
        assert_eq!(router.active_remote(), None);
        assert_eq!(router.cursor_position(), (10, 20));
    }

    #[test]
    fn seeded_at_facing_edge_requires_a_fresh_entry_before_crossing() {
        let layout = Layout {
            screens: vec![screen(1, "main", 0, 0), screen(2, "right", 1, 0)],
            self_screen: Some(ScreenId(1)),
        };
        let mut router = EdgeRouter::new(layout).unwrap();
        // Controller (re)starts with the pointer already parked at the
        // facing edge: resting noise must clamp, never cross.
        router.set_local_cursor_position(1919, 540).unwrap();
        for _ in 0..10 {
            let result = router.route(InputEvent::MouseMove { dx: 4, dy: 0 });
            assert!(matches!(result, RoutedEvent::Local(_)));
        }
        assert_eq!(router.active_remote(), None);
        // Come comfortably inside once: the gate lifts...
        let result = router.route(InputEvent::MouseMove { dx: -400, dy: 0 });
        assert!(matches!(result, RoutedEvent::Local(_)));
        // ...and a deliberate outward run crosses again.
        let mut crossed = false;
        for _ in 0..40 {
            if matches!(
                router.route(InputEvent::MouseMove { dx: 30, dy: 0 }),
                RoutedEvent::Handoff { .. }
            ) {
                crossed = true;
                break;
            }
        }
        assert!(crossed);
    }

    #[test]
    fn unarmed_home_shove_returns_without_settling_first() {
        let layout = Layout {
            screens: vec![screen(1, "main", 0, 0), screen(2, "right", 1, 0)],
            self_screen: Some(ScreenId(1)),
        };
        let mut router = EdgeRouter::new(layout).unwrap();
        let handoff = router.route(InputEvent::MouseMove { dx: 1000, dy: 0 });
        assert!(matches!(handoff, RoutedEvent::Handoff { .. }));
        // Parked unarmed at the entry boundary: small shoves clamp...
        for _ in 0..6 {
            let result = router.route(InputEvent::MouseMove { dx: -10, dy: 0 });
            assert!(!matches!(result, RoutedEvent::ReturnHome { .. }));
        }
        // ...but a sustained home-ward shove escapes without ever
        // settling inside first.
        let result = router.route(InputEvent::MouseMove { dx: -10, dy: 0 });
        assert!(matches!(
            result,
            RoutedEvent::ReturnHome {
                from: ScreenId(2),
                edge: Edge::Left
            }
        ));
        assert_eq!(router.active_remote(), None);
    }

    #[test]
    fn unarmed_boundary_jitter_never_returns() {
        let layout = Layout {
            screens: vec![screen(1, "main", 0, 0), screen(2, "right", 1, 0)],
            self_screen: Some(ScreenId(1)),
        };
        let mut router = EdgeRouter::new(layout).unwrap();
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 1000, dy: 0 }),
            RoutedEvent::Handoff { .. }
        ));
        // Alternating jitter around the parked boundary self-cancels:
        // inside moves reset the escape run every time.
        for _ in 0..30 {
            let out = router.route(InputEvent::MouseMove { dx: -3, dy: 0 });
            assert!(!matches!(out, RoutedEvent::ReturnHome { .. }));
            let back = router.route(InputEvent::MouseMove { dx: 3, dy: 0 });
            assert!(!matches!(back, RoutedEvent::ReturnHome { .. }));
        }
        assert_eq!(router.active_remote(), Some(ScreenId(2)));
    }

    #[test]
    fn locked_router_holds_the_cursor_locally() {
        let layout = Layout::pair_default("me", "peer", &"ab".repeat(32));
        let mut router = EdgeRouter::new(layout).unwrap();
        router.set_locked(true);
        assert!(router.is_locked());
        // Even a full crossing stays local while locked.
        let result = router.route(InputEvent::MouseMove { dx: 5000, dy: 0 });
        assert!(matches!(result, RoutedEvent::Local(_)));
        assert_eq!(router.active_remote(), None);
        router.set_locked(false);
        assert!(!router.is_locked());
        let result = router.route(InputEvent::MouseMove { dx: 5000, dy: 0 });
        assert!(matches!(result, RoutedEvent::Handoff { .. }));
    }

    #[test]
    fn edge_crossing_needs_sustained_push() {
        // Deskflow jump-zone parity: a stray 1px overflow pins at the
        // border; only accumulated outward pressure opens the edge.
        let layout = Layout::pair_default("me", "peer", &"ab".repeat(32));
        let mut router = EdgeRouter::new(layout).unwrap();
        // Walk to one px inside the right edge (cursor starts centered).
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 959, dy: 0 }),
            RoutedEvent::Local(_)
        ));
        assert_eq!(router.cursor_position(), (1919, 540));
        // A lone stray delta overflows by 1px: stays local, pinned.
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 1, dy: 0 }),
            RoutedEvent::Local(_)
        ));
        assert_eq!(router.active_remote(), None);
        assert_eq!(router.cursor_position(), (1919, 540));
        // Sustained pressure accumulates across events, then crosses.
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 30, dy: 0 }),
            RoutedEvent::Handoff {
                edge: Edge::Right,
                ..
            }
        ));
        assert_eq!(router.active_remote(), Some(ScreenId(2)));
    }

    #[test]
    fn edge_push_streak_resets_back_inside() {
        // Drift can never "save up": coming back inside restarts the run.
        let layout = Layout::pair_default("me", "peer", &"ab".repeat(32));
        let mut router = EdgeRouter::new(layout).unwrap();
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 959, dy: 0 }),
            RoutedEvent::Local(_)
        ));
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 10, dy: 0 }),
            RoutedEvent::Local(_)
        ));
        assert_eq!(router.active_remote(), None);
        // Back inside wipes the 10px run ...
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: -100, dy: 0 }),
            RoutedEvent::Local(_)
        ));
        // ... so a fresh 10px overflow still does not cross.
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 110, dy: 0 }),
            RoutedEvent::Local(_)
        ));
        assert_eq!(router.cursor_position(), (1919, 540));
        assert_eq!(router.active_remote(), None);
        // ... but uninterrupted pressure from here does.
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 30, dy: 0 }),
            RoutedEvent::Handoff { .. }
        ));
    }

    #[test]
    fn edge_push_streak_resets_on_edge_change() {
        // Double mode opens both horizontal edges; a run on one edge
        // never spends toward the other.
        let layout = Layout::pair_default("me", "peer", &"ab".repeat(32));
        let mut router = EdgeRouter::new(layout).unwrap();
        router.set_edge_mode(EdgeMode::Double);
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 959, dy: 0 }),
            RoutedEvent::Local(_)
        ));
        // 10px run toward the right edge ...
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 10, dy: 0 }),
            RoutedEvent::Local(_)
        ));
        // ... then all the way to the left edge: the left run starts
        // from zero, so a 10px left overflow stays local too.
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: -1929, dy: 0 }),
            RoutedEvent::Local(_)
        ));
        assert_eq!(router.cursor_position(), (0, 540));
        assert_eq!(router.active_remote(), None);
        // And the earlier right-edge run is forgotten as well.
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 1929, dy: 0 }),
            RoutedEvent::Local(_)
        ));
        assert_eq!(router.active_remote(), None);
    }

    #[test]
    fn resync_pins_virtual_cursor_to_os_truth() {
        // The phantom-crossing root cause: integrated deltas run ahead of
        // the OS pointer that stopped at the edge. Fresh truth re-pins.
        let layout = Layout::pair_default("me", "peer", &"ab".repeat(32));
        let mut router = EdgeRouter::new(layout).unwrap();
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 959, dy: 0 }),
            RoutedEvent::Local(_)
        ));
        assert_eq!(router.cursor_position(), (1919, 540));
        // OS truth says the pointer is mid-screen (e.g. a warp or a
        // clamped edge stop the deltas never saw): adopt it, drop runs.
        router.resync_if_local(100, 200);
        assert_eq!(router.cursor_position(), (100, 200));
        assert_eq!(router.local_cursor_position(), (100, 200));
        // Out-of-range truth clamps instead of panicking.
        router.resync_if_local(9000, 9000);
        assert_eq!(router.cursor_position(), (1919, 1079));
        // While driving remotely the peer owns the coordinate: no-op.
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 5000, dy: 0 }),
            RoutedEvent::Handoff { .. }
        ));
        router.resync_if_local(5, 5);
        assert_ne!(router.cursor_position(), (5, 5));
    }

    #[test]
    fn resync_at_edge_preserves_push_run() {
        // The 0.9.5 edge regression: the per-event truth resync wiped the
        // push run even when it pinned nothing, so sustained small pushes
        // never accumulated and only giant flings crossed. Lean into the
        // edge with 1px events and identical truth: must accumulate and
        // fire like one firm push.
        let layout = Layout::pair_default("me", "peer", &"ab".repeat(32));
        let mut router = EdgeRouter::new(layout).unwrap();
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 959, dy: 0 }),
            RoutedEvent::Local(_)
        ));
        assert_eq!(router.cursor_position(), (1919, 540));
        let mut fired = false;
        for _ in 0..30 {
            // OS truth agrees with virtual (both clamped at the edge):
            // the pin moves nothing, the run survives.
            router.resync_if_local(1919, 540);
            if matches!(
                router.route(InputEvent::MouseMove { dx: 1, dy: 0 }),
                RoutedEvent::Handoff { edge: Edge::Right, .. }
            ) {
                fired = true;
                break;
            }
        }
        assert!(fired, "sustained 1px pushes with agreeing truth must cross");
        assert_eq!(router.active_remote(), Some(ScreenId(2)));
    }

    #[test]
    fn resync_jump_restarts_push_run() {
        // ...but a pin that actually moves the cursor (warp, scaling
        // divergence, resolution change) still drops the stale run: the
        // old overflow was measured from a phantom position.
        let layout = Layout::pair_default("me", "peer", &"ab".repeat(32));
        let mut router = EdgeRouter::new(layout).unwrap();
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 959, dy: 0 }),
            RoutedEvent::Local(_)
        ));
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 10, dy: 0 }),
            RoutedEvent::Local(_)
        ));
        // Jump far away: cursor adopts truth, stale 10px run is gone.
        router.resync_if_local(100, 200);
        assert_eq!(router.cursor_position(), (100, 200));
        // Back at the edge on fresh truth: one more 10px overflow is a
        // fresh 10px run, not 20 — stays local.
        router.resync_if_local(1919, 540);
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 10, dy: 0 }),
            RoutedEvent::Local(_)
        ));
        assert_eq!(router.active_remote(), None);
    }

    #[test]
    fn near_crossing_edge_flags_only_crossable_borders() {        // Mid-screen is never near; the facing edge within margin is;
        // an unlinked edge (top) never is; lock and remote never are.
        let layout = Layout::pair_default("me", "peer", &"ab".repeat(32));
        let mut router = EdgeRouter::new(layout).unwrap();
        assert!(!router.near_crossing_edge(64));
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 895, dy: 0 }),
            RoutedEvent::Local(_)
        ));
        // Cursor now at 1855: 64px from the facing right edge.
        assert!(router.near_crossing_edge(64));
        assert!(!router.near_crossing_edge(63));
        // Top edge has no neighbour in Single: never near.
        router.resync_if_local(960, 10);
        assert!(!router.near_crossing_edge(64));
        // Locked and driving states never cross.
        router.resync_if_local(1910, 540);
        router.set_locked(true);
        assert!(!router.near_crossing_edge(64));
        router.set_locked(false);
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 5000, dy: 0 }),
            RoutedEvent::Handoff { .. }
        ));
        assert!(!router.near_crossing_edge(64));
    }

    #[test]
    fn edge_overflow_reports_signed_overshoot() {
        // Shared jump-zone primitive: inside is None, each edge reports
        // how far past it the step lands.
        assert_eq!(edge_overflow(1920, 1080, 100, 100, 5, 5), None);
        assert_eq!(
            edge_overflow(1920, 1080, 1919, 540, 5, 0),
            Some((Edge::Right, 5))
        );
        assert_eq!(
            edge_overflow(1920, 1080, 0, 540, -3, 0),
            Some((Edge::Left, 3))
        );
        assert_eq!(
            edge_overflow(1920, 1080, 400, 0, 0, -7),
            Some((Edge::Top, 7))
        );
        assert_eq!(
            edge_overflow(1920, 1080, 400, 1079, 0, 2),
            Some((Edge::Bottom, 2))
        );
    }

    #[test]
    fn adopt_local_screen_size_clamps_and_applies() {
        // Measured geometry replaces the fallback: the virtual edge moves
        // to the visible edge and tracked cursors clamp inside.
        let layout = Layout::pair_default("me", "peer", &"ab".repeat(32));
        let mut router = EdgeRouter::new(layout).unwrap();
        assert_eq!(router.adopt_local_screen_size(1280, 720), Some((1280, 720)));
        assert_eq!(
            router.layout().screen(router.local_screen()).map(|s| (s.width, s.height)),
            Some((1280, 720))
        );
        // Cursor was centered in 1920x1080: now clamped into 1280x720.
        assert_eq!(router.cursor_position(), (960, 540));
        router.resync_if_local(5000, 5000);
        assert_eq!(router.cursor_position(), (1279, 719));
        // Zero dims or unknown screens never corrupt the layout.
        assert_eq!(router.adopt_local_screen_size(0, 720), None);
        assert_eq!(
            router.layout().screen(router.local_screen()).map(|s| (s.width, s.height)),
            Some((1280, 720))
        );
    }

    #[test]
    fn next_screen_id_never_collides() {        let paired = Layout::pair_default("me", "peer", &"ab".repeat(32));
        assert_eq!(paired.next_screen_id(), ScreenId(3));
        assert_eq!(Layout::default().next_screen_id(), ScreenId(1));
    }

    #[test]
    fn single_peer_links_cross_only_facing_edges() {
        // Machine 1: peer on the right. The facing edge crosses; every
        // other edge — including the old "double edge" outer edge and the
        // top/bottom brushes — clamps locally and never hands off.
        let layout = Layout::pair_default("me", "peer", &"ab".repeat(32));
        assert_eq!(
            layout.edge_target(SELF_SCREEN_ID, Edge::Right),
            Some(FIRST_PEER_SCREEN_ID)
        );
        assert_eq!(layout.edge_target(SELF_SCREEN_ID, Edge::Left), None);
        assert_eq!(layout.edge_target(SELF_SCREEN_ID, Edge::Top), None);
        assert_eq!(layout.edge_target(SELF_SCREEN_ID, Edge::Bottom), None);
        let mut router = EdgeRouter::new(layout).unwrap();
        let brushed_top = router.route(InputEvent::MouseMove { dx: 0, dy: -5000 });
        assert!(matches!(brushed_top, RoutedEvent::Local(_)));
        assert_eq!(router.active_remote(), None);
        // Grids were and stay strict: the neighbour wins, nothing else.
        let mut grid = Layout::pair_default("me", "peer", &"ab".repeat(32));
        grid.screens.push(Screen {
            id: ScreenId(9),
            name: "third".into(),
            x: -1,
            y: 0,
            width: 1920,
            height: 1080,
            peer_fingerprint: Some("ff".repeat(32)),
        });
        assert_eq!(
            grid.edge_target(SELF_SCREEN_ID, Edge::Left),
            Some(ScreenId(9))
        );
        assert_eq!(grid.single_peer_screen(), None);
    }

    #[test]
    fn driving_home_returns_past_the_facing_edge() {
        let layout = Layout::pair_default("me", "peer", &"ab".repeat(32));
        let mut router = EdgeRouter::new(layout).unwrap();
        let _ = router.route(InputEvent::MouseMove { dx: 200, dy: 0 });
        let home = router.cursor_position();
        // Exit right into the peer: entry at the peer's left edge.
        let handoff = router.route(InputEvent::MouseMove { dx: 5000, dy: 0 });
        assert!(matches!(
            handoff,
            RoutedEvent::Handoff {
                target,
                target_x: 0,
                ..
            } if target == FIRST_PEER_SCREEN_ID
        ));
        // Post-entry jitter against the entry edge pins, never returns.
        let jitter = router.route(InputEvent::MouseMove { dx: -3, dy: 0 });
        assert!(matches!(jitter, RoutedEvent::Forward { .. }));
        assert_eq!(router.active_remote(), Some(FIRST_PEER_SCREEN_ID));
        assert_eq!(router.cursor_position(), (0, 540));
        // Small motion while driving forwards and tracks the remote cursor.
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 100, dy: 50 }),
            RoutedEvent::Forward { .. }
        ));
        assert_eq!(router.cursor_position(), (100, 590));
        // Pushing back past the facing edge returns to the saved home —
        // never mid-screen — with no network round trip.
        let back = router.route(InputEvent::MouseMove {
            dx: -5000,
            dy: 0,
        });
        assert!(matches!(
            back,
            RoutedEvent::ReturnHome {
                from,
                edge: Edge::Left,
            } if from == FIRST_PEER_SCREEN_ID
        ));
        assert_eq!(router.active_remote(), None);
        assert_eq!(router.cursor_position(), home);
    }

    #[test]
    fn lone_peer_far_edge_clamps_without_returning() {
        // Two-machine link, driving the peer: pushing past the FAR side
        // has nowhere arranged to go, so it pins at the border and keeps
        // driving. Only the home-facing edge ever returns (the old
        // push-through rule turned every far-side brush into a snap-back).
        let layout = Layout::pair_default("me", "peer", &"ab".repeat(32));
        let mut router = EdgeRouter::new(layout).unwrap();
        let _ = router.route(InputEvent::MouseMove { dx: 5000, dy: 0 });
        assert_eq!(router.active_remote(), Some(FIRST_PEER_SCREEN_ID));
        // Settle first, so the clamp below proves the edge rule and not
        // the entry disarm.
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 100, dy: 0 }),
            RoutedEvent::Forward { .. }
        ));
        let pushed = router.route(InputEvent::MouseMove { dx: 5000, dy: 0 });
        assert!(matches!(pushed, RoutedEvent::Forward { .. }));
        assert_eq!(router.active_remote(), Some(FIRST_PEER_SCREEN_ID));
        assert_eq!(router.cursor_position(), (1919, 540));
    }

    #[test]
    fn entry_edge_jitter_never_returns_before_settling() {
        // The live desk: Mint on Windows' left; Windows exits left and
        // enters Mint at its right edge (x=1919, 1px from overflow).
        let peer_fp = "ab".repeat(32);
        let layout = Layout {
            screens: vec![
                Screen {
                    id: ScreenId(2),
                    name: "windows".into(),
                    x: 0,
                    y: 0,
                    width: 1920,
                    height: 1080,
                    peer_fingerprint: None,
                },
                Screen {
                    id: ScreenId(1),
                    name: "mint".into(),
                    x: -1,
                    y: 0,
                    width: 1920,
                    height: 1080,
                    peer_fingerprint: Some(peer_fp),
                },
            ],
            self_screen: Some(ScreenId(2)),
        };
        let mut router = EdgeRouter::new(layout).unwrap();
        let home = router.cursor_position();
        let handoff = router.route(InputEvent::MouseMove { dx: -5000, dy: 0 });
        assert!(matches!(
            handoff,
            RoutedEvent::Handoff {
                from,
                target,
                edge: Edge::Left,
                target_x: 1919,
                ..
            } if from == ScreenId(2) && target == ScreenId(1)
        ));
        // Jitter around the entry point: out, in, out — all Forward, all
        // pinned, never home. This exact sequence snapped back on 0.8.3.
        for delta in [2, -1, 1, 3, -2, 2] {
            let routed = router.route(InputEvent::MouseMove { dx: delta, dy: 0 });
            assert!(
                matches!(routed, RoutedEvent::Forward { .. }),
                "jitter dx={delta} must forward, not return"
            );
            assert_eq!(router.active_remote(), Some(ScreenId(1)));
        }
        assert_eq!(router.cursor_position(), (1919, 540));
        // Non-facing edges clamp too, armed or not: Mint exits to Windows
        // only through its right edge.
        for motion in [
            InputEvent::MouseMove { dx: 0, dy: -5000 },
            InputEvent::MouseMove { dx: 0, dy: 5000 },
            InputEvent::MouseMove { dx: -5000, dy: 0 },
        ] {
            let routed = router.route(motion);
            assert!(
                matches!(routed, RoutedEvent::Forward { .. }),
                "non-facing overflow must clamp, not return"
            );
            assert_eq!(router.active_remote(), Some(ScreenId(1)));
        }
        // Settle inside (arms the entry), then push back out through the
        // shared edge: now it comes home, to the exact saved pixel.
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 500, dy: 0 }),
            RoutedEvent::Forward { .. }
        ));
        let back = router.route(InputEvent::MouseMove { dx: 5000, dy: 0 });
        assert!(matches!(
            back,
            RoutedEvent::ReturnHome {
                from,
                edge: Edge::Right,
            } if from == ScreenId(1)
        ));
        assert_eq!(router.active_remote(), None);
        assert_eq!(router.cursor_position(), home);
    }

    #[test]
    fn return_arms_exactly_at_the_settle_threshold() {
        let layout = Layout::pair_default("me", "peer", &"ab".repeat(32));
        let mut router = EdgeRouter::new(layout).unwrap();
        // Peer on the right: enter at its left edge (x=0), entry edge Left.
        let _ = router.route(InputEvent::MouseMove { dx: 5000, dy: 0 });
        // 47px inside: still disarmed — facing overflow clamps.
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 47, dy: 0 }),
            RoutedEvent::Forward { .. }
        ));
        let clamped = router.route(InputEvent::MouseMove { dx: -100, dy: 0 });
        assert!(matches!(clamped, RoutedEvent::Forward { .. }));
        assert_eq!(router.active_remote(), Some(FIRST_PEER_SCREEN_ID));
        // One step to exactly 48px inside: armed — facing overflow home.
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 48, dy: 0 }),
            RoutedEvent::Forward { .. }
        ));
        let back = router.route(InputEvent::MouseMove { dx: -100, dy: 0 });
        assert!(matches!(
            back,
            RoutedEvent::ReturnHome { edge: Edge::Left, .. }
        ));
        assert_eq!(router.active_remote(), None);
    }

    #[test]
    fn peer_placed_drive_returns_without_settling() {
        // A peer-driven hop (chained control) has no entry edge: any
        // home-facing overflow returns immediately, anything else clamps.
        let layout = Layout::pair_default("me", "peer", &"ab".repeat(32));
        let mut router = EdgeRouter::new(layout).unwrap();
        assert!(router.handoff_to(FIRST_PEER_SCREEN_ID, 0, 540).unwrap());
        let back = router.route(InputEvent::MouseMove { dx: -50, dy: 0 });
        assert!(matches!(
            back,
            RoutedEvent::ReturnHome { edge: Edge::Left, .. }
        ));
        assert_eq!(router.active_remote(), None);
    }

    #[test]
    fn opposite_edges_mirror() {
        assert_eq!(Edge::Left.opposite(), Edge::Right);
        assert_eq!(Edge::Right.opposite(), Edge::Left);
        assert_eq!(Edge::Top.opposite(), Edge::Bottom);
        assert_eq!(Edge::Bottom.opposite(), Edge::Top);
    }

    #[test]
    fn double_edge_opens_both_horizontal_edges_to_the_lone_peer() {
        // Two-machine link, peer on the right: Single crosses right only;
        // Double additionally crosses the left outer edge. Top/bottom
        // clamp in both modes.
        let layout = Layout::pair_default("me", "peer", &"ab".repeat(32));
        let mut single = EdgeRouter::new(layout.clone()).unwrap();
        assert!(matches!(
            single.route(InputEvent::MouseMove { dx: -5000, dy: 0 }),
            RoutedEvent::Local(_)
        ));
        let mut double = EdgeRouter::new(layout).unwrap();
        double.set_edge_mode(EdgeMode::Double);
        let handoff = double.route(InputEvent::MouseMove { dx: -5000, dy: 0 });
        assert!(matches!(
            handoff,
            RoutedEvent::Handoff {
                target,
                edge: Edge::Left,
                target_x: 1919,
                ..
            } if target == FIRST_PEER_SCREEN_ID
        ));
        // The stateless receiver hop agrees, per mode.
        let layout2 = Layout::pair_default("me", "peer", &"ab".repeat(32));
        assert!(layout2
            .handoff_for_motion(SELF_SCREEN_ID, 0, 540, -50, 0, EdgeMode::Single)
            .is_none());
        let hop = layout2
            .handoff_for_motion(SELF_SCREEN_ID, 0, 540, -50, 0, EdgeMode::Double)
            .expect("double mode must hand off the outer edge");
        assert_eq!(hop.target, FIRST_PEER_SCREEN_ID);
        assert_eq!(hop.target_x, 1919);
        // Top and bottom never cross implicitly, even doubled.
        assert!(layout2
            .handoff_for_motion(SELF_SCREEN_ID, 960, 0, 0, -50, EdgeMode::Double)
            .is_none());
        // Grids stay facing-only in Double mode: the third screen owns
        // the left edge, so no fallback fires there.
        let mut grid = Layout::pair_default("me", "peer", &"ab".repeat(32));
        grid.screens.push(Screen {
            id: ScreenId(9),
            name: "third".into(),
            x: -1,
            y: 0,
            width: 1920,
            height: 1080,
            peer_fingerprint: Some("ff".repeat(32)),
        });
        let mut grid_router = EdgeRouter::new(grid).unwrap();
        grid_router.set_edge_mode(EdgeMode::Double);
        let routed = grid_router.route(InputEvent::MouseMove { dx: -5000, dy: 0 });
        assert!(matches!(
            routed,
            RoutedEvent::Handoff { target, .. } if target == ScreenId(9)
        ));
    }

    #[test]
    fn grid_far_edge_clamps_without_returning() {
        // Three in a row: driving the middle screen, its far edge stops
        // at the border and keeps driving (no automatic third hop).
        let mut layout = Layout::pair_default("me", "peer", &"ab".repeat(32));
        layout.screens.push(Screen {
            id: ScreenId(9),
            name: "third".into(),
            x: 2,
            y: 0,
            width: 1920,
            height: 1080,
            peer_fingerprint: Some("ff".repeat(32)),
        });
        let mut router = EdgeRouter::new(layout).unwrap();
        let _ = router.route(InputEvent::MouseMove { dx: 5000, dy: 0 });
        assert_eq!(router.active_remote(), Some(FIRST_PEER_SCREEN_ID));
        let pushed = router.route(InputEvent::MouseMove { dx: 5000, dy: 0 });
        assert!(matches!(pushed, RoutedEvent::Forward { .. }));
        assert_eq!(router.active_remote(), Some(FIRST_PEER_SCREEN_ID));
        assert_eq!(router.cursor_position(), (1919, 540));
    }

    #[test]
    fn restores_saved_local_position_when_remote_handoff_fails() {        let layout = Layout {
            screens: vec![screen(1, "main", 0, 0), screen(2, "right", 1, 0)],
            self_screen: Some(ScreenId(1)),
        };
        let mut router = EdgeRouter::new(layout).unwrap();
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 200, dy: 0 }),
            RoutedEvent::Local(InputEvent::MouseMove { .. })
        ));
        let saved = router.cursor_position();
        assert!(matches!(
            router.route(InputEvent::MouseMove { dx: 2000, dy: 0 }),
            RoutedEvent::Handoff {
                target: ScreenId(2),
                ..
            }
        ));
        assert_eq!(router.local_cursor_position(), saved);
        assert_eq!(router.restore_local(ScreenId(2)).unwrap(), saved);
        assert_eq!(router.cursor_position(), saved);
        assert_eq!(router.active_remote(), None);
    }

    #[test]
    fn pair_default_puts_machine1_left_with_one_exit_edge() {
        let layout = Layout::pair_default("laptop", "mint", &"ab".repeat(32));
        assert_eq!(layout.validate(), Ok(()));
        assert_eq!(layout.self_screen, Some(SELF_SCREEN_ID));
        assert_eq!(layout.peer_exit_edge(), Some(Edge::Right));
        // Facing edges agree across the pair: A pushes right into B.
        let handoff = layout
            .handoff_for_motion(SELF_SCREEN_ID, 1919, 540, 50, 0, EdgeMode::Single)
            .expect("right edge must hand off");
        assert_eq!(handoff.target, FIRST_PEER_SCREEN_ID);
        assert_eq!(handoff.target_x, 0);
        // No grid neighbour on the outer edge — and a single-peer link no
        // longer crosses there either (strict facing edges only).
        assert_eq!(layout.neighbor_for_edge(SELF_SCREEN_ID, Edge::Left), None);
        assert_eq!(layout.edge_target(SELF_SCREEN_ID, Edge::Left), None);
    }

    #[test]
    fn both_sides_number_themselves_one_and_route_by_name() {
        // The deterministic convention: both machines are self=1, peer=2.
        // Handoffs name the device, so the numbering never has to agree —
        // this is what the old mirror heuristic (self=2 on one side, dealt
        // by a peer-book race) broke in both directions at once.
        let laptop = Layout::pair_default("laptop", "mint", &"cd".repeat(32));
        let mint = Layout::pair_default("mint", "laptop", &"ef".repeat(32));
        assert_eq!(laptop.self_screen, Some(SELF_SCREEN_ID));
        assert_eq!(mint.self_screen, Some(SELF_SCREEN_ID));
        assert_eq!(laptop.screen_by_name("mint").map(|s| s.id), Some(FIRST_PEER_SCREEN_ID));
        assert_eq!(mint.screen_by_name("laptop").map(|s| s.id), Some(FIRST_PEER_SCREEN_ID));
        // Fresh defaults face right on both sides (the dialer keeps this;
        // the station mirrors to the left on first inbound).
        assert_eq!(laptop.peer_exit_edge(), Some(Edge::Right));
        assert_eq!(mint.peer_exit_edge(), Some(Edge::Right));
    }

    #[test]
    fn screens_resolve_by_device_name_for_handoff_routing() {
        let fp = "ee".repeat(32);
        let layout = Layout::pair_default("me", "peer", &fp);
        assert_eq!(layout.screen_by_name("me").map(|s| s.id), Some(SELF_SCREEN_ID));
        assert_eq!(
            layout.screen_by_name("peer").and_then(|s| s.peer_fingerprint.clone()),
            Some(fp)
        );
        assert!(layout.screen_by_name("stranger").is_none());
    }

    #[test]
    fn place_peer_moves_exit_edge_and_refuses_collisions() {
        let fp = &"cd".repeat(32);
        let mut layout = Layout::pair_default("a", "b", fp);
        layout.place_peer(fp, Edge::Top).expect("top must be free");
        assert_eq!(layout.validate(), Ok(()));
        assert_eq!(layout.peer_exit_edge(), Some(Edge::Top));
        layout.place_peer(fp, Edge::Right).expect("right must be free");
        assert_eq!(layout.peer_exit_edge(), Some(Edge::Right));

        // A third screen on the left blocks moving the peer there.
        layout.screens.push(Screen {
            id: ScreenId(9),
            name: "third".into(),
            x: -1,
            y: 0,
            width: 1920,
            height: 1080,
            peer_fingerprint: None,
        });
        assert!(layout.place_peer(fp, Edge::Left).is_err());
        // An unknown fingerprint cannot be placed.
        assert!(layout.place_peer(&"ff".repeat(32), Edge::Left).is_err());
        // And a layout without a peer screen cannot place one.
        layout
            .screens
            .retain(|screen| screen.peer_fingerprint.is_none());
        assert!(layout.place_peer(fp, Edge::Left).is_err());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edge {
    Left,
    Right,
    Top,
    Bottom,
}

impl Edge {
    /// The edge facing the opposite direction: exiting locally through
    /// Left enters the peer through its Right edge, and vice versa.
    pub fn opposite(self) -> Edge {
        match self {
            Edge::Left => Edge::Right,
            Edge::Right => Edge::Left,
            Edge::Top => Edge::Bottom,
            Edge::Bottom => Edge::Top,
        }
    }
}

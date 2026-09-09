use crate::InputEvent;
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
    /// two-machine link). Single-peer links are double-edged: pushing past
    /// ANY edge hands control to the peer, so a link works with zero
    /// arrangement fuss and a stale arrangement can never strand the
    /// cursor. Multi-screen grids keep strict facing edges.
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

    /// Edge target with the single-peer fallback: a grid neighbour wins;
    /// otherwise, on a two-machine link, the lone peer takes ANY edge.
    pub fn edge_target(&self, me: ScreenId, edge: Edge) -> Option<ScreenId> {
        if let Some(neighbour) = self.neighbor_for_edge(me, edge) {
            return Some(neighbour);
        }
        let peer = self.single_peer_screen()?;
        if peer == me {
            return None;
        }
        Some(peer)
    }
    pub fn screen(&self, id: ScreenId) -> Option<&Screen> {
        self.screens.iter().find(|screen| screen.id == id)
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
    /// (0,0), the peer at (1,0). Every machine writes this same shape —
    /// self=1, peer=2 — because handoffs travel by device name and numbers
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
    /// (Display helper for icons and texts; the router itself crosses ANY
    /// edge on single-peer links — see [`Layout::edge_target`].)
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
        let target = self.edge_target(screen_id, edge)?;
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
    /// Deskflow-style screen lock (ScrollLock): while set, no edge crossing
    /// opens a new handoff — the cursor stays where it is. Locking never
    /// strands control remotely: engaging it returns home first (see the
    /// daemon handoff arm), so the lock always means "held locally".
    locked: bool,
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
            locked: false,
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
    pub fn set_local_cursor_position(&mut self, x: u32, y: u32) -> Result<(), String> {
        if self.active_remote.is_some() {
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
        Ok(())
    }

    pub fn route(&mut self, event: InputEvent) -> RoutedEvent {
        if let Some(target) = self.active_remote {
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
            return RoutedEvent::Local(event);
        };
        // Locked screens never open a handoff: clamp like an unlinked edge
        // so local window controls stay reachable.
        if self.locked {
            return self.clamp_to_edge(next_x, next_y, screen.width, screen.height);
        }
        let Some(target) = self.layout.edge_target(self.current_screen, edge) else {
            return self.clamp_to_edge(next_x, next_y, screen.width, screen.height);
        };
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
        Ok(true)
    }
}

fn map_coordinate(value: u32, source_span: u32, target_span: u32) -> u32 {
    if source_span <= 1 || target_span <= 1 {
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
    fn next_screen_id_never_collides() {
        let paired = Layout::pair_default("me", "peer", &"ab".repeat(32));
        assert_eq!(paired.next_screen_id(), ScreenId(3));
        assert_eq!(Layout::default().next_screen_id(), ScreenId(1));
    }

    #[test]
    fn double_edge_exit_on_single_peer_links() {        // Machine 1: peer on the right, but the LEFT (outer) edge must also
        // cross on a two-machine link.
        let layout = Layout::pair_default("me", "peer", &"ab".repeat(32));
        assert_eq!(
            layout.edge_target(SELF_SCREEN_ID, Edge::Left),
            Some(FIRST_PEER_SCREEN_ID)
        );
        assert_eq!(
            layout.edge_target(SELF_SCREEN_ID, Edge::Top),
            Some(FIRST_PEER_SCREEN_ID)
        );
        assert_eq!(
            layout.edge_target(SELF_SCREEN_ID, Edge::Bottom),
            Some(FIRST_PEER_SCREEN_ID)
        );
        // The receiver side agrees: any motion out of its screen hops back.
        let back = layout
            .handoff_for_motion(SELF_SCREEN_ID, 0, 540, -50, 0)
            .expect("outer edge must hand off on a single-peer link");
        assert_eq!(back.target, FIRST_PEER_SCREEN_ID);
        // Grids keep strict facing edges: no fallback past real neighbours.
        let mut grid = layout.clone();
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
            .handoff_for_motion(SELF_SCREEN_ID, 1919, 540, 50, 0)
            .expect("right edge must hand off");
        assert_eq!(handoff.target, FIRST_PEER_SCREEN_ID);
        assert_eq!(handoff.target_x, 0);
        // No grid neighbour on the outer edge — but edge_target still
        // crosses there on a single-peer link (double edge exit).
        assert_eq!(layout.neighbor_for_edge(SELF_SCREEN_ID, Edge::Left), None);
        assert_eq!(
            layout.edge_target(SELF_SCREEN_ID, Edge::Left),
            Some(FIRST_PEER_SCREEN_ID)
        );
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

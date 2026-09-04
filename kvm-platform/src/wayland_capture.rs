//! Portal/libei input capture for logged-in Wayland sessions.
//!
//! Wayland deliberately prevents ordinary applications from globally reading
//! keyboard and pointer events. The xdg-desktop-portal input-capture protocol
//! is the compositor-mediated path intended for applications such as KVM and
//! remote-desktop tools. `input-capture` owns the portal/libei async state
//! machine; this module adapts its stream to TheKVM's blocking capture trait.
//!
//! This backend is used for topology sessions. It installs barriers on all
//! four edges and forwards events after a barrier is activated; the daemon's
//! existing relative-motion router then chooses the configured neighbor. A
//! separate release command returns control when that edge has no neighbor.

use crate::{capture::CaptureBackend, PlatformError};
use futures::StreamExt;
use input_capture::{Backend, CaptureEvent, InputCapture, Position};
use input_event::{Event, KeyboardEvent, PointerEvent};
use kvm_core::{InputEvent, KeyEvent, MouseButton, WheelDelta};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tokio::runtime::Builder;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::task::LocalSet;

const INITIALIZATION_TIMEOUT: Duration = Duration::from_secs(10);
const EVENT_POLL_TIMEOUT: Duration = Duration::from_millis(100);
const SCROLL_UNIT: f64 = 120.0;

enum Command {
    SetExclusive(bool),
    Release,
    Shutdown,
}

/// A synchronous adapter around the async xdg-desktop-portal/libei backend.
pub struct WaylandCapture {
    receiver: Receiver<InputEvent>,
    commands: UnboundedSender<Command>,
    worker: Option<JoinHandle<()>>,
    exclusive: bool,
}

impl WaylandCapture {
    /// Start a portal capture session and install barriers for all screen
    /// edges. Creation is synchronous so callers can cleanly fall back to
    /// evdev when no compatible portal/compositor is available.
    pub fn create(
        initial_exclusive: bool,
        capture_when_inactive: bool,
    ) -> Result<Self, PlatformError> {
        let (event_tx, receiver) = mpsc::channel();
        let (commands, command_rx) = tokio::sync::mpsc::unbounded_channel();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);

        let worker = thread::Builder::new()
            .name("thekvm-wayland-input-capture".into())
            .spawn(move || {
                wayland_worker(
                    event_tx,
                    command_rx,
                    ready_tx,
                    initial_exclusive,
                    capture_when_inactive,
                );
            })
            .map_err(|error| {
                PlatformError::Capture(format!("start Wayland capture thread: {error}"))
            })?;

        match ready_rx.recv_timeout(INITIALIZATION_TIMEOUT) {
            Ok(Ok(())) => Ok(Self {
                receiver,
                commands,
                worker: Some(worker),
                exclusive: initial_exclusive,
            }),
            Ok(Err(error)) => {
                let _ = worker.join();
                Err(PlatformError::Capture(error))
            }
            Err(error) => {
                let _ = worker.join();
                Err(PlatformError::Capture(format!(
                    "Wayland input capture initialization timed out: {error}"
                )))
            }
        }
    }
}

impl CaptureBackend for WaylandCapture {
    fn next_event(
        &mut self,
        stop: &AtomicBool,
        exclusive: &AtomicBool,
        release: &AtomicBool,
    ) -> Result<InputEvent, PlatformError> {
        loop {
            if stop.load(Ordering::Acquire) {
                return Err(PlatformError::Capture("capture stopped".into()));
            }
            if release.swap(false, Ordering::AcqRel) {
                self.release()?;
            }
            let desired_exclusive = exclusive.load(Ordering::Acquire);
            if desired_exclusive != self.exclusive {
                self.set_exclusive(desired_exclusive)?;
            }
            match self.receiver.recv_timeout(EVENT_POLL_TIMEOUT) {
                Ok(event) => return Ok(event),
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(PlatformError::Capture(
                        "Wayland input capture stopped".into(),
                    ));
                }
            }
        }
    }

    fn set_exclusive(&mut self, exclusive: bool) -> Result<(), PlatformError> {
        self.commands
            .send(Command::SetExclusive(exclusive))
            .map_err(|_| PlatformError::Capture("Wayland capture worker stopped".into()))?;
        self.exclusive = exclusive;
        Ok(())
    }

    fn release(&mut self) -> Result<(), PlatformError> {
        self.commands
            .send(Command::Release)
            .map_err(|_| PlatformError::Capture("Wayland capture worker stopped".into()))
    }
}

impl Drop for WaylandCapture {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Shutdown);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn wayland_worker(
    event_tx: Sender<InputEvent>,
    command_rx: UnboundedReceiver<Command>,
    ready_tx: SyncSender<Result<(), String>>,
    initial_exclusive: bool,
    capture_when_inactive: bool,
) {
    let runtime = match Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = ready_tx.send(Err(format!("create Wayland async runtime: {error}")));
            return;
        }
    };
    let local_set = LocalSet::new();
    let result = local_set.block_on(
        &runtime,
        run_wayland_capture(
            event_tx,
            command_rx,
            ready_tx,
            initial_exclusive,
            capture_when_inactive,
        ),
    );
    if let Err(error) = result {
        tracing::debug!(%error, "Wayland/libei capture worker exited");
    }
}

async fn run_wayland_capture(
    event_tx: Sender<InputEvent>,
    mut command_rx: UnboundedReceiver<Command>,
    ready_tx: SyncSender<Result<(), String>>,
    initial_exclusive: bool,
    capture_when_inactive: bool,
) -> Result<(), String> {
    let mut capture = match InputCapture::new(Some(Backend::InputCapturePortal)).await {
        Ok(capture) => capture,
        Err(error) => {
            let message = format!("create input-capture portal session: {error}");
            let _ = ready_tx.send(Err(message.clone()));
            return Err(message);
        }
    };

    for (handle, position) in [
        (1, Position::Left),
        (2, Position::Right),
        (3, Position::Top),
        (4, Position::Bottom),
    ] {
        if let Err(error) = capture.create(handle, position).await {
            let message = format!("install {position} Wayland capture barrier: {error}");
            let _ = capture.terminate().await;
            let _ = ready_tx.send(Err(message.clone()));
            return Err(message);
        }
    }

    if ready_tx.send(Ok(())).is_err() {
        let _ = capture.terminate().await;
        return Ok(());
    }

    let mut exclusive = initial_exclusive;
    let mut accumulator = EventAccumulator::default();
    let result = loop {
        tokio::select! {
            command = command_rx.recv() => match command {
                Some(Command::SetExclusive(enabled)) => {
                    exclusive = enabled;
                    // Releasing a portal capture is the compositor-safe way
                    // to return control locally. The next barrier crossing
                    // can activate it again when the peer becomes available.
                    if !enabled {
                        capture.release().await.map_err(|error| format!("release Wayland capture: {error}"))?;
                    }
                }
                Some(Command::Release) => {
                    capture.release().await.map_err(|error| format!("release Wayland capture: {error}"))?;
                }
                Some(Command::Shutdown) | None => break Ok(()),
            },
            event = capture.next() => match event {
                Some(Ok((_handle, CaptureEvent::Begin))) => {
                    if !exclusive && !capture_when_inactive {
                        capture.release().await.map_err(|error| format!("release inactive Wayland capture: {error}"))?;
                    }
                }
                Some(Ok((_handle, CaptureEvent::Input(event))))
                    if exclusive || capture_when_inactive => {
                    if let Some(event) = translate_event(event, &mut accumulator) {
                        if event_tx.send(event).is_err() {
                            break Ok(());
                        }
                    }
                }
                Some(Ok((_handle, CaptureEvent::Input(_)))) => {}
                Some(Err(error)) => break Err(format!("Wayland input capture: {error}")),
                None => break Err("Wayland input capture stream closed".into()),
            },
        }
    };

    if let Err(error) = capture.terminate().await {
        return result.and_then(|()| Err(format!("terminate Wayland capture: {error}")));
    }
    result
}

#[derive(Default)]
struct EventAccumulator {
    motion_x: f64,
    motion_y: f64,
    wheel_x: f64,
    wheel_y: f64,
}

fn translate_event(event: Event, accumulator: &mut EventAccumulator) -> Option<InputEvent> {
    match event {
        Event::Keyboard(KeyboardEvent::Key { key, state, .. }) => {
            let pressed = match state {
                0 => false,
                1 => true,
                _ => return None,
            };
            crate::evdev_capture::hid_from_evdev(key as u16)
                .map(|usage| InputEvent::Key(KeyEvent { usage, pressed }))
        }
        Event::Keyboard(KeyboardEvent::Modifiers { .. }) => None,
        Event::Pointer(PointerEvent::Motion { dx, dy, .. }) => {
            let dx = take_integer(&mut accumulator.motion_x, dx);
            let dy = take_integer(&mut accumulator.motion_y, dy);
            (dx != 0 || dy != 0).then_some(InputEvent::MouseMove { dx, dy })
        }
        Event::Pointer(PointerEvent::Button { button, state, .. }) => {
            mouse_button(button).map(|button| InputEvent::MouseButton {
                button,
                pressed: state != 0,
            })
        }
        Event::Pointer(PointerEvent::Axis { axis, value, .. }) => {
            let value = value / SCROLL_UNIT;
            let (x, y) = match axis {
                0 => (0, take_integer(&mut accumulator.wheel_y, value)),
                1 => (take_integer(&mut accumulator.wheel_x, value), 0),
                _ => return None,
            };
            (x != 0 || y != 0).then_some(InputEvent::Wheel(WheelDelta {
                x: clamp_i16(x),
                y: clamp_i16(y),
            }))
        }
        Event::Pointer(PointerEvent::AxisDiscrete120 { axis, value }) => {
            let value = f64::from(value) / SCROLL_UNIT;
            let (x, y) = match axis {
                0 => (0, take_integer(&mut accumulator.wheel_y, value)),
                1 => (take_integer(&mut accumulator.wheel_x, value), 0),
                _ => return None,
            };
            (x != 0 || y != 0).then_some(InputEvent::Wheel(WheelDelta {
                x: clamp_i16(x),
                y: clamp_i16(y),
            }))
        }
    }
}

fn take_integer(remainder: &mut f64, value: f64) -> i32 {
    if !value.is_finite() {
        return 0;
    }
    let total = (*remainder + value).clamp(-(i32::MAX as f64), i32::MAX as f64);
    let whole = total.trunc();
    *remainder = total - whole;
    whole as i32
}

fn clamp_i16(value: i32) -> i16 {
    value.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16
}

fn mouse_button(button: u32) -> Option<MouseButton> {
    Some(match button {
        input_event::BTN_LEFT => MouseButton::Left,
        input_event::BTN_RIGHT => MouseButton::Right,
        input_event::BTN_MIDDLE => MouseButton::Middle,
        input_event::BTN_BACK => MouseButton::Back,
        input_event::BTN_FORWARD => MouseButton::Forward,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_libei_keyboard_and_buttons_to_hid_events() {
        let mut accumulator = EventAccumulator::default();
        assert_eq!(
            translate_event(
                Event::Keyboard(KeyboardEvent::Key {
                    time: 0,
                    key: 30,
                    state: 1,
                }),
                &mut accumulator,
            ),
            Some(InputEvent::Key(KeyEvent {
                usage: 0x04,
                pressed: true,
            }))
        );
        assert_eq!(
            translate_event(
                Event::Pointer(PointerEvent::Button {
                    time: 0,
                    button: input_event::BTN_LEFT,
                    state: 0,
                }),
                &mut accumulator,
            ),
            Some(InputEvent::MouseButton {
                button: MouseButton::Left,
                pressed: false,
            })
        );
    }

    #[test]
    fn preserves_subpixel_motion_and_scroll_until_a_wire_unit_exists() {
        let mut accumulator = EventAccumulator::default();
        assert_eq!(
            translate_event(
                Event::Pointer(PointerEvent::Motion {
                    time: 0,
                    dx: 0.5,
                    dy: -0.5,
                }),
                &mut accumulator,
            ),
            None
        );
        assert_eq!(
            translate_event(
                Event::Pointer(PointerEvent::Motion {
                    time: 0,
                    dx: 0.5,
                    dy: -0.5,
                }),
                &mut accumulator,
            ),
            Some(InputEvent::MouseMove { dx: 1, dy: -1 })
        );
        assert_eq!(
            translate_event(
                Event::Pointer(PointerEvent::AxisDiscrete120 { axis: 0, value: 60 }),
                &mut accumulator,
            ),
            None
        );
        assert_eq!(
            translate_event(
                Event::Pointer(PointerEvent::AxisDiscrete120 { axis: 0, value: 60 }),
                &mut accumulator,
            ),
            Some(InputEvent::Wheel(WheelDelta { x: 0, y: 1 }))
        );
    }

    #[test]
    fn ignores_key_repeats_modifiers_and_unknown_buttons() {
        let mut accumulator = EventAccumulator::default();
        assert_eq!(
            translate_event(
                Event::Keyboard(KeyboardEvent::Key {
                    time: 0,
                    key: 30,
                    state: 2,
                }),
                &mut accumulator,
            ),
            None
        );
        assert_eq!(
            translate_event(
                Event::Keyboard(KeyboardEvent::Modifiers {
                    depressed: 0,
                    latched: 0,
                    locked: 0,
                    group: 0,
                }),
                &mut accumulator,
            ),
            None
        );
        assert_eq!(
            translate_event(
                Event::Pointer(PointerEvent::Button {
                    time: 0,
                    button: 0x1ff,
                    state: 1,
                }),
                &mut accumulator,
            ),
            None
        );
    }
}

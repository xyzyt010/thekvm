//! Length-delimited application messages carried over QUIC streams.

use kvm_core::{InputEvent, InputPacket, InputState, Mode, WheelDelta};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_FRAME_SIZE: usize = 64 * 1024;
pub const MAX_NODE_NAME_BYTES: usize = 128;
const MAX_REJECT_REASON_BYTES: usize = 1024;
/// Text clipboard synchronization intentionally remains a single bounded
/// message in this first implementation. Large rich/file clipboard payloads
/// belong to the future chunked transfer protocol.
pub const MAX_CLIPBOARD_TEXT_BYTES: usize = 48 * 1024;
/// Keep motion datagrams below the usual QUIC path-MTU budget. Key/button
/// transitions remain on the reliable stream; motion and wheel updates may be
/// dropped when the network is congested.
pub const MAX_DATAGRAM_SIZE: usize = 1200;

const DATAGRAM_MOUSE_MOVE: u8 = 1;
const DATAGRAM_WHEEL: u8 = 2;
const DATAGRAM_VERSION: u8 = 1;
const DATAGRAM_MOUSE_MOVE_SIZE: usize = 1 + 1 + 8 + 4 + 4;
const DATAGRAM_WHEEL_SIZE: usize = 1 + 1 + 8 + 2 + 2;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DatagramInput {
    pub sequence: u64,
    pub event: InputEvent,
}

pub fn encode_input_datagram(packet: DatagramInput) -> std::io::Result<Vec<u8>> {
    // Pointer updates are the hottest part of a KVM session. Keep them
    // deliberately smaller than the reliable JSON control frames so QUIC can
    // carry many updates without allocator or parser overhead. The format is:
    // version (u8), kind (u8), sequence (u64 BE), then signed big-endian
    // event fields. A version byte lets a future receiver reject or migrate
    // a datagram format without guessing from its length.
    let mut payload = Vec::with_capacity(DATAGRAM_MOUSE_MOVE_SIZE);
    payload.extend_from_slice(&[
        DATAGRAM_VERSION,
        match packet.event {
            InputEvent::MouseMove { .. } => DATAGRAM_MOUSE_MOVE,
            InputEvent::Wheel(_) => DATAGRAM_WHEEL,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "only pointer motion and wheel events may use datagrams",
                ))
            }
        },
    ]);
    payload.extend_from_slice(&packet.sequence.to_be_bytes());
    match packet.event {
        InputEvent::MouseMove { dx, dy } => {
            payload.extend_from_slice(&dx.to_be_bytes());
            payload.extend_from_slice(&dy.to_be_bytes());
        }
        InputEvent::Wheel(WheelDelta { x, y }) => {
            payload.extend_from_slice(&x.to_be_bytes());
            payload.extend_from_slice(&y.to_be_bytes());
        }
        _ => unreachable!("event kind was validated above"),
    }
    debug_assert!(payload.len() <= MAX_DATAGRAM_SIZE);
    Ok(payload)
}

pub fn decode_input_datagram(payload: &[u8]) -> std::io::Result<DatagramInput> {
    if payload.len() > MAX_DATAGRAM_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid input datagram size",
        ));
    }
    let version = *payload.first().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "empty input datagram")
    })?;
    if version != DATAGRAM_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported input datagram version",
        ));
    }
    let kind = *payload.get(1).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "missing input datagram kind",
        )
    })?;
    let (expected_size, sequence) = match kind {
        DATAGRAM_MOUSE_MOVE if payload.len() == DATAGRAM_MOUSE_MOVE_SIZE => {
            (DATAGRAM_MOUSE_MOVE_SIZE, read_u64(&payload[2..10]))
        }
        DATAGRAM_WHEEL if payload.len() == DATAGRAM_WHEEL_SIZE => {
            (DATAGRAM_WHEEL_SIZE, read_u64(&payload[2..10]))
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid input datagram kind or size",
            ))
        }
    };
    debug_assert_eq!(payload.len(), expected_size);
    let event = match kind {
        DATAGRAM_MOUSE_MOVE => InputEvent::MouseMove {
            dx: read_i32(&payload[10..14]),
            dy: read_i32(&payload[14..18]),
        },
        DATAGRAM_WHEEL => InputEvent::Wheel(WheelDelta {
            x: read_i16(&payload[10..12]),
            y: read_i16(&payload[12..14]),
        }),
        _ => unreachable!("datagram kind was validated above"),
    };
    Ok(DatagramInput { sequence, event })
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("validated u64 field size"))
}

fn read_i32(bytes: &[u8]) -> i32 {
    i32::from_be_bytes(bytes.try_into().expect("validated i32 field size"))
}

fn read_i16(bytes: &[u8]) -> i16 {
    i16::from_be_bytes(bytes.try_into().expect("validated i16 field size"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScreenGeometry {
    pub screen_id: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub node_name: String,
    pub mode: Mode,
    /// Requests permission to operate while the receiver is locked or at the
    /// login greeter. The receiver must independently enable this locally.
    pub lock_screen_requested: bool,
    /// Negotiates normal logged-in text clipboard synchronization. Both ends
    /// must opt in; this capability is independent of lock-screen input.
    #[serde(default)]
    pub clipboard_enabled: bool,
    /// Logical coordinate space advertised by the sending desktop. This is
    /// optional so older peers can still establish an input session.
    #[serde(default)]
    pub screen_geometry: Option<ScreenGeometry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WireMessage {
    Hello(Hello),
    PairRequest {
        node_name: String,
        fingerprint_hex: String,
    },
    PairChallenge {
        node_name: String,
        fingerprint_hex: String,
        /// Six-digit numeric-comparison code the initiating side can verify
        /// against its own derivation of the same two fingerprints. Absent
        /// when the peer predates this field; present peers must agree.
        #[serde(default)]
        verification_code: Option<String>,
    },
    PairConfirm {
        server_fingerprint_hex: String,
    },
    Accepted {
        lock_screen_enabled: bool,
        #[serde(default)]
        clipboard_enabled: bool,
        /// Logical coordinate space used by this receiver's local screen.
        #[serde(default)]
        screen_geometry: Option<ScreenGeometry>,
    },
    Input(InputPacket),
    /// Reliable sender state snapshot, sent before the first event on every
    /// newly established input session.
    StateSync(InputState),
    /// Bounded plain-text clipboard update for normal logged-in sessions.
    ClipboardText {
        revision: u64,
        text: String,
    },
    ReleaseAll,
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    /// Establish the logical pointer position when control crosses a screen
    /// edge. The receiver may use this for a future absolute-pointer backend;
    /// relative input remains the authoritative event stream in this slice.
    PointerHandoff {
        screen_id: u32,
        x: u32,
        y: u32,
        /// Coordinate space in which x/y were calculated. The receiver maps
        /// it to its own configured screen when the dimensions differ.
        #[serde(default)]
        screen_geometry: Option<ScreenGeometry>,
    },
    /// Ask the controller to activate the screen reached from the receiver's
    /// edge. The controller may return locally when this is its self screen.
    HandoffRequest {
        screen_id: u32,
        x: u32,
        y: u32,
        /// Relative motion that crossed the edge, to be applied after the
        /// next peer establishes the target cursor position.
        #[serde(default)]
        dx: i32,
        #[serde(default)]
        dy: i32,
        /// Coordinate space in which x/y were calculated. The controller maps
        /// it to its own configured screen when the dimensions differ.
        #[serde(default)]
        screen_geometry: Option<ScreenGeometry>,
    },
    Reject {
        reason: String,
    },
}

pub async fn write_frame<W>(writer: &mut W, message: &WireMessage) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    validate_message(message)?;
    let payload = serde_json::to_vec(message)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if payload.len() > MAX_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "wire message exceeds maximum frame size",
        ));
    }
    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(&payload).await?;
    writer.flush().await
}

pub fn validate_message(message: &WireMessage) -> std::io::Result<()> {
    let geometry = match message {
        WireMessage::Hello(hello) => {
            validate_node_name(&hello.node_name)?;
            hello.screen_geometry.as_ref()
        }
        WireMessage::Accepted {
            screen_geometry, ..
        }
        | WireMessage::PointerHandoff {
            screen_geometry, ..
        }
        | WireMessage::HandoffRequest {
            screen_geometry, ..
        } => screen_geometry.as_ref(),
        WireMessage::PairRequest {
            node_name,
            fingerprint_hex,
        } => {
            validate_node_name(node_name)?;
            validate_fingerprint(fingerprint_hex)?;
            None
        }
        WireMessage::PairChallenge {
            node_name,
            fingerprint_hex,
            verification_code,
        } => {
            validate_node_name(node_name)?;
            validate_fingerprint(fingerprint_hex)?;
            if let Some(code) = verification_code {
                if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "pairing verification code must contain exactly six digits",
                    ));
                }
            }
            None
        }
        WireMessage::PairConfirm {
            server_fingerprint_hex,
        } => {
            validate_fingerprint(server_fingerprint_hex)?;
            None
        }
        WireMessage::Reject { reason } => {
            if reason.len() > MAX_REJECT_REASON_BYTES || reason.chars().any(char::is_control) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "rejection reason is empty, too long, or contains control characters",
                ));
            }
            None
        }
        _ => None,
    };
    if let Some(geometry) = geometry {
        if geometry.width == 0 || geometry.height == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "screen geometry cannot have zero width or height",
            ));
        }
        if geometry.width > 1_000_000 || geometry.height > 1_000_000 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "screen geometry exceeds maximum dimension",
            ));
        }
    }
    if let WireMessage::ClipboardText { text, .. } = message {
        if text.len() > MAX_CLIPBOARD_TEXT_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "clipboard text exceeds maximum size",
            ));
        }
    }
    Ok(())
}

fn validate_node_name(name: &str) -> std::io::Result<()> {
    if name.trim().is_empty()
        || name.len() > MAX_NODE_NAME_BYTES
        || name.chars().any(char::is_control)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "node name is empty, too long, or contains control characters",
        ));
    }
    Ok(())
}

fn validate_fingerprint(fingerprint: &str) -> std::io::Result<()> {
    if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "fingerprint must contain 64 hexadecimal characters",
        ));
    }
    Ok(())
}

pub async fn read_frame<R>(reader: &mut R) -> std::io::Result<Option<WireMessage>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > MAX_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid wire frame size: {size}"),
        ));
    }
    let mut payload = vec![0u8; size];
    reader.read_exact(&mut payload).await?;
    let message = serde_json::from_slice::<WireMessage>(&payload)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    validate_message(&message)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    Ok(Some(message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_core::{InputEvent, InputState, KeyEvent, MouseButton};

    #[tokio::test]
    async fn frames_are_length_delimited() {
        let (mut left, mut right) = tokio::io::duplex(1024);
        let expected = WireMessage::Input(InputPacket {
            sequence: 7,
            event: InputEvent::Key(KeyEvent {
                usage: 0x04,
                pressed: true,
            }),
        });
        let sender = tokio::spawn(async move {
            write_frame(&mut left, &expected).await.unwrap();
        });
        let actual = read_frame(&mut right).await.unwrap().unwrap();
        sender.await.unwrap();
        assert!(matches!(actual, WireMessage::Input(packet) if packet.sequence == 7));
    }

    #[tokio::test]
    async fn state_sync_is_reliable_and_preserves_held_controls() {
        let (mut left, mut right) = tokio::io::duplex(2048);
        let expected = WireMessage::StateSync(InputState {
            pressed_keys: vec![0xe0, 0x04],
            pressed_buttons: vec![MouseButton::Left],
        });
        let sender = tokio::spawn(async move {
            write_frame(&mut left, &expected).await.unwrap();
        });
        let actual = read_frame(&mut right).await.unwrap().unwrap();
        sender.await.unwrap();
        assert!(
            matches!(actual, WireMessage::StateSync(state) if state.pressed_keys == vec![0xe0, 0x04] && state.pressed_buttons == vec![MouseButton::Left])
        );
    }

    #[tokio::test]
    async fn rejects_oversized_clipboard_frames_before_writing() {
        let (mut left, _right) = tokio::io::duplex(1024);
        let message = WireMessage::ClipboardText {
            revision: 1,
            text: "x".repeat(MAX_CLIPBOARD_TEXT_BYTES + 1),
        };
        assert!(write_frame(&mut left, &message).await.is_err());
    }

    #[tokio::test]
    async fn clipboard_frames_preserve_revision_and_unicode_text() {
        let (mut left, mut right) = tokio::io::duplex(1024);
        let expected = WireMessage::ClipboardText {
            revision: 42,
            text: "TheKVM — साझा clipboard".into(),
        };
        let sender = tokio::spawn(async move {
            write_frame(&mut left, &expected).await.unwrap();
        });
        let actual = read_frame(&mut right).await.unwrap().unwrap();
        sender.await.unwrap();
        assert!(matches!(
            actual,
            WireMessage::ClipboardText { revision: 42, text } if text == "TheKVM — साझा clipboard"
        ));
    }

    #[test]
    fn clipboard_capability_defaults_for_older_hello_and_acceptance_frames() {
        let hello: WireMessage = serde_json::from_str(
            r#"{"Hello":{"node_name":"legacy","mode":"Bidirectional","lock_screen_requested":false}}"#,
        )
        .unwrap();
        assert!(matches!(
            hello,
            WireMessage::Hello(Hello {
                clipboard_enabled: false,
                ..
            })
        ));

        let accepted: WireMessage =
            serde_json::from_str(r#"{"Accepted":{"lock_screen_enabled":false}}"#).unwrap();
        assert!(matches!(
            accepted,
            WireMessage::Accepted {
                clipboard_enabled: false,
                ..
            }
        ));
    }

    #[test]
    fn geometry_capability_defaults_for_older_session_frames() {
        let hello: WireMessage = serde_json::from_str(
            r#"{"Hello":{"node_name":"legacy","mode":"Bidirectional","lock_screen_requested":false,"clipboard_enabled":false}}"#,
        )
        .unwrap();
        assert!(matches!(
            hello,
            WireMessage::Hello(Hello {
                screen_geometry: None,
                ..
            })
        ));

        let accepted: WireMessage =
            serde_json::from_str(r#"{"Accepted":{"lock_screen_enabled":false}}"#).unwrap();
        assert!(matches!(
            accepted,
            WireMessage::Accepted {
                screen_geometry: None,
                ..
            }
        ));
    }

    #[test]
    fn invalid_geometry_is_rejected_before_transport() {
        assert!(validate_message(&WireMessage::Hello(Hello {
            node_name: "node".into(),
            mode: Mode::Bidirectional,
            lock_screen_requested: false,
            clipboard_enabled: false,
            screen_geometry: Some(ScreenGeometry {
                screen_id: 1,
                width: 0,
                height: 1080,
            }),
        }))
        .is_err());
    }

    #[test]
    fn rejects_untrusted_protocol_identity_strings() {
        assert!(validate_message(&WireMessage::Hello(Hello {
            node_name: "bad\nname".into(),
            mode: Mode::Bidirectional,
            lock_screen_requested: false,
            clipboard_enabled: false,
            screen_geometry: None,
        }))
        .is_err());
        assert!(validate_message(&WireMessage::PairRequest {
            node_name: "node".into(),
            fingerprint_hex: "not-a-fingerprint".into(),
        })
        .is_err());
        assert!(validate_message(&WireMessage::Reject {
            reason: "bad\rmessage".into(),
        })
        .is_err());
        assert!(validate_message(&WireMessage::PairConfirm {
            server_fingerprint_hex: "ab".repeat(32),
        })
        .is_ok());
    }

    #[test]
    fn pair_challenge_verification_code_round_trips_and_validates() {
        let challenge = WireMessage::PairChallenge {
            node_name: "receiver".into(),
            fingerprint_hex: "cd".repeat(32),
            verification_code: Some("123456".into()),
        };
        assert!(validate_message(&challenge).is_ok());
        let encoded = serde_json::to_vec(&challenge).unwrap();
        let decoded: WireMessage = serde_json::from_slice(&encoded).unwrap();
        assert!(matches!(
            &decoded,
            WireMessage::PairChallenge { verification_code: Some(code), .. } if code == "123456"
        ));

        assert!(validate_message(&WireMessage::PairChallenge {
            node_name: "receiver".into(),
            fingerprint_hex: "cd".repeat(32),
            verification_code: Some("12a456".into()),
        })
        .is_err());
        assert!(validate_message(&WireMessage::PairChallenge {
            node_name: "receiver".into(),
            fingerprint_hex: "cd".repeat(32),
            verification_code: Some("12345".into()),
        })
        .is_err());

        // Legacy peers without the field keep working.
        let legacy: WireMessage = serde_json::from_str(
            r#"{"PairChallenge":{"node_name":"old","fingerprint_hex":"0000000000000000000000000000000000000000000000000000000000000000"}}"#,
        )
        .unwrap();
        assert!(matches!(
            legacy,
            WireMessage::PairChallenge {
                verification_code: None,
                ..
            }
        ));
    }

    #[test]
    fn pointer_datagrams_are_bounded_and_round_trip() {
        let expected = DatagramInput {
            sequence: 9,
            event: InputEvent::MouseMove { dx: 12, dy: -4 },
        };
        let encoded = encode_input_datagram(expected).unwrap();
        assert_eq!(encoded.len(), DATAGRAM_MOUSE_MOVE_SIZE);
        assert_eq!(decode_input_datagram(&encoded).unwrap().sequence, 9);
        assert_eq!(
            decode_input_datagram(&encoded).unwrap().event,
            expected.event
        );
        let wheel = DatagramInput {
            sequence: 10,
            event: InputEvent::Wheel(WheelDelta { x: -2, y: 3 }),
        };
        let wheel_encoded = encode_input_datagram(wheel).unwrap();
        assert_eq!(wheel_encoded.len(), DATAGRAM_WHEEL_SIZE);
        assert_eq!(
            decode_input_datagram(&wheel_encoded).unwrap().event,
            wheel.event
        );
        assert!(encode_input_datagram(DatagramInput {
            sequence: 11,
            event: InputEvent::Key(KeyEvent {
                usage: 0x04,
                pressed: true,
            }),
        })
        .is_err());
        assert!(decode_input_datagram(&[DATAGRAM_MOUSE_MOVE, 0]).is_err());
        assert!(decode_input_datagram(&[99; DATAGRAM_MOUSE_MOVE_SIZE]).is_err());
    }
}

//! Text clipboard access for normal logged-in sessions.
//!
//! Clipboard ownership is inherently session-scoped. This adapter is
//! deliberately separate from the privileged input injector: a system daemon
//! at a greeter may create `/dev/uinput`, but it must not pretend that it can
//! read or modify an arbitrary user's clipboard.

use crate::PlatformError;

/// Cross-platform text clipboard handle. The daemon's user-session agent
/// polls this handle and updates it when a negotiated peer sends new text.
pub struct SystemClipboard {
    clipboard: arboard::Clipboard,
    last_text: Option<String>,
}

impl SystemClipboard {
    pub fn create() -> Result<Self, PlatformError> {
        let clipboard = arboard::Clipboard::new()
            .map_err(|error| PlatformError::Clipboard(format!("open system clipboard: {error}")))?;
        Ok(Self {
            clipboard,
            last_text: None,
        })
    }

    /// Return the current text once when it differs from the last observed
    /// value. A clipboard containing only an image or another non-text format
    /// is ignored; it is not an error for synchronization purposes.
    pub fn poll_changed(&mut self) -> Result<Option<String>, PlatformError> {
        let text = match self.clipboard.get_text() {
            Ok(text) => text,
            Err(_) => return Ok(None),
        };
        if self.last_text.as_deref() == Some(text.as_str()) {
            return Ok(None);
        }
        self.last_text = Some(text.clone());
        Ok(Some(text))
    }

    /// Set text received from a peer and remember it as locally observed so
    /// the polling loop does not immediately echo it back.
    pub fn set_text(&mut self, text: String) -> Result<(), PlatformError> {
        self.clipboard
            .set_text(text.clone())
            .map_err(|error| PlatformError::Clipboard(format!("set system clipboard: {error}")))?;
        self.last_text = Some(text);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn clipboard_module_compiles_for_supported_platforms() {
        // The actual desktop clipboard requires a live user session and is
        // therefore covered by manual/platform acceptance tests.
        let _type_name = std::any::type_name::<super::SystemClipboard>();
    }
}

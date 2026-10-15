//! Clipboard auto-copy (text). arboard primary.
use anyhow::Result;

pub fn copy_text(text: &str) -> Result<()> {
    if text.is_empty() {
        anyhow::bail!("nothing to copy");
    }
    let mut cb = arboard::Clipboard::new()?;
    cb.set_text(text.to_string())?;
    Ok(())
}

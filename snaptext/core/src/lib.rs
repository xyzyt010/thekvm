//! snaptext-core: custom Rust backend. No GUI here.

pub mod catalog;
pub mod capture;
pub mod clipboard;
pub mod device;
pub mod hotkeys;
pub mod ocr;
pub mod overlay;
pub mod pipeline;
pub mod preprocess;
pub mod recommender;
pub mod vlm;

pub use ocr::{OcrBox, OcrResult};

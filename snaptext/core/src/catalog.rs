//! Model catalog: lab accuracy/speed; bench overwrites speed on-device.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelEntry {
    pub id: String,
    pub family: String,
    pub engine: String,
    pub label: String,
    pub min_ram_gb: f64,
    pub min_cores: usize,
    pub arch: Vec<String>,
    pub os: Vec<String>,
    pub accuracy_gui: f64,
    pub speed_ms_ref: u64,
    pub notes: String,
}

const CATALOG_JSON: &str = include_str!("models_catalog.json");

pub fn load() -> Vec<ModelEntry> {
    let v: serde_json::Value =
        serde_json::from_str(CATALOG_JSON).expect("embedded catalog valid");
    serde_json::from_value(v["models"].clone()).expect("models array valid")
}

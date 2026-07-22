//! Dynamic payload deserialization
//!
//! This module provides utilities to deserialize PublicOutput payloads.
//! All zk programs output payloads as simple strings with key:value format,
//! which makes deserialization straightforward - we just deserialize into PublicOutput.

use serde_json::Value;
use zeenome_core::{errors::Result, zk::deserialize_public_output_bincode};

/// Decode SP1 `execute()` output bytes (guest `PublicOutput` bincode) into the same JSON shape as
/// [`deserialize_public_output`] uses for proof `public_values`.
pub fn deserialize_public_output_from_execute_bytes(public_values_bytes: &[u8]) -> Result<Value> {
    deserialize_public_output("", public_values_bytes)
}

/// Deserialize PublicOutput with string payload type
/// All zk programs output payloads as simple strings with key:value pairs
/// separated by newlines. This avoids bincode's limitation with serde_json::Value
/// and makes deserialization universal for all program types.
pub fn deserialize_public_output(
    _bundle_id: &str,
    public_values_bytes: &[u8],
) -> Result<serde_json::Value> {
    let output = deserialize_public_output_bincode(public_values_bytes).map_err(|e| {
        zeenome_core::errors::ZeenomeError::InvalidFormat(format!(
            "Failed to deserialize public output: {}",
            e
        ))
    })?;

    // Parse the string payload into a JSON object
    // Format: key:value\nkey:value\n...
    let mut payload_obj = serde_json::Map::new();
    for line in output.payload.lines() {
        if let Some((key, value)) = line.split_once(':') {
            // Try to parse as number, otherwise keep as string
            let json_value = if let Ok(num) = value.parse::<f64>() {
                Value::Number(
                    serde_json::Number::from_f64(num).unwrap_or(serde_json::Number::from(0)),
                )
            } else if let Ok(num) = value.parse::<i64>() {
                Value::Number(serde_json::Number::from(num))
            } else {
                Value::String(value.to_string())
            };
            payload_obj.insert(key.to_string(), json_value);
        }
    }

    Ok(serde_json::json!({
        "policy": {
            "whitelist_registry_root": output.policy.whitelist_registry_root,
            "job_id": output.policy.job_id,
        },
        "nullifier": output.nullifier,
        "payload": payload_obj,
    }))
}

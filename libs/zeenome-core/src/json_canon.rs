//! RFC 8785 JSON canonicalization and path-indexed Merkle leaf helpers.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json_canonicalizer::to_string as jcs_to_string;

use crate::errors::{Result, ZeenomeError};

/// Zeenome JSON Path leaf prefix (v1).
pub const LEAF_PREFIX_V1: &str = "ZJP1";

/// A single attested scalar at a JSON Pointer path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsonPathLeaf {
    pub pointer: String,
    pub jcs_value: String,
}

impl JsonPathLeaf {
    /// Merkle leaf preimage for this attested path/value pair.
    pub fn merkle_leaf_preimage(&self) -> String {
        format!(
            "{}|{}|{}",
            LEAF_PREFIX_V1,
            self.pointer,
            self.jcs_value
        )
    }
}

/// Canonical RFC 8785 serialization of a JSON value.
pub fn canonicalize_json(value: &Value) -> Result<String> {
    jcs_to_string(value).map_err(|e| {
        ZeenomeError::InvalidFormat(format!("canonicalize_json failed: {e}"))
    })
}

fn escape_json_pointer_segment(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

fn is_scalar(value: &Value) -> bool {
    matches!(
        value,
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
    )
}

/// Walk a JSON document and collect one leaf per scalar value (RFC 6901 pointers).
/// Leaves are sorted lexicographically by pointer, then by `jcs_value`.
pub fn collect_all_scalar_leaves(doc: &Value) -> Result<Vec<JsonPathLeaf>> {
    let mut leaves = Vec::new();

    fn walk(value: &Value, pointer: &str, leaves: &mut Vec<JsonPathLeaf>) -> Result<()> {
        if is_scalar(value) {
            leaves.push(JsonPathLeaf {
                pointer: pointer.to_string(),
                jcs_value: canonicalize_json(value)?,
            });
            return Ok(());
        }
        match value {
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    walk(item, &format!("{pointer}/{index}"), leaves)?;
                }
            }
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                for key in keys {
                    let segment = escape_json_pointer_segment(key);
                    let child_pointer = if pointer.is_empty() {
                        format!("/{segment}")
                    } else {
                        format!("{pointer}/{segment}")
                    };
                    walk(&map[key], &child_pointer, leaves)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    if !doc.is_object() && !doc.is_array() {
        return Err(ZeenomeError::InvalidFormat(
            "collect_all_scalar_leaves: document root must be an object or array".to_string(),
        ));
    }

    walk(doc, "", &mut leaves)?;

    leaves.sort_by(|a, b| {
        a.pointer
            .cmp(&b.pointer)
            .then_with(|| a.jcs_value.cmp(&b.jcs_value))
    });
    Ok(leaves)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_object_key_order() {
        let input: Value = serde_json::from_str(r#"{"b":1,"a":2}"#).unwrap();
        assert_eq!(
            canonicalize_json(&input).expect("canonicalize"),
            r#"{"a":2,"b":1}"#
        );
    }

    #[test]
    fn collect_scalar_leaves_sorted_by_pointer() {
        let input: Value = serde_json::from_str(
            r#"{
              "id": "pkt-1",
              "subject": { "sex": "UNKNOWN_SEX" }
            }"#,
        )
        .unwrap();
        let leaves = collect_all_scalar_leaves(&input).expect("collect leaves");
        assert_eq!(leaves.len(), 2);
        assert_eq!(leaves[0].pointer, "/id");
        assert_eq!(leaves[1].pointer, "/subject/sex");
        assert_eq!(
            leaves[1].merkle_leaf_preimage(),
            r#"ZJP1|/subject/sex|"UNKNOWN_SEX""#
        );
    }
}

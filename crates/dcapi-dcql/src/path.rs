use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};
use serde_json::Value;
use thiserror::Error;

/// One component of a DCQL claims path pointer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PathElement {
    /// Object key lookup.
    String(String),
    /// Array index lookup.
    Index(u64),
    /// Array wildcard (`null` in the serialized path).
    Wildcard,
}

impl Serialize for PathElement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            PathElement::String(value) => serializer.serialize_str(value),
            PathElement::Index(value) => serializer.serialize_u64(*value),
            PathElement::Wildcard => serializer.serialize_unit(),
        }
    }
}

impl<'de> Deserialize<'de> for PathElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::String(s) => Ok(PathElement::String(s)),
            Value::Number(n) => n
                .as_u64()
                .map(PathElement::Index)
                .ok_or_else(|| D::Error::custom("path index must be a non-negative integer")),
            Value::Null => Ok(PathElement::Wildcard),
            _ => Err(D::Error::custom(
                "path element must be string, non-negative integer, or null",
            )),
        }
    }
}

pub type ClaimsPathPointer = Vec<PathElement>;

/// Claims path processing errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PathError {
    /// Path component was applied to a value of an incompatible type.
    #[error(
        "invalid claims path at segment #{segment_index} ({segment:?}): expected {expected}, found {found}"
    )]
    InvalidType {
        /// 0-based segment index in the path pointer.
        segment_index: usize,
        /// Path segment being applied.
        segment: PathElement,
        /// Expected JSON container type.
        expected: &'static str,
        /// Actual JSON value type.
        found: &'static str,
    },
    /// Path index/lookup did not resolve a value.
    #[error("invalid claims path at segment #{segment_index} ({segment:?}): no value resolved")]
    InvalidIndex {
        /// 0-based segment index in the path pointer.
        segment_index: usize,
        /// Path segment being applied.
        segment: PathElement,
    },
    /// Path pointer is empty.
    #[error("invalid claims path: empty pointer")]
    Empty,
}

/// Select values from a JSON credential using DCQL path semantics.
///
/// This implementation intentionally follows the OpenID4VP processing rules:
/// unresolved object keys or array indices are removed from the current selection,
/// while type mismatches abort processing with an error.
pub fn select_nodes<'a>(
    root: &'a Value,
    path: &ClaimsPathPointer,
) -> Result<Vec<&'a Value>, PathError> {
    if path.is_empty() {
        return Err(PathError::Empty);
    }

    let mut current = vec![root];
    for (segment_index, part) in path.iter().enumerate() {
        let mut next = Vec::new();
        for node in &current {
            match part {
                PathElement::String(key) => match node {
                    Value::Object(map) => {
                        if let Some(child) = map.get(key) {
                            next.push(child);
                        }
                    }
                    _ => {
                        return Err(PathError::InvalidType {
                            segment_index,
                            segment: part.clone(),
                            expected: "object",
                            found: json_type_name(node),
                        });
                    }
                },
                PathElement::Index(index) => match node {
                    Value::Array(arr) => {
                        let idx = *index as usize;
                        if let Some(child) = arr.get(idx) {
                            next.push(child);
                        }
                    }
                    _ => {
                        return Err(PathError::InvalidType {
                            segment_index,
                            segment: part.clone(),
                            expected: "array",
                            found: json_type_name(node),
                        });
                    }
                },
                PathElement::Wildcard => match node {
                    Value::Array(arr) => next.extend(arr.iter()),
                    _ => {
                        return Err(PathError::InvalidType {
                            segment_index,
                            segment: part.clone(),
                            expected: "array",
                            found: json_type_name(node),
                        });
                    }
                },
            }
        }
        if next.is_empty() {
            return Err(PathError::InvalidIndex {
                segment_index,
                segment: part.clone(),
            });
        }
        current = next;
    }

    Ok(current)
}

/// Returns true when `actual` matches `pattern`, honoring wildcard segments.
pub fn path_matches(pattern: &ClaimsPathPointer, actual: &ClaimsPathPointer) -> bool {
    if pattern.len() != actual.len() {
        return false;
    }
    for (pattern_item, actual_item) in pattern.iter().zip(actual.iter()) {
        match pattern_item {
            PathElement::Wildcard => continue,
            _ if pattern_item == actual_item => continue,
            _ => return false,
        }
    }
    true
}

/// Returns true only for valid mdoc claims paths (`[namespace, element_identifier]`).
pub fn is_mdoc_path(path: &ClaimsPathPointer) -> bool {
    if path.len() != 2 {
        return false;
    }
    matches!(path[0], PathElement::String(_)) && matches!(path[1], PathElement::String(_))
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bool_path_element_is_rejected() {
        let parsed: Result<ClaimsPathPointer, _> = serde_json::from_str(r#"["name", true]"#);
        assert!(parsed.is_err());
    }

    #[test]
    fn null_path_element_is_wildcard() {
        let parsed: ClaimsPathPointer = serde_json::from_str(r#"["items", null]"#).unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(matches!(parsed[0], PathElement::String(_)));
        assert!(matches!(parsed[1], PathElement::Wildcard));
    }
}

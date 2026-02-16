use android_credman::CredentialReader;
use dcapi_dcql::{ClaimValue, ClaimsPathPointer, CredentialFormat, CredentialStore, ValueMatch};
use dcapi_matcher::{
    CredentialDescriptor, CredentialDescriptorField, MatcherOptions, MatcherStore, OpenId4VpConfig,
    PROTOCOL_OPENID4VP_V1_SIGNED, PROTOCOL_OPENID4VP_V1_UNSIGNED, dcapi_matcher,
    match_dc_api_request,
};
use serde_json::{Map, Value};
use std::io::Read;

/// Parsed CMWallet credential package.
///
/// The package is a binary envelope with a 4-byte little-endian JSON offset followed by
/// raw assets (icons) and a JSON object. The JSON payload follows the registry structure
/// produced by `PnvTokenRegistry.buildRegistryDatabase`:
///
/// `{"credentials": { "<format>": { "<vct>": [ { ...credential... } ] } } }`
#[derive(Debug, Clone)]
pub struct CmCredentialPackage {
    credentials: Vec<CmCredential>,
}

#[derive(Debug, Clone)]
struct CmCredential {
    id: String,
    format: String,
    vct: Option<String>,
    title: String,
    subtitle: Option<String>,
    disclaimer: Option<String>,
    #[allow(dead_code)]
    verifier_terms_prefix: Option<String>,
    shared_attribute_display_name: Option<String>,
    #[allow(dead_code)]
    iss_allowlist: Option<Vec<String>>,
    claims: Value,
    icon: Option<Vec<u8>>,
}

impl CredentialStore for CmCredentialPackage {
    type CredentialRef = usize;

    fn list_credentials(&self, format: Option<&str>) -> Vec<Self::CredentialRef> {
        self.credentials
            .iter()
            .enumerate()
            .filter(|(_, credential)| format.is_none_or(|requested| credential.format == requested))
            .map(|(idx, _)| idx)
            .collect()
    }

    fn format(&self, cred: &Self::CredentialRef) -> CredentialFormat {
        CredentialFormat::from_query_format(&self.credentials[*cred].format)
    }

    fn has_vct(&self, cred: &Self::CredentialRef, vct: &str) -> bool {
        self.credentials[*cred].vct.as_deref() == Some(vct)
    }

    fn has_claim_path(&self, cred: &Self::CredentialRef, path: &ClaimsPathPointer) -> bool {
        dcapi_dcql::select_nodes(&self.credentials[*cred].claims, path).is_ok()
    }

    fn match_claim_value(
        &self,
        cred: &Self::CredentialRef,
        path: &ClaimsPathPointer,
        expected_values: &[ClaimValue],
    ) -> ValueMatch {
        let Ok(nodes) = dcapi_dcql::select_nodes(&self.credentials[*cred].claims, path) else {
            return ValueMatch::NoMatch;
        };
        for node in nodes {
            if expected_values.iter().any(|value| match value {
                ClaimValue::String(v) => node.as_str() == Some(v),
                ClaimValue::Integer(v) => node.as_i64() == Some(*v),
                ClaimValue::Boolean(v) => node.as_bool() == Some(*v),
            }) {
                return ValueMatch::Match;
            }
        }
        ValueMatch::NoMatch
    }
}

impl MatcherStore for CmCredentialPackage {
    fn describe_credential(&self, cred: &Self::CredentialRef) -> CredentialDescriptor {
        let credential = &self.credentials[*cred];
        let mut descriptor =
            CredentialDescriptor::new(credential.id.clone(), credential.title.clone());
        descriptor.subtitle = credential.subtitle.clone();
        descriptor.disclaimer = credential.disclaimer.clone();
        descriptor.icon = credential.icon.clone();
        if let Some(display_name) = &credential.shared_attribute_display_name {
            descriptor.fields.push(CredentialDescriptorField {
                display_name: display_name.clone(),
                display_value: String::new(),
            });
        }
        descriptor
    }

    fn supports_protocol(&self, _cred: &Self::CredentialRef, protocol: &str) -> bool {
        matches!(
            protocol,
            PROTOCOL_OPENID4VP_V1_UNSIGNED | PROTOCOL_OPENID4VP_V1_SIGNED
        )
    }

    fn openid4vp_config(&self) -> OpenId4VpConfig {
        OpenId4VpConfig {
            enabled: true,
            allow_dcql: true,
            allow_dcql_scope: false,
            allow_transaction_data: true,
            allow_signed_requests: true,
            allow_response_mode_jwt: false,
        }
    }
}

/// Parses a CMWallet-formatted credentials blob.
fn parse_cmwallet_blob(blob: &[u8]) -> Result<CmCredentialPackage, String> {
    if blob.len() < 4 {
        return Err("blob is too short for offset header".to_string());
    }

    let mut offset = [0u8; 4];
    offset.copy_from_slice(&blob[..4]);
    let json_offset = u32::from_le_bytes(offset) as usize;
    if json_offset < 4 || json_offset > blob.len() {
        return Err("invalid json offset in blob".to_string());
    }

    let root: Value = serde_json::from_slice(&blob[json_offset..])
        .map_err(|err| format!("invalid credentials json payload: {err}"))?;
    let credentials_obj = root
        .get("credentials")
        .and_then(Value::as_object)
        .ok_or_else(|| "missing credentials object".to_string())?;

    let mut credentials = Vec::new();
    for (format, format_bucket) in credentials_obj {
        let grouped = format_bucket.as_object().ok_or_else(|| {
            format!("credential format bucket {format} must be an object of vct arrays")
        })?;
        for (vct, candidates) in grouped {
            let entries = candidates.as_array().ok_or_else(|| {
                format!("credential group {format}/{vct} must be an array of entries")
            })?;
            for entry in entries {
                credentials.push(parse_credential_entry(blob, format, vct, entry)?);
            }
        }
    }

    Ok(CmCredentialPackage { credentials })
}

fn parse_credential_entry(
    blob: &[u8],
    format: &str,
    vct: &str,
    entry: &Value,
) -> Result<CmCredential, String> {
    let object = entry
        .as_object()
        .ok_or_else(|| "credential entry must be an object".to_string())?;
    let id = get_required_string(object, "id")?;
    let title = get_required_string(object, "title")?;
    let subtitle = get_string(object, "subtitle");
    let disclaimer = get_string(object, "disclaimer");
    let verifier_terms_prefix = get_string(object, "verifier_terms_prefix");
    let shared_attribute_display_name = get_string(object, "shared_attribute_display_name");
    let iss_allowlist = parse_string_vec(object.get("iss_allowlist"));
    let icon = extract_icon_bytes(blob, object);
    let claims = normalize_claim_paths(object.get("paths"));

    Ok(CmCredential {
        id,
        format: format.to_string(),
        vct: Some(vct.to_string()),
        title,
        subtitle,
        disclaimer,
        verifier_terms_prefix,
        shared_attribute_display_name,
        iss_allowlist,
        claims,
        icon,
    })
}

fn parse_string_vec(value: Option<&Value>) -> Option<Vec<String>> {
    let values: Vec<String> = value.and_then(Value::as_array)?
        .iter()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect();
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

fn get_required_string(object: &Map<String, Value>, key: &str) -> Result<String, String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("missing string field: {key}"))
}

fn get_string(object: &Map<String, Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn extract_icon_bytes(blob: &[u8], object: &Map<String, Value>) -> Option<Vec<u8>> {
    let icon = object.get("icon")?.as_object()?;
    let start = icon.get("start").and_then(Value::as_u64)? as usize;
    let length = icon.get("length").and_then(Value::as_u64)? as usize;
    let end = start.checked_add(length)?;
    if start >= blob.len() || end > blob.len() || length == 0 {
        return None;
    }
    Some(blob[start..end].to_vec())
}

fn normalize_claim_paths(paths: Option<&Value>) -> Value {
    match paths {
        Some(value) => normalize_claim_value(value),
        None => Value::Object(Map::new()),
    }
}

fn normalize_claim_value(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            if let Some(leaf_value) = object.get("value") {
                return leaf_value.clone();
            }
            let mut out = Map::new();
            for (key, child) in object {
                if matches!(key.as_str(), "display" | "display_value" | "_sd") {
                    continue;
                }
                out.insert(key.clone(), normalize_claim_value(child));
            }
            Value::Object(out)
        }
        Value::Array(array) => Value::Array(array.iter().map(normalize_claim_value).collect()),
        other => other.clone(),
    }
}

/// Example Credman matcher entrypoint for CMWallet-formatted credential blobs.
#[dcapi_matcher]
pub fn matcher_entrypoint(request: String, mut credentials: CredentialReader) {
    let mut blob = Vec::new();
    if credentials.read_to_end(&mut blob).is_err() {
        return;
    }

    let Ok(package) = parse_cmwallet_blob(blob.as_slice()) else {
        return;
    };

    let Ok(response) = match_dc_api_request(&request, &package, &MatcherOptions::default()) else {
        return;
    };

    response.apply();
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcapi_dcql::{PathElement, ValueMatch};
    use serde_json::json;

    fn build_cmwallet_blob(icons: &[u8], payload: &Value) -> Vec<u8> {
        let payload_bytes = serde_json::to_vec(payload).unwrap();
        let json_offset = 4 + icons.len();

        let mut out = Vec::new();
        out.extend_from_slice(&(json_offset as u32).to_le_bytes());
        out.extend_from_slice(icons);
        out.extend_from_slice(payload_bytes.as_slice());
        out
    }

    #[test]
    fn parses_cmwallet_blob_layout_and_extracts_claims() {
        let icon = [1u8, 2u8, 3u8];
        let payload = json!({
            "credentials": {
                "dc-authorization+sd-jwt": {
                    "number-verification/verify/ts43": [{
                        "id": "pnv-1",
                        "title": "Terrific Telecom",
                        "subtitle": "+1 (650) 215-4321",
                        "disclaimer": "Consent text",
                        "verifier_terms_prefix": "Provider Terms:\n",
                        "shared_attribute_display_name": "Phone number",
                        "icon": { "start": 4, "length": 3 },
                        "paths": {
                            "phone_number_hint": { "value": "+16502154321" }
                        }
                    }]
                }
            }
        });

        let blob = build_cmwallet_blob(icon.as_slice(), &payload);
        let package = parse_cmwallet_blob(blob.as_slice()).expect("must parse");

        assert_eq!(package.credentials.len(), 1);
        assert_eq!(
            package.list_credentials(Some("dc-authorization+sd-jwt")),
            vec![0]
        );
        assert!(package.has_vct(&0, "number-verification/verify/ts43"));

        let path = vec![PathElement::String("phone_number_hint".to_string())];
        assert!(package.has_claim_path(&0, &path));
        let matched =
            package.match_claim_value(&0, &path, &[ClaimValue::String("+16502154321".to_string())]);
        assert!(matches!(matched, ValueMatch::Match));

        let descriptor = package.describe_credential(&0);
        assert_eq!(descriptor.title, "Terrific Telecom");
        assert_eq!(descriptor.subtitle.as_deref(), Some("+1 (650) 215-4321"));
        assert_eq!(descriptor.disclaimer.as_deref(), Some("Consent text"));
        assert_eq!(descriptor.icon.as_deref(), Some(icon.as_slice()));
        assert_eq!(descriptor.fields.len(), 1);
        assert_eq!(descriptor.fields[0].display_name, "Phone number");
    }

    #[test]
    fn rejects_invalid_json_offset() {
        let blob = vec![255u8, 255u8, 255u8, 255u8, 0u8];
        assert!(parse_cmwallet_blob(blob.as_slice()).is_err());
    }
}

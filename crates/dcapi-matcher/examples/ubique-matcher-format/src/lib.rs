use android_credman::{CredentialReader, CredmanApplyExt};
use dcapi_dcql::{
    ClaimValue, ClaimsPathPointer, CredentialFormat, CredentialStore, TransactionData, ValueMatch,
};
use dcapi_matcher::{
    MatcherOptions, MatcherStore, PROTOCOL_OPENID4VP, PROTOCOL_OPENID4VP_V1_MULTISIGNED,
    PROTOCOL_OPENID4VP_V1_SIGNED, PROTOCOL_OPENID4VP_V1_UNSIGNED, dcapi_matcher,
    match_dc_api_request,
};
use serde_json::Value;
use std::io::Read;

/// Credential package parser compatible with Ubique's matcher format.
///
/// The input is the exact payload accepted by Ubique's `UbiqueWalletDatabaseFormat` parser:
/// a UTF-8 JSON array of credential objects.
#[derive(Debug, Clone)]
pub struct UbiqueCredentialPackage {
    credentials: Vec<Value>,
}

impl UbiqueCredentialPackage {
    fn parse(input: &[u8]) -> Result<Self, String> {
        let parsed = serde_json::from_slice::<Value>(input)
            .map_err(|err| format!("invalid credential package json: {err}"))?;
        let credentials = parsed
            .as_array()
            .ok_or_else(|| "credential package must be a json array".to_string())?
            .to_vec();
        Ok(Self { credentials })
    }

    fn credential(&self, idx: usize) -> &Value {
        &self.credentials[idx]
    }
}

impl CredentialStore for UbiqueCredentialPackage {
    type CredentialRef = usize;

    fn list_credentials(&self, format: Option<&str>) -> Vec<Self::CredentialRef> {
        self.credentials
            .iter()
            .enumerate()
            .filter(|(_, credential)| {
                format.is_none_or(|requested| {
                    credential.get("credential_format").and_then(Value::as_str) == Some(requested)
                })
            })
            .map(|(idx, _)| idx)
            .collect()
    }

    fn format(&self, cred: &Self::CredentialRef) -> CredentialFormat {
        let format = self
            .credential(*cred)
            .get("credential_format")
            .and_then(Value::as_str)
            .unwrap_or_default();
        CredentialFormat::from_query_format(format)
    }

    fn has_vct(&self, cred: &Self::CredentialRef, vct: &str) -> bool {
        self.credential(*cred)
            .get("document_type")
            .and_then(Value::as_str)
            == Some(vct)
    }

    fn supports_holder_binding(&self, _cred: &Self::CredentialRef) -> bool {
        // Ubique credential package does not encode holder-binding capabilities.
        // Keep parity with Ubique matcher behavior and treat credentials as usable.
        true
    }

    fn has_doctype(&self, cred: &Self::CredentialRef, doctype: &str) -> bool {
        self.credential(*cred)
            .get("document_type")
            .and_then(Value::as_str)
            == Some(doctype)
    }

    fn can_sign_transaction_data(
        &self,
        _cred: &Self::CredentialRef,
        _transaction_data: &TransactionData,
    ) -> bool {
        false
    }

    fn has_claim_path(&self, cred: &Self::CredentialRef, path: &ClaimsPathPointer) -> bool {
        let claims = self.credential(*cred).get("paths").unwrap_or(&Value::Null);
        dcapi_dcql::select_nodes(claims, path)
            .map(|nodes| !nodes.is_empty())
            .unwrap_or(false)
    }

    fn match_claim_value(
        &self,
        cred: &Self::CredentialRef,
        path: &ClaimsPathPointer,
        expected_values: &[ClaimValue],
    ) -> ValueMatch {
        let claims = self.credential(*cred).get("paths").unwrap_or(&Value::Null);
        let Ok(nodes) = dcapi_dcql::select_nodes(claims, path) else {
            return ValueMatch::NoMatch;
        };
        for node in nodes {
            if expected_values.iter().any(|expected| match expected {
                ClaimValue::String(value) => node.as_str() == Some(value),
                ClaimValue::Integer(value) => node.as_i64() == Some(*value),
                ClaimValue::Boolean(value) => node.as_bool() == Some(*value),
            }) {
                return ValueMatch::Match;
            }
        }
        ValueMatch::NoMatch
    }
}

impl MatcherStore for UbiqueCredentialPackage {
    fn credential_id<'a>(&'a self, cred: &Self::CredentialRef) -> &'a str {
        self.credential(*cred)
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
    }

    fn credential_title<'a>(&'a self, cred: &Self::CredentialRef) -> &'a str {
        self.credential(*cred)
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("")
    }

    fn credential_subtitle<'a>(&'a self, cred: &Self::CredentialRef) -> Option<&'a str> {
        self.credential(*cred)
            .get("subtitle")
            .and_then(Value::as_str)
    }

    fn supports_protocol(&self, _cred: &Self::CredentialRef, protocol: &str) -> bool {
        matches!(
            protocol,
            PROTOCOL_OPENID4VP
                | PROTOCOL_OPENID4VP_V1_UNSIGNED
                | PROTOCOL_OPENID4VP_V1_SIGNED
                | PROTOCOL_OPENID4VP_V1_MULTISIGNED
        )
    }

    fn preferred_locales(&self) -> &[&str] {
        static LOCALES: [&str; 1] = ["en"];
        &LOCALES
    }
}

/// Example Credman matcher entrypoint for Ubique matcher package format.
#[dcapi_matcher]
pub fn matcher_entrypoint(request: String, mut credentials: CredentialReader) {
    let mut raw = Vec::new();
    if let Err(err) = credentials.read_to_end(&mut raw) {
        dcapi_matcher::diagnostics::error(format!("credential package read error: {err}"));
        return;
    }

    let package = match UbiqueCredentialPackage::parse(raw.as_slice()) {
        Ok(package) => package,
        Err(err) => {
            dcapi_matcher::diagnostics::error(format!("credential package parse error: {err}"));
            return;
        }
    };
    let Ok(response) = match_dc_api_request(&request, &package, &MatcherOptions::default()) else {
        return;
    };
    response.apply();
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcapi_dcql::PathElement;
    use serde_json::json;

    #[test]
    fn parses_ubique_credential_package_shape() {
        let payload = json!([
          {
            "paths": { "org.iso.18013.5.1": { "family_name": "Mustermann", "age_over_18": true } },
            "credential_format": "mso_mdoc",
            "document_type": "org.iso.18013.5.1.mDL",
            "id": 113,
            "title": "Drivers Licence",
            "subtitle": ""
          }
        ]);
        let bytes = serde_json::to_vec(&payload).unwrap();
        let package = UbiqueCredentialPackage::parse(bytes.as_slice()).expect("must parse");

        assert_eq!(package.list_credentials(Some("mso_mdoc")), vec![0]);
        assert_eq!(
            package.list_credentials(Some("dc+sd-jwt")),
            Vec::<usize>::new()
        );
        assert_eq!(package.credential_id(&0), "113");

        let path = vec![
            PathElement::String("org.iso.18013.5.1".to_string()),
            PathElement::String("family_name".to_string()),
        ];
        assert!(package.has_claim_path(&0, &path));
        assert!(matches!(
            package.match_claim_value(&0, &path, &[ClaimValue::String("Mustermann".to_string())]),
            ValueMatch::Match
        ));
    }

    #[test]
    fn rejects_non_array_payload() {
        let payload = json!({
            "credentials": []
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        assert!(UbiqueCredentialPackage::parse(bytes.as_slice()).is_err());
    }

    #[test]
    fn parses_ubique_reference_vector() {
        let bytes = include_bytes!(
            "../../../../../oid4vp-wasm-matcher/src/dcql/test_vectors/ubique_format_db.json"
        );
        let package = UbiqueCredentialPackage::parse(bytes).expect("ubique vector must parse");
        assert!(!package.credentials.is_empty());
        assert!(
            package
                .credentials
                .iter()
                .all(|credential| credential.get("credential_format").is_some())
        );
    }
}

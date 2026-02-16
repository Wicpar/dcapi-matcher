use crate::models::{FieldConstraint, InputDescriptor, PROTOCOL_OPENID4VCI, PROTOCOL_OPENID4VP};
use crate::error::CredentialValidationError;
use crate::config::{OpenId4VciConfig, OpenId4VpConfig};
use crate::ts12::{Ts12PaymentSummary, Ts12TransactionMetadata};
use dcapi_dcql::{
    ClaimValue, ClaimsPathPointer, CredentialFormat, CredentialStore, PathElement, ValueMatch,
};
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use serde_json::Value;

/// User-facing credential descriptor used to build Credman entries.
#[derive(Debug, Clone)]
pub struct CredentialDescriptor {
    /// Credential selection id returned to host.
    pub credential_id: String,
    /// Entry title.
    pub title: String,
    /// Optional icon bytes.
    pub icon: Option<Vec<u8>>,
    /// Optional subtitle.
    pub subtitle: Option<String>,
    /// Optional disclaimer.
    pub disclaimer: Option<String>,
    /// Optional warning.
    pub warning: Option<String>,
    /// Optional credential-scoped metadata object.
    pub metadata: Option<Value>,
    /// Display fields.
    pub fields: Vec<CredentialDescriptorField>,
}

impl CredentialDescriptor {
    /// Creates a descriptor with mandatory fields.
    pub fn new(credential_id: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            credential_id: credential_id.into(),
            title: title.into(),
            icon: None,
            subtitle: None,
            disclaimer: None,
            warning: None,
            metadata: None,
            fields: Vec::new(),
        }
    }
}

/// One label/value field for credential detail rendering.
#[derive(Debug, Clone)]
pub struct CredentialDescriptorField {
    /// Field label.
    pub display_name: String,
    /// Field value.
    pub display_value: String,
}

/// Context passed when building Credman metadata for one candidate entry.
#[derive(Debug)]
pub enum CredentialSelectionContext<'a> {
    /// Selection produced from OpenID4VP + DCQL.
    OpenId4VpDcql {
        /// Request index in `DcApiRequest.requests`.
        request_index: usize,
        /// Alternative index in planned DCQL output.
        alternative_index: usize,
        /// DCQL credential query id.
        query_id: &'a str,
        /// Transaction data decoded from request.
        transaction_data: &'a [dcapi_dcql::TransactionData],
        /// Transaction data indices bound to this query id in the selected alternative.
        transaction_data_indices: &'a [usize],
    },
    /// Selection produced from OpenID4VP + Presentation Definition.
    OpenId4VpPresentationDefinition {
        /// Request index in `DcApiRequest.requests`.
        request_index: usize,
        /// Input descriptor id.
        input_descriptor_id: &'a str,
    },
    /// Selection produced from OpenID4VCI credential offer.
    OpenId4VciOffer {
        /// Request index in `DcApiRequest.requests`.
        request_index: usize,
        /// Credential issuer identifier.
        credential_issuer: &'a str,
        /// Credential configuration id.
        credential_configuration_id: &'a str,
        /// Optional configuration object resolved from issuer metadata.
        credential_configuration: Option<&'a Value>,
    },
}

impl<'a> CredentialSelectionContext<'a> {
    /// Returns a protocol label for metadata serialization.
    pub fn protocol(&self) -> &'static str {
        match self {
            Self::OpenId4VpDcql { .. } | Self::OpenId4VpPresentationDefinition { .. } => {
                PROTOCOL_OPENID4VP
            }
            Self::OpenId4VciOffer { .. } => PROTOCOL_OPENID4VCI,
        }
    }
}

/// Store contract used by `dcapi-matcher`.
///
/// This extends `dcapi_dcql::CredentialStore` so DCQL matching can be delegated to
/// `dcapi-dcql`. Implementers only need to define how credentials are displayed and
/// how to match Presentation Definition / OpenID4VCI constraints for their package format.
pub trait MatcherStore: CredentialStore {
    /// Returns descriptor data for one credential.
    fn describe_credential(&self, cred: &Self::CredentialRef) -> CredentialDescriptor;

    /// Returns whether this credential is available for a protocol.
    fn supports_protocol(&self, _cred: &Self::CredentialRef, _protocol: &str) -> bool {
        false
    }

    /// Returns wallet-level OpenID4VP support configuration.
    fn openid4vp_config(&self) -> OpenId4VpConfig {
        OpenId4VpConfig::default()
    }

    /// Returns wallet-level OpenID4VCI support configuration.
    fn openid4vci_config(&self) -> OpenId4VciConfig {
        OpenId4VciConfig::default()
    }

    /// Preferred locales for UI rendering, in priority order.
    fn preferred_locales(&self) -> &[&str] {
        &[]
    }

    /// Logging level for matcher diagnostics. `None` disables logging.
    fn log_level(&self) -> Option<tracing_core::Level> {
        None
    }

    /// Optional protocol-specific metadata to attach to Credman set entries.
    fn metadata_for_credman(
        &self,
        _cred: &Self::CredentialRef,
        _context: &CredentialSelectionContext<'_>,
    ) -> Option<Value> {
        None
    }

    /// Validates the credential package.
    ///
    /// Return an error to remove the credential from consideration and emit a warning.
    fn validate_credential(
        &self,
        _cred: &Self::CredentialRef,
    ) -> Result<(), CredentialValidationError> {
        Ok(())
    }

    /// Returns resolved TS12 transaction metadata for display and validation.
    ///
    /// Implementers must resolve any `claims_uri` / `ui_labels_uri` references and apply
    /// `extends` merging rules before returning this metadata. The returned metadata must
    /// already contain the concrete JSON Schema object and the matching `type`/`subtype`;
    /// the matcher does not resolve schema URLs or built-in types, and it forbids external
    /// `$ref` references during validation. Return `None` when the credential does not
    /// support the provided transaction data type.
    fn ts12_transaction_metadata(
        &self,
        _cred: &Self::CredentialRef,
        _transaction_data: &dcapi_dcql::TransactionData,
    ) -> Option<Ts12TransactionMetadata> {
        None
    }

    /// Optional payment summary for TS12 flows.
    ///
    /// Return `Some` to render the credential as a payment entry for the given transaction data.
    /// The summary fields must be derived from credential package metadata/payloads and already
    /// localized as needed; the matcher does not inject hardcoded strings.
    fn ts12_payment_summary(
        &self,
        _cred: &Self::CredentialRef,
        _transaction_data: &dcapi_dcql::TransactionData,
        _payload: &Value,
        _metadata: &Ts12TransactionMetadata,
        _locale: &str,
    ) -> Option<Ts12PaymentSummary> {
        None
    }

    /// Optional formatter for TS12 transaction data values.
    ///
    /// This hook lets wallets provide localized or domain-specific value rendering
    /// (for example, translating recurrence frequency codes) without hardcoded strings
    /// in the matcher core. When `None` is returned, the matcher falls back to
    /// a basic string representation of the JSON value.
    fn format_ts12_value(
        &self,
        _cred: &Self::CredentialRef,
        _path: &ClaimsPathPointer,
        _value: &Value,
        _locale: &str,
    ) -> Option<String> {
        None
    }

    /// Matches a credential against one Presentation Definition descriptor.
    fn matches_presentation_definition(
        &self,
        cred: &Self::CredentialRef,
        descriptor: &InputDescriptor,
    ) -> bool {
        if !matches_descriptor_format(self, cred, descriptor) {
            return false;
        }

        let Some(constraints) = &descriptor.constraints else {
            return true;
        };
        for field in &constraints.fields {
            if !matches_field_constraint(self, cred, field) {
                return false;
            }
        }
        true
    }

    /// Matches one credential against one OpenID4VCI configuration id.
    ///
    /// `credential_configuration` is optional because request payload may not include
    /// issuer metadata.
    fn matches_openid4vci_configuration(
        &self,
        cred: &Self::CredentialRef,
        _credential_offer: &crate::models::CredentialOffer,
        _credential_configuration_id: &str,
        credential_configuration: Option<&Value>,
    ) -> bool {
        let Some(configuration) = credential_configuration else {
            return false;
        };
        let Some(config_obj) = configuration.as_object() else {
            return false;
        };

        if let Some(format) = config_obj.get("format").and_then(Value::as_str) {
            let expected = CredentialFormat::from_query_format(format);
            if self.format(cred) != expected {
                return false;
            }
        }
        if let Some(doctype) = config_obj.get("doctype").and_then(Value::as_str)
            && !self.has_doctype(cred, doctype)
        {
            return false;
        }
        if let Some(vct) = config_obj.get("vct").and_then(Value::as_str)
            && !self.has_vct(cred, vct)
        {
            return false;
        }

        true
    }
}

fn matches_descriptor_format<S>(
    store: &S,
    cred: &S::CredentialRef,
    descriptor: &InputDescriptor,
) -> bool
where
    S: CredentialStore + ?Sized,
{
    let Some(format) = &descriptor.format else {
        return true;
    };

    let credential_format = store.format(cred);
    if format.contains_key("mso_mdoc") && credential_format != CredentialFormat::MsoMdoc {
        return false;
    }
    if format.contains_key("dc+sd-jwt") && credential_format != CredentialFormat::DcSdJwt {
        return false;
    }

    true
}

fn matches_field_constraint<S>(store: &S, cred: &S::CredentialRef, field: &FieldConstraint) -> bool
where
    S: CredentialStore + ?Sized,
{
    if field.path.is_empty() {
        return false;
    }

    let expected_values = filter_expected_values(field.filter.as_ref());

    for raw_path in &field.path {
        let Some(path) = parse_json_path(raw_path) else {
            continue;
        };
        if !store.has_claim_path(cred, &path) {
            continue;
        }

        if let Some(values) = &expected_values {
            if matches!(
                store.match_claim_value(cred, &path, values),
                ValueMatch::Match
            ) {
                return true;
            }
            continue;
        }

        return true;
    }

    false
}

fn filter_expected_values(filter: Option<&Value>) -> Option<Vec<ClaimValue>> {
    let filter = filter?;
    let obj = filter.as_object()?;
    if let Some(value) = obj.get("const") {
        return claim_value_from_json(value).map(|v| vec![v]);
    }
    let values = obj.get("enum")?.as_array()?;
    let mut out = Vec::new();
    for value in values {
        let Some(converted) = claim_value_from_json(value) else {
            continue;
        };
        out.push(converted);
    }
    if out.is_empty() { None } else { Some(out) }
}

fn claim_value_from_json(value: &Value) -> Option<ClaimValue> {
    match value {
        Value::String(v) => Some(ClaimValue::String(v.clone())),
        Value::Bool(v) => Some(ClaimValue::Boolean(*v)),
        Value::Number(v) => v.as_i64().map(ClaimValue::Integer),
        _ => None,
    }
}

/// Parses a JSONPath-like expression to a DCQL claims path.
///
/// Supported forms:
/// - `$.a.b`
/// - `$['a']['b']`
/// - `$[\"a\"][\"b\"]`
pub fn parse_json_path(path: &str) -> Option<ClaimsPathPointer> {
    if !path.starts_with('$') {
        return None;
    }
    let bytes = path.as_bytes();
    let mut i = 1usize;
    let mut out = Vec::new();

    while i < bytes.len() {
        match bytes[i] {
            b'.' => {
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i] != b'.' && bytes[i] != b'[' {
                    i += 1;
                }
                if i == start {
                    return None;
                }
                out.push(PathElement::String(path[start..i].to_string()));
            }
            b'[' => {
                i += 1;
                if i >= bytes.len() {
                    return None;
                }
                if bytes[i] == b'\'' || bytes[i] == b'"' {
                    let quote = bytes[i];
                    i += 1;
                    let start = i;
                    while i < bytes.len() && bytes[i] != quote {
                        i += 1;
                    }
                    if i >= bytes.len() {
                        return None;
                    }
                    let key = &path[start..i];
                    i += 1;
                    if i >= bytes.len() || bytes[i] != b']' {
                        return None;
                    }
                    i += 1;
                    out.push(PathElement::String(key.to_string()));
                } else if bytes[i] == b'*' {
                    i += 1;
                    if i >= bytes.len() || bytes[i] != b']' {
                        return None;
                    }
                    i += 1;
                    out.push(PathElement::Wildcard);
                } else {
                    let start = i;
                    while i < bytes.len() && bytes[i].is_ascii_digit() {
                        i += 1;
                    }
                    if i == start || i >= bytes.len() || bytes[i] != b']' {
                        return None;
                    }
                    let index = path[start..i].parse::<u64>().ok()?;
                    i += 1;
                    out.push(PathElement::Index(index));
                }
            }
            _ => return None,
        }
    }

    if out.is_empty() { None } else { Some(out) }
}

use crate::diagnostics::LogLevel;
use crate::models::PROTOCOL_OPENID4VP;
use crate::config::{OpenId4VciConfig, OpenId4VpConfig};
use crate::ts12::{Ts12PaymentSummary, Ts12TransactionMetadata};
use dcapi_dcql::{ClaimsPathPointer, CredentialStore};
use alloc::borrow::Cow;
use alloc::vec::Vec;
use serde_json::Value;

/// User-facing credential descriptor used to build Credman entries.
#[derive(Debug, Clone)]
pub struct CredentialDescriptor<'a> {
    /// Credential selection id returned to host.
    pub credential_id: Cow<'a, str>,
    /// Entry title.
    pub title: Cow<'a, str>,
    /// Optional icon bytes.
    pub icon: Option<Cow<'a, [u8]>>,
    /// Optional subtitle.
    pub subtitle: Option<Cow<'a, str>>,
    /// Optional disclaimer.
    pub disclaimer: Option<Cow<'a, str>>,
    /// Optional warning.
    pub warning: Option<Cow<'a, str>>,
    /// Optional credential-scoped metadata object.
    pub metadata: Option<Value>,
    /// Display fields.
    pub fields: Vec<CredentialDescriptorField<'a>>,
}

impl<'a> CredentialDescriptor<'a> {
    /// Creates a descriptor with mandatory fields.
    pub fn new(
        credential_id: impl Into<Cow<'a, str>>,
        title: impl Into<Cow<'a, str>>,
    ) -> Self {
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
pub struct CredentialDescriptorField<'a> {
    /// Field label.
    pub display_name: Cow<'a, str>,
    /// Field value.
    pub display_value: Option<Cow<'a, str>>,
}

/// Context passed when building Credman metadata for one candidate entry.
#[derive(Debug)]
pub struct DcqlSelectionContext<'a> {
    /// Request index in `DcApiRequest.requests`.
    pub request_index: usize,
    /// Alternative index in planned DCQL output.
    pub alternative_index: usize,
    /// DCQL credential query id.
    pub query_id: &'a str,
    /// Claim constraints selected for this query.
    pub selected_claims: &'a [dcapi_dcql::ClaimsQuery],
    /// Transaction data decoded from request.
    pub transaction_data: &'a [dcapi_dcql::TransactionData],
    /// Transaction data indices bound to this query id in the selected alternative.
    pub transaction_data_indices: &'a [usize],
}

impl DcqlSelectionContext<'_> {
    /// Returns a protocol label for metadata serialization.
    pub fn protocol(&self) -> &'static str {
        PROTOCOL_OPENID4VP
    }
}

/// Store contract used by `dcapi-matcher`.
///
/// This extends `dcapi_dcql::CredentialStore` so DCQL matching can be delegated to
/// `dcapi-dcql`. Implementers only need to define how credentials are displayed.
pub trait MatcherStore: CredentialStore {
    /// Returns descriptor data for one credential in a specific selection context.
    fn describe_credential<'a>(
        &'a self,
        cred: &Self::CredentialRef,
        context: &DcqlSelectionContext<'_>,
    ) -> CredentialDescriptor<'a>;

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
    fn log_level(&self) -> Option<LogLevel> {
        None
    }

    /// Optional protocol-specific metadata to attach to Credman set entries.
    fn metadata_for_credman(
        &self,
        _cred: &Self::CredentialRef,
        _context: &DcqlSelectionContext<'_>,
    ) -> Option<Value> {
        None
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
    fn ts12_payment_summary<'a>(
        &'a self,
        _cred: &Self::CredentialRef,
        _transaction_data: &dcapi_dcql::TransactionData,
        _payload: &Value,
        _metadata: &Ts12TransactionMetadata,
        _locale: &str,
    ) -> Option<Ts12PaymentSummary<'a>> {
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

}

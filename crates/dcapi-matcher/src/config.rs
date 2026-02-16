use serde::{Deserialize, Serialize};

/// Wallet-supported OpenID4VP features.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OpenId4VpConfig {
    /// Whether OpenID4VP requests are supported at all.
    pub enabled: bool,
    /// Whether DCQL-based requests using `dcql_query` are supported.
    pub allow_dcql: bool,
    /// Whether DCQL-based requests using `scope` are supported.
    pub allow_dcql_scope: bool,
    /// Whether transaction_data constraints are supported.
    pub allow_transaction_data: bool,
    /// Whether signed OpenID4VP request variants are supported.
    pub allow_signed_requests: bool,
    /// Whether the `dc_api.jwt` response mode is supported.
    pub allow_response_mode_jwt: bool,
}

impl OpenId4VpConfig {
    /// Returns a configuration with all features disabled.
    pub fn disabled() -> Self {
        Self::default()
    }
}

/// Wallet-supported OpenID4VCI features.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OpenId4VciConfig {
    /// Whether OpenID4VCI requests are supported at all.
    pub enabled: bool,
    /// Whether credential offers are supported.
    pub allow_credential_offer: bool,
    /// Whether credential_offer_uri is supported.
    pub allow_credential_offer_uri: bool,
    /// Whether the Authorization Code grant is supported.
    ///
    /// This is only considered supported when either `allow_authorization_details`
    /// or `allow_scope` is also enabled.
    pub allow_authorization_code: bool,
    /// Whether the Pre-Authorized Code grant is supported.
    pub allow_pre_authorized_code: bool,
    /// Whether Transaction Code handling is supported for Pre-Authorized Code flows.
    pub allow_tx_code: bool,
    /// Whether `authorization_details` is supported when requesting authorization.
    pub allow_authorization_details: bool,
    /// Whether `scope` is supported when requesting authorization.
    pub allow_scope: bool,
}

impl OpenId4VciConfig {
    /// Returns a configuration with all features disabled.
    pub fn disabled() -> Self {
        Self::default()
    }
}

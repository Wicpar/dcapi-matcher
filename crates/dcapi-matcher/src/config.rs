use serde::{Deserialize, Serialize};

/// Wallet-supported OpenID4VP features.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
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

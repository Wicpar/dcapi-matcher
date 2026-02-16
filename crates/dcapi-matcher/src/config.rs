/// Wallet-supported OpenID4VP features.
#[derive(Debug, Clone, Default)]
pub struct OpenId4VpConfig {
    /// Whether OpenID4VP requests are supported at all.
    pub enabled: bool,
    /// Whether DCQL-based requests are supported.
    pub allow_dcql: bool,
    /// Whether Presentation Definition requests are supported.
    pub allow_presentation_definition: bool,
    /// Whether transaction_data constraints are supported.
    pub allow_transaction_data: bool,
    /// Whether signed OpenID4VP request variants are supported.
    pub allow_signed_requests: bool,
}

impl OpenId4VpConfig {
    /// Returns a configuration with all features disabled.
    pub fn disabled() -> Self {
        Self::default()
    }
}

/// Wallet-supported OpenID4VCI features.
#[derive(Debug, Clone, Default)]
pub struct OpenId4VciConfig {
    /// Whether OpenID4VCI requests are supported at all.
    pub enabled: bool,
    /// Whether credential offers are supported.
    pub allow_credential_offer: bool,
    /// Whether credential_offer_uri is supported.
    pub allow_credential_offer_uri: bool,
}

impl OpenId4VciConfig {
    /// Returns a configuration with all features disabled.
    pub fn disabled() -> Self {
        Self::default()
    }
}

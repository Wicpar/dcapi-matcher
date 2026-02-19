use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use dcapi_dcql::DcqlQuery;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Protocol identifier for OpenID4VP requests in DC API.
pub const PROTOCOL_OPENID4VP: &str = "openid4vp";
/// Protocol identifier for OpenID4VP unsigned requests in DC API.
pub const PROTOCOL_OPENID4VP_V1_UNSIGNED: &str = "openid4vp-v1-unsigned";
/// Protocol identifier for OpenID4VP JWS signed requests in DC API.
pub const PROTOCOL_OPENID4VP_V1_SIGNED: &str = "openid4vp-v1-signed";
/// Protocol identifier for OpenID4VP multi-signed requests in DC API.
pub const PROTOCOL_OPENID4VP_V1_MULTISIGNED: &str = "openid4vp-v1-multisigned";
/// Protocol identifier for OpenID4VCI requests in DC API.
pub const PROTOCOL_OPENID4VCI: &str = "openid4vci";

/// Root request envelope passed by DC API to matchers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcApiRequest {
    /// Requested protocol operations.
    pub requests: Vec<DcApiRequestItem>,
}

/// One protocol request in the DC API request list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcApiRequestItem {
    /// Protocol identifier.
    pub protocol: String,
    /// Request body for the protocol.
    pub data: RequestData,
}

/// Raw protocol request payload.
///
/// DC API transports `data` as a string containing JSON in common deployments,
/// but object-valued payloads are also accepted by this matcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestData {
    /// JSON document encoded as string.
    JsonString(String),
    /// JSON object/value directly.
    JsonValue(Value),
}

impl RequestData {
    /// Returns the payload as JSON value.
    pub fn to_value(&self) -> Result<Value, serde_json::Error> {
        match self {
            Self::JsonString(raw) => match serde_json::from_str(raw) {
                Ok(value) => Ok(value),
                Err(_) => Ok(Value::String(raw.clone())),
            },
            Self::JsonValue(value) => Ok(value.clone()),
        }
    }
}

/// OpenID4VP request payload.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OpenId4VpRequest {
    /// Response type parameter.
    pub response_type: Option<String>,
    /// Response mode parameter.
    pub response_mode: Option<String>,
    /// DCQL query request.
    pub dcql_query: Option<DcqlQuery>,
    /// Transaction data constraints as defined by OpenID4VP.
    pub transaction_data: Option<Vec<TransactionDataInput>>,
    /// Legacy Presentation Exchange request (ignored by matcher).
    pub presentation_definition: Option<Value>,
    /// Preserved unknown fields.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// One transaction-data request entry, either already decoded or base64url encoded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TransactionDataInput {
    /// Base64url encoded JSON object.
    Encoded(String),
    /// Decoded JSON object.
    Decoded(Box<dcapi_dcql::TransactionData>),
}

/// OpenID4VCI request payload used by the matcher.
///
/// This supports both direct `credential_offer` wrapper and direct
/// offer objects through `decode_openid4vci_request`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OpenId4VciRequest {
    /// Credential Offer by value.
    pub credential_offer: Option<CredentialOffer>,
    /// Credential Offer by reference (not fetched by this matcher).
    pub credential_offer_uri: Option<String>,
    /// Optional issuer metadata supplied with request.
    pub credential_issuer_metadata: Option<CredentialIssuerMetadata>,
    /// Preserved unknown fields.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// OpenID4VCI Credential Offer object.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredentialOffer {
    /// Credential Issuer identifier.
    pub credential_issuer: String,
    /// Offered credential configuration identifiers.
    #[serde(default)]
    pub credential_configuration_ids: Vec<String>,
    /// Supported grants.
    #[serde(default)]
    pub grants: serde_json::Map<String, Value>,
    /// Preserved unknown fields.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Minimal issuer metadata subset used by matcher for OpenID4VCI.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredentialIssuerMetadata {
    /// Credential configurations indexed by `credential_configuration_id`.
    #[serde(default)]
    pub credential_configurations_supported: serde_json::Map<String, Value>,
    /// Preserved unknown fields.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

impl OpenId4VciRequest {
    /// Returns the active credential offer, if available.
    pub fn credential_offer(&self) -> Option<&CredentialOffer> {
        self.credential_offer.as_ref()
    }

    /// Looks up configuration metadata for a configuration id.
    pub fn credential_configuration(&self, id: &str) -> Option<&Value> {
        self.credential_issuer_metadata
            .as_ref()
            .and_then(|metadata| metadata.credential_configurations_supported.get(id))
    }
}

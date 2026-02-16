use crate::path::ClaimsPathPointer;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Core DCQL object from OpenID4VP.
///
/// It intentionally models only DCQL members. `transaction_data` belongs to the
/// enclosing Authorization Request and is therefore passed separately to the planner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcqlQuery {
    /// Requested Credential Queries.
    pub credentials: Vec<CredentialQuery>,
    /// Optional combinations constraining which credential query ids can be returned together.
    pub credential_sets: Option<Vec<CredentialSetQuery>>,
}

/// One credential request entry.
///
/// The enum is keyed by `format` to keep the query strongly typed per credential format.
/// Unknown formats are retained at parse time and rejected during validation so deserialization
/// remains forward-compatible.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "format")]
pub enum CredentialQuery {
    /// ISO mdoc credential query.
    #[serde(rename = "mso_mdoc")]
    MsoMdoc {
        #[serde(flatten)]
        common: CredentialQueryCommon,
        /// mdoc-specific meta. Required by spec.
        meta: IsoMdocMeta,
    },
    /// SD-JWT VC credential query.
    #[serde(rename = "dc+sd-jwt")]
    DcSdJwt {
        #[serde(flatten)]
        common: CredentialQueryCommon,
        /// SD-JWT-specific meta. Required by spec.
        meta: SdJwtMeta,
    },
    /// Unknown format value.
    #[serde(other)]
    Unknown,
}

/// Internal typed wrapper for the parsed `meta` object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Meta {
    IsoMdoc(IsoMdocMeta),
    SdJwtVc(SdJwtMeta),
}

/// `meta` members for `mso_mdoc`.
///
/// Unknown fields are intentionally accepted so extension fields are ignored
/// instead of causing hard parse failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsoMdocMeta {
    doctype_value: String,
}

impl IsoMdocMeta {
    /// Required mdoc doctype constraint.
    pub fn doctype_value(&self) -> &str {
        self.doctype_value.as_str()
    }
}

/// `meta` members for `dc+sd-jwt`.
///
/// Unknown fields are intentionally accepted so extension fields are ignored
/// instead of causing hard parse failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdJwtMeta {
    vct_values: Vec<String>,
}

impl SdJwtMeta {
    /// Allowed VCT values (and optionally inherited VCTs) for the requested credential.
    pub fn vct_values(&self) -> &[String] {
        self.vct_values.as_slice()
    }
}

/// Format-agnostic Credential Query members.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialQueryCommon {
    id: String,
    multiple: Option<bool>,
    trusted_authorities: Option<Vec<TrustedAuthority>>,
    require_cryptographic_holder_binding: Option<bool>,
    claims: Option<Vec<ClaimsQuery>>,
    claim_sets: Option<Vec<Vec<String>>>,
}

impl CredentialQuery {
    fn common(&self) -> Option<&CredentialQueryCommon> {
        match self {
            Self::MsoMdoc { common, .. } | Self::DcSdJwt { common, .. } => Some(common),
            Self::Unknown => None,
        }
    }

    /// True if the request used an unknown credential format identifier.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }

    /// Credential query id.
    pub fn id(&self) -> Option<&str> {
        self.common().map(|common| common.id.as_str())
    }

    /// Normalized format string for supported formats.
    pub fn format(&self) -> Option<&'static str> {
        match self {
            Self::MsoMdoc { .. } => Some("mso_mdoc"),
            Self::DcSdJwt { .. } => Some("dc+sd-jwt"),
            Self::Unknown => None,
        }
    }

    /// True when this is an mdoc format query.
    pub fn is_mdoc(&self) -> bool {
        matches!(self, Self::MsoMdoc { .. })
    }

    /// Typed meta object for supported formats.
    pub fn meta(&self) -> Option<Meta> {
        match self {
            Self::MsoMdoc { meta, .. } => Some(Meta::IsoMdoc(meta.clone())),
            Self::DcSdJwt { meta, .. } => Some(Meta::SdJwtVc(meta.clone())),
            Self::Unknown => None,
        }
    }

    /// mdoc doctype constraint for supported mdoc queries.
    pub fn doctype_value(&self) -> Option<&str> {
        match self {
            Self::MsoMdoc { meta, .. } => Some(meta.doctype_value.as_str()),
            Self::DcSdJwt { .. } | Self::Unknown => None,
        }
    }

    /// SD-JWT VCT constraints for supported SD-JWT queries.
    pub fn vct_values(&self) -> Option<&[String]> {
        match self {
            Self::MsoMdoc { .. } | Self::Unknown => None,
            Self::DcSdJwt { meta, .. } => Some(meta.vct_values.as_slice()),
        }
    }

    /// Whether multiple credentials may satisfy this query.
    pub fn multiple(&self) -> Option<bool> {
        self.common().and_then(|common| common.multiple)
    }

    /// Trusted authority constraints.
    pub fn trusted_authorities(&self) -> Option<&[TrustedAuthority]> {
        self.common()
            .and_then(|common| common.trusted_authorities.as_deref())
    }

    /// Holder-binding requirement.
    pub fn require_cryptographic_holder_binding(&self) -> Option<bool> {
        self.common()
            .and_then(|common| common.require_cryptographic_holder_binding)
    }

    /// Requested claim constraints.
    pub fn claims(&self) -> Option<&[ClaimsQuery]> {
        self.common().and_then(|common| common.claims.as_deref())
    }

    /// Requested alternatives of claim ids.
    pub fn claim_sets(&self) -> Option<&[Vec<String>]> {
        self.common()
            .and_then(|common| common.claim_sets.as_deref())
    }
}

/// Trusted authority constraint from DCQL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedAuthority {
    /// Trusted authority type identifier.
    pub r#type: String,
    /// Values interpreted according to `type`.
    pub values: Vec<String>,
}

/// Allowed value constraint primitive types for claims.
///
/// OpenID4VP restricts value matching to strings, integers and booleans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ClaimValue {
    String(String),
    Integer(i64),
    Boolean(bool),
}

impl ClaimValue {
    /// Convert into `serde_json::Value` for stores that use JSON internals.
    pub fn to_json_value(&self) -> Value {
        match self {
            Self::String(value) => Value::String(value.clone()),
            Self::Integer(value) => Value::Number((*value).into()),
            Self::Boolean(value) => Value::Bool(*value),
        }
    }
}

/// One requested claim constraint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimsQuery {
    /// Claim id, required only when `claim_sets` is present.
    pub id: Option<String>,
    /// Claims path pointer selecting claim(s) in the credential payload.
    pub path: ClaimsPathPointer,
    /// Optional accepted values. If present, at least one must match exactly.
    pub values: Option<Vec<ClaimValue>>,
    /// Optional mdoc-specific hint carried through to callers.
    pub intent_to_retain: Option<bool>,
}

impl ClaimsQuery {
    /// Optional claim id.
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }
}

/// Credential set constraint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSetQuery {
    /// Alternative required-id combinations.
    pub options: Vec<Vec<String>>,
    /// Whether this set is mandatory.
    #[serde(default = "default_required")]
    pub required: bool,
    /// Optional verifier purpose string/object forwarded as-is.
    pub purpose: Option<Value>,
}

/// Default value for `CredentialSetQuery::required`.
pub const fn default_required() -> bool {
    true
}

/// Transaction data type discriminator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TransactionDataType {
    /// Transaction data type identifier.
    #[serde(rename = "type")]
    pub r#type: String,
    /// Optional type-specific subtype discriminator.
    pub subtype: Option<String>,
}

/// Decoded transaction data object used for planning.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionData {
    /// Type and optional subtype discriminator.
    #[serde(flatten)]
    pub data_type: TransactionDataType,
    /// Referenced credential query ids that can authorize this transaction.
    pub credential_ids: Vec<String>,
    /// Optional algorithm identifier from OpenID4VP transaction data.
    ///
    /// TS12 uses this value together with `transaction_data_hashes` in KB-JWT processing.
    pub transaction_data_hashes_alg: Option<String>,
    /// Optional structured transaction payload.
    ///
    /// TS12 defines this as required for TS12 transaction-data types.
    pub payload: Option<Value>,
    /// Unknown extension fields preserved for forward compatibility.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

use dcapi_dcql::{ClaimsPathPointer, TransactionDataType};
use alloc::string::String;
use thiserror::Error;

/// TS12-specific request/configuration warnings.
#[derive(Debug, Error)]
pub enum Ts12Error {
    /// Payload is not an object.
    #[error("transaction_data[{index}] payload must be an object")]
    PayloadNotObject { index: usize },
    /// Failed to serialize TS12 metadata.
    #[error("failed to serialize ts12 metadata for transaction_data[{index}]: {source}")]
    MetadataSerialization {
        index: usize,
        #[source]
        source: serde_json::Error,
    },
}

/// TS12 metadata validation errors (credential package warnings).
#[derive(Debug, Error)]
pub enum Ts12MetadataError {
    /// Missing metadata entry for a required transaction data type.
    #[error("credential {credential_id} ts12 metadata missing entry for {data_type:?}")]
    MissingMetadata {
        credential_id: String,
        data_type: TransactionDataType,
    },
    /// Transaction data metadata does not match the requested type/subtype.
    #[error(
        "credential {credential_id} ts12 metadata type mismatch (expected {expected:?}, got {actual:?})"
    )]
    MetadataTypeMismatch {
        credential_id: String,
        expected: TransactionDataType,
        actual: TransactionDataType,
    },
    /// Schema is not an object.
    #[error("credential {credential_id} ts12 metadata for {data_type:?} schema must be an object")]
    SchemaNotObject {
        credential_id: String,
        data_type: TransactionDataType,
    },
    /// Schema contains an external $ref.
    #[error(
        "credential {credential_id} ts12 metadata for {data_type:?} schema contains external $ref: {reference}"
    )]
    SchemaExternalRef {
        credential_id: String,
        data_type: TransactionDataType,
        reference: String,
    },
    /// Schema compilation failed.
    #[error("credential {credential_id} ts12 metadata for {data_type:?} invalid schema: {source}")]
    SchemaInvalid {
        credential_id: String,
        data_type: TransactionDataType,
        #[source]
        source: jsonschema::ValidationError<'static>,
    },
    /// Payload failed schema validation.
    #[error(
        "credential {credential_id} ts12 metadata for {data_type:?} payload does not match schema: {source}"
    )]
    SchemaValidation {
        credential_id: String,
        data_type: TransactionDataType,
        #[source]
        source: jsonschema::ValidationError<'static>,
    },
    /// Missing claim metadata for a payload path.
    #[error(
        "credential {credential_id} ts12 metadata for {data_type:?} missing claim metadata for path {path:?}"
    )]
    MissingClaimMetadata {
        credential_id: String,
        data_type: TransactionDataType,
        path: ClaimsPathPointer,
    },
    /// Missing localized label for a claim.
    #[error(
        "credential {credential_id} ts12 metadata for {data_type:?} missing label for locale {locale} at path {path:?}"
    )]
    MissingClaimLabel {
        credential_id: String,
        data_type: TransactionDataType,
        locale: String,
        path: ClaimsPathPointer,
    },
    /// Empty localized label for a claim.
    #[error(
        "credential {credential_id} ts12 metadata for {data_type:?} empty label for locale {locale} at path {path:?}"
    )]
    EmptyClaimLabel {
        credential_id: String,
        data_type: TransactionDataType,
        locale: String,
        path: ClaimsPathPointer,
    },
    /// UI labels catalogue missing a required key.
    #[error("credential {credential_id} ts12 metadata for {data_type:?} ui_labels missing {label}")]
    MissingUiLabels {
        credential_id: String,
        data_type: TransactionDataType,
        label: &'static str,
    },
    /// UI labels catalogue missing a localized value for a required key.
    #[error(
        "credential {credential_id} ts12 metadata for {data_type:?} ui_labels missing localized {label} for locale {locale}"
    )]
    MissingLocalizedUiLabel {
        credential_id: String,
        data_type: TransactionDataType,
        label: &'static str,
        locale: String,
    },
    /// Preferred locales are required for TS12 display.
    #[error("credential {credential_id} ts12 metadata for {data_type:?} requires preferred locales")]
    MissingPreferredLocales {
        credential_id: String,
        data_type: TransactionDataType,
    },
}

/// Transaction-data decoding warnings (request-level warnings).
#[derive(Debug, Error)]
pub enum TransactionDataDecodeError {
    /// Base64url decoding failed.
    #[error("transaction_data[{index}] base64url decode failed: {source}")]
    Base64 {
        index: usize,
        #[source]
        source: base64::DecodeError,
    },
    /// JSON decoding failed.
    #[error("transaction_data[{index}] invalid json: {source}")]
    Json {
        index: usize,
        #[source]
        source: serde_json::Error,
    },
    /// Missing transaction data type.
    #[error("transaction_data[{index}] type must be non-empty")]
    MissingType { index: usize },
    /// Missing credential ids.
    #[error("transaction_data[{index}] credential_ids must be non-empty")]
    MissingCredentialIds { index: usize },
    /// Unknown credential id.
    #[error("transaction_data[{index}] unknown credential_id: {credential_id}")]
    UnknownCredentialId { index: usize, credential_id: String },
    /// Holder binding requirement failed.
    #[error("transaction_data[{index}] requires holder binding: {credential_id}")]
    HolderBindingRequired { index: usize, credential_id: String },
}

/// Credential package validation error (credential-level warnings).
#[derive(Debug, Error)]
pub enum CredentialValidationError {
    /// Credential package is invalid.
    #[error("credential {credential_id} invalid: {reason}")]
    Invalid { credential_id: String, reason: String },
}

/// Request data decoding error.
#[derive(Debug, Error)]
pub enum RequestDataError {
    /// Failed to decode request data JSON.
    #[error("request data is not valid json")]
    Json {
        #[source]
        source: serde_json::Error,
    },
}

/// OpenID4VP request errors.
#[derive(Debug, Error)]
pub enum OpenId4VpError {
    /// Request JSON is invalid.
    #[error("openid4vp request is not valid json")]
    Json {
        #[source]
        source: serde_json::Error,
    },
    /// Signed request parsing is not supported.
    #[error("signed openid4vp payload parsing is not supported for {protocol}")]
    SignedPayloadNotSupported {
        protocol: String,
        #[source]
        source: serde_json::Error,
    },
    /// Request object handling is not supported.
    #[error("openid4vp request object is not supported for {protocol}")]
    RequestObjectUnsupported { protocol: String },
    /// DCQL via `scope` is not supported.
    #[error("dcql query via scope is not supported")]
    DcqlScopeUnsupported,
}

/// OpenID4VCI request errors.
#[derive(Debug, Error)]
pub enum OpenId4VciError {
    /// Request JSON is invalid.
    #[error("openid4vci request is not valid json")]
    Json {
        #[source]
        source: serde_json::Error,
    },
    /// Credential offer fields are mutually exclusive.
    #[error("credential_offer and credential_offer_uri are mutually exclusive")]
    CredentialOfferConflict,
    /// Credential offer URI fetch is not supported.
    #[error("credential_offer_uri fetching is not supported by matcher runtime")]
    CredentialOfferUriUnsupported,
    /// Credential configuration ids must be non-empty.
    #[error("credential_configuration_ids must be non-empty")]
    CredentialConfigurationIdsEmpty,
    /// Credential configuration ids contains empty id.
    #[error("credential_configuration_ids contains an empty id")]
    CredentialConfigurationIdEmpty,
    /// Credential configuration ids must be unique.
    #[error("credential_configuration_ids must be unique")]
    CredentialConfigurationIdsNotUnique,
    /// OpenID4VCI request does not contain a credential offer.
    #[error("request data must contain credential_offer/credential_offer_uri or be a credential_offer object")]
    MissingCredentialOffer,
}

/// Credential package decoding errors.
#[derive(Debug, Error)]
pub enum CredentialPackageError {
    /// CBOR decoding failed.
    #[error("credential package CBOR decode failed")]
    CborDecode {
        #[source]
        source: ciborium::de::Error<ciborium_io::EndOfFile>,
    },
    /// JSON decoding failed.
    #[error("credential package JSON decode failed")]
    JsonDecode {
        #[source]
        source: serde_json::Error,
    },
    /// Reading package bytes failed.
    #[cfg(feature = "std")]
    #[error("credential package read failed")]
    Read {
        #[source]
        source: std::io::Error,
    },
}

/// Error type returned by the matcher framework.
#[derive(Debug, Error)]
pub enum MatcherError {
    /// Request payload is not valid JSON.
    #[error("invalid request json")]
    InvalidRequestJson(#[from] serde_json::Error),
    /// Protocol request uses a malformed `data` payload.
    #[error("invalid request data")]
    InvalidRequestData(#[from] RequestDataError),
    /// OpenID4VP request structure is invalid.
    #[error("invalid openid4vp request")]
    InvalidOpenId4Vp(#[from] OpenId4VpError),
    /// OpenID4VCI request structure is invalid.
    #[error("invalid openid4vci request")]
    InvalidOpenId4Vci(#[from] OpenId4VciError),
    /// Base64url decoding failed.
    #[error("invalid base64url data")]
    InvalidBase64(#[from] base64::DecodeError),
    /// DCQL planning failed.
    #[error("dcql planning error")]
    Dcql(#[from] dcapi_dcql::PlanError),
    /// Credential package decoding failed.
    #[error("credential package decode error")]
    CredentialPackageDecode(#[from] CredentialPackageError),
    /// Failed to serialize response metadata.
    #[error("response metadata serialization failed")]
    MetadataSerialization {
        #[source]
        source: serde_json::Error,
    },
}

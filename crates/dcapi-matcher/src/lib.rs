#![no_std]
#![doc = include_str!("../README.md")]

extern crate alloc;

#[cfg(feature = "std")]
use alloc::vec::Vec;

mod engine;
mod error;
mod config;
mod models;
mod response;
mod traits;
mod ts12;

pub use dcapi_matcher_macros::dcapi_matcher;
pub use dcapi_matcher_tracing as tracing_backend;
pub use config::{OpenId4VciConfig, OpenId4VpConfig};
pub use engine::{
    MatcherOptions, decode_request_data, match_dc_api_request, match_dc_api_request_value,
};
pub use error::{
    CredentialPackageError, CredentialValidationError, MatcherError, OpenId4VpError,
    OpenId4VciError, RequestDataError, Ts12Error, Ts12MetadataError,
};
pub use tracing_core::Level as LogLevel;
pub use models::*;
pub use response::*;
pub use traits::*;
pub use ts12::{
    Ts12ClaimMetadata, Ts12LocalizedLabel, Ts12LocalizedValue, Ts12PaymentSummary,
    Ts12TransactionMetadata, Ts12UiLabels,
};

use serde::de::DeserializeOwned;
#[cfg(feature = "std")]
use std::io::Read;

/// Decodes a credential package from CBOR bytes.
pub fn decode_cbor_package<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, MatcherError> {
    ciborium::from_reader(bytes).map_err(|err| {
        let error =
            MatcherError::CredentialPackageDecode(crate::error::CredentialPackageError::CborDecode {
                source: err,
            });
        tracing::error!(error = %error, "credential package decode error");
        error
    })
}

/// Reads all bytes from a credential reader and decodes a CBOR package.
#[cfg(feature = "std")]
pub fn decode_cbor_package_from_reader<T: DeserializeOwned, R: Read>(
    mut reader: R,
) -> Result<T, MatcherError> {
    let mut bytes = Vec::new();
    if let Err(err) = reader.read_to_end(&mut bytes) {
        let error = MatcherError::CredentialPackageDecode(
            crate::error::CredentialPackageError::Read { source: err },
        );
        tracing::error!(error = %error, "credential package decode error");
        return Err(error);
    }
    decode_cbor_package(bytes.as_slice())
}

/// Decodes a credential package from JSON bytes.
pub fn decode_json_package<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, MatcherError> {
    serde_json::from_slice(bytes).map_err(|err| {
        let error =
            MatcherError::CredentialPackageDecode(crate::error::CredentialPackageError::JsonDecode {
                source: err,
            });
        tracing::error!(error = %error, "credential package decode error");
        error
    })
}

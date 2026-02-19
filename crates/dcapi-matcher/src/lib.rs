#![doc = include_str!("../README.md")]

extern crate alloc;

mod config;
pub mod diagnostics;
mod engine;
mod error;
mod models;
mod profile;
mod traits;
mod ts12;

pub use android_credman::{
    CredentialEntry, CredentialSet, CredentialSlot, Field, InlineIssuanceEntry, MatcherResponse,
    MatcherResult, PaymentEntry, StringIdEntry,
};
pub use config::{OpenId4VciConfig, OpenId4VpConfig};
pub use dcapi_matcher_macros::dcapi_matcher;
pub use diagnostics::LogLevel;
pub use engine::{MatcherOptions, decode_request_data, match_dc_api_request};
pub use error::{
    CredentialPackageError, MatcherError, OpenId4VciError, OpenId4VpError, RequestDataError,
    Ts12Error, Ts12MetadataError,
};
pub use models::*;
pub use profile::{DefaultProfile, HaipProfile, HaipProfileError, Profile, ProfileError};
pub use traits::*;
pub use ts12::{
    Ts12ClaimMetadata, Ts12LocalizedLabel, Ts12LocalizedValue, Ts12PaymentSummary,
    Ts12TransactionMetadata, Ts12UiLabels,
};

use crate::diagnostics::ErrorExt;
use serde::de::DeserializeOwned;

/// Decodes a credential package from JSON bytes.
pub fn decode_json_package<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, MatcherError> {
    serde_json::from_slice(bytes).map_err(|err| {
        let error = MatcherError::CredentialPackageDecode(
            crate::error::CredentialPackageError::JsonDecode { source: err },
        );
        error.error();
        error
    })
}

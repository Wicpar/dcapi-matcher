use crate::*;
use std::io::Read;

/// Emits a value to the host using the Credential Manager output ABI.
///
/// # Purpose
/// Types like `StringIdEntry`, `PaymentEntry`, and `CredentialSet` implement this trait
/// so they can be applied uniformly from matcher code.
///
/// # `options`
/// Implementations may use `options` as additional context (for example, set id/index).
pub trait CredmanApply<T = ()> {
    fn apply(&self, options: T);
}

/// Convenience extension for `CredmanApply<()>`.
///
/// This allows calling `x.apply()` instead of `CredmanApply::apply(&x, ())`.
pub trait CredmanApplyExt {
    fn apply(&self);
}

impl<S> CredmanApplyExt for S
where
    S: CredmanApply<()>,
{
    fn apply(&self) {
        CredmanApply::apply(self, ());
    }
}

/// Builds a type from the host request payload.
///
/// # Typical Usage
/// - `String::from_request()` for JSON request text.
/// - `Vec::<u8>::from_request()` for raw bytes.
pub trait FromRequest {
    fn from_request() -> Self;
}

impl FromRequest for Vec<u8> {
    fn from_request() -> Self {
        get_request()
    }
}

impl FromRequest for String {
    fn from_request() -> Self {
        get_request_string()
    }
}

/// Builds a type from the host credentials blob.
///
/// # Typical Usage
/// - `CredentialReader::from_credentials()` for streaming decode.
/// - `Vec::<u8>::from_credentials()` for eager read.
pub trait FromCredentials {
    fn from_credentials() -> Self;
}

impl FromCredentials for CredentialReader {
    fn from_credentials() -> Self {
        CredentialReader::new()
    }
}

impl FromCredentials for Vec<u8> {
    fn from_credentials() -> Self {
        let mut reader = CredentialReader::new();
        let mut buffer = Vec::with_capacity(reader.len() as usize);
        reader.read_to_end(&mut buffer).unwrap_or(0);
        buffer
    }
}

impl FromCredentials for String {
    fn from_credentials() -> Self {
        let bytes: Vec<u8> = FromCredentials::from_credentials();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

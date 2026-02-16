use crate::models::{ClaimValue, ClaimsQuery, CredentialQuery, TransactionData, TrustedAuthority};
use crate::path::ClaimsPathPointer;

/// Normalized credential format identifiers used by the planner.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CredentialFormat {
    /// ISO/IEC mdoc (`mso_mdoc`).
    MsoMdoc,
    /// SD-JWT VC (`dc+sd-jwt`).
    DcSdJwt,
    /// Any other wallet-local or extension format identifier.
    Other(String),
}

impl CredentialFormat {
    /// Convert a query format string into the planner enum.
    pub fn from_query_format(format: &str) -> Self {
        match format {
            "mso_mdoc" => Self::MsoMdoc,
            "dc+sd-jwt" => Self::DcSdJwt,
            _ => Self::Other(format.to_owned()),
        }
    }
}

/// Outcome of strict claim value matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueMatch {
    /// Claim value is present and exactly matches one requested value.
    Match,
    /// No exact match (including unknown/unavailable value).
    NoMatch,
}

/// Wallet credential abstraction consumed by the DCQL planner.
///
/// The trait is intentionally minimal and uses references (`CredentialRef`) so callers
/// can keep zero-copy handles to wallet-internal credential records.
pub trait CredentialStore {
    type CredentialRef: Clone + Eq + std::hash::Hash;

    /// Enumerate credential references, optionally filtered by format.
    fn list_credentials(&self, format: Option<&str>) -> Vec<Self::CredentialRef>;

    /// Format identifier for the credential.
    fn format(&self, cred: &Self::CredentialRef) -> CredentialFormat;

    /// Returns true if the credential matches the provided VCT (including any `extends` values).
    fn has_vct(&self, _cred: &Self::CredentialRef, _vct: &str) -> bool {
        false
    }

    /// Returns true if the credential can do cryptographic holder binding.
    fn supports_holder_binding(&self, _cred: &Self::CredentialRef) -> bool {
        false
    }

    /// Returns true if the credential has the provided ISO mdoc doctype.
    fn has_doctype(&self, _cred: &Self::CredentialRef, _doctype: &str) -> bool {
        false
    }

    /// Returns true if the credential can sign for the provided transaction data constraint.
    ///
    /// Implementations should validate both the type/subtype and any associated
    /// metadata structure required by the wallet policy.
    fn can_sign_transaction_data(
        &self,
        _cred: &Self::CredentialRef,
        _transaction_data: &TransactionData,
    ) -> bool {
        false
    }

    /// Returns true if the credential can provide a claim at this path.
    fn has_claim_path(&self, cred: &Self::CredentialRef, path: &ClaimsPathPointer) -> bool;

    /// Strict value matching for claim values.
    ///
    /// Return `Match` only when the claim exists and equals one of `expected_values`.
    /// Return `NoMatch` for any non-match or when value comparison cannot be performed.
    fn match_claim_value(
        &self,
        cred: &Self::CredentialRef,
        path: &ClaimsPathPointer,
        expected_values: &[ClaimValue],
    ) -> ValueMatch;

    /// Best-effort trusted authority matching.
    fn matches_trusted_authorities(
        &self,
        _cred: &Self::CredentialRef,
        _trusted_authorities: &[TrustedAuthority],
    ) -> bool {
        true
    }

    /// Default claim matching using the DCQL engine.
    fn match_claims(
        &self,
        cred: &Self::CredentialRef,
        query: &CredentialQuery,
    ) -> Option<Vec<ClaimsQuery>> {
        crate::planner::match_claims(self, cred, query)
    }
}

use core::convert::Infallible;
use crate::models::{OpenId4VciRequest, OpenId4VpRequest};
use dcapi_dcql::{ClaimsQuery, CredentialQuery};
use thiserror::Error;

/// Profile that can validate and normalize protocol requests.
pub trait Profile {
    type Error;

    /// Validate and optionally transform an OpenID4VP request.
    fn apply_openid4vp(
        &self,
        protocol: &str,
        request: OpenId4VpRequest,
    ) -> Result<OpenId4VpRequest, Self::Error>;

    /// Validate and optionally transform an OpenID4VCI request.
    fn apply_openid4vci(
        &self,
        request: OpenId4VciRequest,
    ) -> Result<OpenId4VciRequest, Self::Error>;
}

/// Default profile: no validation beyond parsing.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultProfile;

impl Profile for DefaultProfile {
    type Error = Infallible;

    fn apply_openid4vp(
        &self,
        _protocol: &str,
        request: OpenId4VpRequest,
    ) -> Result<OpenId4VpRequest, Self::Error> {
        Ok(request)
    }

    fn apply_openid4vci(
        &self,
        request: OpenId4VciRequest,
    ) -> Result<OpenId4VciRequest, Self::Error> {
        Ok(request)
    }
}

/// OpenID4VC HAIP profile checks.
#[derive(Debug, Clone, Copy, Default)]
pub struct HaipProfile;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HaipProfileError {
    #[error("response_mode must be dc_api.jwt")]
    InvalidResponseMode,
    #[error("response_type must be vp_token")]
    InvalidResponseType,
    #[error("dcql_query must be present")]
    MissingDcqlQuery,
    #[error("presentation_definition must not be present")]
    PresentationDefinitionPresent,
    #[error("mso_mdoc claim missing intent_to_retain at credential index {index}")]
    MissingIntentToRetain { index: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProfileError {
    #[error("haip profile violation: {0}")]
    Haip(#[from] HaipProfileError),
}

impl From<Infallible> for ProfileError {
    fn from(value: Infallible) -> Self {
        match value {}
    }
}

impl Profile for HaipProfile {
    type Error = HaipProfileError;

    fn apply_openid4vp(
        &self,
        _protocol: &str,
        request: OpenId4VpRequest,
    ) -> Result<OpenId4VpRequest, Self::Error> {
        if request.response_mode.as_deref() != Some("dc_api.jwt") {
            return Err(HaipProfileError::InvalidResponseMode);
        }
        if request.response_type.as_deref() != Some("vp_token") {
            return Err(HaipProfileError::InvalidResponseType);
        }
        if request.presentation_definition.is_some() {
            return Err(HaipProfileError::PresentationDefinitionPresent);
        }
        let Some(dcql_query) = request.dcql_query.as_ref() else {
            return Err(HaipProfileError::MissingDcqlQuery);
        };

        for (index, credential) in dcql_query.credentials.iter().enumerate() {
            let CredentialQuery::MsoMdoc { common, .. } = credential else {
                continue;
            };
            if let Some(claims) = common.claims.as_deref()
                && claims_missing_intent_to_retain(claims)
            {
                return Err(HaipProfileError::MissingIntentToRetain { index });
            }
        }

        Ok(request)
    }

    fn apply_openid4vci(
        &self,
        request: OpenId4VciRequest,
    ) -> Result<OpenId4VciRequest, Self::Error> {
        Ok(request)
    }
}

fn claims_missing_intent_to_retain(claims: &[ClaimsQuery]) -> bool {
    claims.iter().any(|claim| claim.intent_to_retain.is_none())
}

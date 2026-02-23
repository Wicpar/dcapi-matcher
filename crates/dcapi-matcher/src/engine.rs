use crate::config::OpenId4VpConfig;
use crate::diagnostics::{self, ErrorExt};
use crate::error::{
    MatcherError, OpenId4VpError, RequestDataError, TransactionDataDecodeError,
};
use crate::models::{
    DcApiRequest, DcApiRequestItem, OpenId4VpMultiSignedData, OpenId4VpRequest,
    OpenId4VpSignedData, OpenId4VpSignedEnvelope, OpenId4VpSignedFormat,
    OpenId4VpSignedSignature, OpenId4VpUnsignedData, PROTOCOL_OPENID4VP,
    PROTOCOL_OPENID4VP_V1_MULTISIGNED, PROTOCOL_OPENID4VP_V1_SIGNED,
    PROTOCOL_OPENID4VP_V1_UNSIGNED, RequestData, TransactionDataInput,
};
use crate::profile::{Profile, ProfileError};
use crate::traits::{DcqlSelectionContext, MatcherStore};
use crate::ts12;
use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use android_credman::{get_calling_app_info, get_request_string};
use android_credman::{
    CredentialEntry, CredentialSet, CredentialSlot, Field, MatcherResponse, PaymentEntry,
    StringIdEntry,
};
use base64::Engine;
use c8str::{C8Str, C8String, c8format};
use core::ffi::CStr;
use core::hash::Hash;
use dcapi_dcql::{
    CredentialFormat, PathElement, PlanOptions, SelectionAlternative, TransactionData,
};
use serde::de::DeserializeOwned;
use serde_json::Value;

/// Matcher framework options.
#[derive(Debug, Clone, Default)]
pub struct MatcherOptions {
    /// DCQL planner behavior.
    pub dcql: PlanOptions,
}

/// Parses and matches the DC API request from the Credman host.
pub fn match_dc_api_request<'a, S, P>(
    store: &'a S,
    options: &MatcherOptions,
    profile: &P,
) -> Result<MatcherResponse<'a>, MatcherError>
where
    S: MatcherStore,
    S::CredentialRef: Clone + Eq + Hash,
    P: Profile,
    P::Error: Into<ProfileError>,
{
    diagnostics::begin();
    diagnostics::set_level(store.log_level());
    let request_json = get_request_string();
    let request: DcApiRequest = match serde_json::from_str(&request_json) {
        Ok(request) => request,
        Err(err) => {
            let error = MatcherError::InvalidRequestJson(err);
            error.error();
            return Err(error);
        }
    };
    let result = match_dc_api_request_value_impl(&request, store, options, profile);
    if let Err(err) = &result {
        err.error();
    }
    result
}

fn match_dc_api_request_value_impl<'a, S, P>(
    request: &DcApiRequest,
    store: &'a S,
    options: &MatcherOptions,
    profile: &P,
) -> Result<MatcherResponse<'a>, MatcherError>
where
    S: MatcherStore,
    S::CredentialRef: Clone + Eq + Hash,
    P: Profile,
    P::Error: Into<ProfileError>,
{
    let vp_config = store.openid4vp_config();
    let mut response = MatcherResponse::new();

    for (request_index, item) in request.requests.iter().enumerate() {
        match item {
            DcApiRequestItem::OpenId4VpUnsigned { data } => {
                if !vp_config.enabled {
                    continue;
                }
                let request = decode_openid4vp_unsigned_data(data)?;
                let result = match_openid4vp_request(
                    request_index,
                    PROTOCOL_OPENID4VP_V1_UNSIGNED,
                    request,
                    store,
                    &vp_config,
                    options,
                    profile,
                );
                match result {
                    Ok(result) => {
                        response = response.add_results(result.results.into_owned());
                    }
                    Err(MatcherError::Profile(err)) => {
                        err.error();
                        return Ok(MatcherResponse::new());
                    }
                    Err(err) => return Err(err),
                }
            }
            DcApiRequestItem::OpenId4VpSigned { data } => {
                if !vp_config.enabled || !vp_config.allow_signed_requests {
                    continue;
                }
                let envelope =
                    decode_openid4vp_signed_envelope(PROTOCOL_OPENID4VP_V1_SIGNED, data)?;
                ensure_signed_request_verified(store, PROTOCOL_OPENID4VP_V1_SIGNED, &envelope)?;
                let request =
                    decode_openid4vp_request_from_payload(PROTOCOL_OPENID4VP_V1_SIGNED, &envelope)?;
                ensure_expected_origins(PROTOCOL_OPENID4VP_V1_SIGNED, &request)?;
                let result = match_openid4vp_request(
                    request_index,
                    PROTOCOL_OPENID4VP_V1_SIGNED,
                    request,
                    store,
                    &vp_config,
                    options,
                    profile,
                );
                match result {
                    Ok(result) => {
                        response = response.add_results(result.results.into_owned());
                    }
                    Err(MatcherError::Profile(err)) => {
                        err.error();
                        return Ok(MatcherResponse::new());
                    }
                    Err(err) => return Err(err),
                }
            }
            DcApiRequestItem::OpenId4VpMultiSigned { data } => {
                if !vp_config.enabled || !vp_config.allow_signed_requests {
                    continue;
                }
                let envelope =
                    decode_openid4vp_multisigned_envelope(PROTOCOL_OPENID4VP_V1_MULTISIGNED, data)?;
                ensure_signed_request_verified(
                    store,
                    PROTOCOL_OPENID4VP_V1_MULTISIGNED,
                    &envelope,
                )?;
                let request = decode_openid4vp_request_from_payload(
                    PROTOCOL_OPENID4VP_V1_MULTISIGNED,
                    &envelope,
                )?;
                ensure_expected_origins(PROTOCOL_OPENID4VP_V1_MULTISIGNED, &request)?;
                let result = match_openid4vp_request(
                    request_index,
                    PROTOCOL_OPENID4VP_V1_MULTISIGNED,
                    request,
                    store,
                    &vp_config,
                    options,
                    profile,
                );
                match result {
                    Ok(result) => {
                        response = response.add_results(result.results.into_owned());
                    }
                    Err(MatcherError::Profile(err)) => {
                        err.error();
                        return Ok(MatcherResponse::new());
                    }
                    Err(err) => return Err(err),
                }
            }
            DcApiRequestItem::Unknown => {}
        }
    }

    Ok(response)
}

fn decode_openid4vp_unsigned_data(
    data: &OpenId4VpUnsignedData,
) -> Result<OpenId4VpRequest, MatcherError> {
    match data {
        OpenId4VpUnsignedData::Params(request) => Ok(request.clone()),
        OpenId4VpUnsignedData::JsonString(raw) => serde_json::from_str(raw).map_err(|err| {
            MatcherError::InvalidOpenId4Vp(OpenId4VpError::Json { source: err })
        }),
    }
}

fn decode_openid4vp_signed_envelope(
    protocol: &str,
    data: &OpenId4VpSignedData,
) -> Result<OpenId4VpSignedEnvelope, MatcherError> {
    let mut parts = data.request.split('.');
    let header_b64 = parts.next().unwrap_or_default();
    let payload_b64 = parts.next().unwrap_or_default();
    let signature_b64 = parts.next().unwrap_or_default();
    if header_b64.is_empty() || payload_b64.is_empty() || signature_b64.is_empty() {
        return Err(MatcherError::InvalidOpenId4Vp(
            OpenId4VpError::SignedRequestMalformed {
                protocol: protocol.to_string(),
            },
        ));
    }
    if parts.next().is_some() {
        return Err(MatcherError::InvalidOpenId4Vp(
            OpenId4VpError::SignedRequestMalformed {
                protocol: protocol.to_string(),
            },
        ));
    }
    let protected = decode_base64url_json(protocol, header_b64)?;
    let payload = decode_base64url_json(protocol, payload_b64)?;
    Ok(OpenId4VpSignedEnvelope {
        format: OpenId4VpSignedFormat::Compact,
        payload_b64: payload_b64.to_string(),
        payload,
        signatures: vec![OpenId4VpSignedSignature {
            protected_b64: header_b64.to_string(),
            protected,
            signature_b64: signature_b64.to_string(),
            header: None,
        }],
    })
}

fn decode_openid4vp_multisigned_envelope(
    protocol: &str,
    data: &OpenId4VpMultiSignedData,
) -> Result<OpenId4VpSignedEnvelope, MatcherError> {
    if data.signatures.is_empty() {
        return Err(MatcherError::InvalidOpenId4Vp(
            OpenId4VpError::SignedRequestMalformed {
                protocol: protocol.to_string(),
            },
        ));
    }
    let payload = decode_base64url_json(protocol, data.payload.as_str())?;
    let mut signatures = Vec::with_capacity(data.signatures.len());
    for signature in &data.signatures {
        if signature.protected.is_empty() || signature.signature.is_empty() {
            return Err(MatcherError::InvalidOpenId4Vp(
                OpenId4VpError::SignedRequestMalformed {
                    protocol: protocol.to_string(),
                },
            ));
        }
        let protected = decode_base64url_json(protocol, signature.protected.as_str())?;
        signatures.push(OpenId4VpSignedSignature {
            protected_b64: signature.protected.clone(),
            protected,
            signature_b64: signature.signature.clone(),
            header: signature.header.clone(),
        });
    }
    Ok(OpenId4VpSignedEnvelope {
        format: OpenId4VpSignedFormat::Json,
        payload_b64: data.payload.clone(),
        payload,
        signatures,
    })
}

fn decode_openid4vp_request_from_payload(
    protocol: &str,
    envelope: &OpenId4VpSignedEnvelope,
) -> Result<OpenId4VpRequest, MatcherError> {
    serde_json::from_value(envelope.payload.clone()).map_err(|err| {
        MatcherError::InvalidOpenId4Vp(OpenId4VpError::SignedPayloadNotSupported {
            protocol: protocol.to_string(),
            source: err,
        })
    })
}

fn ensure_signed_request_verified<S: MatcherStore>(
    store: &S,
    protocol: &str,
    envelope: &OpenId4VpSignedEnvelope,
) -> Result<(), MatcherError>
{
    if !store.verify_openid4vp_signed_request(protocol, envelope) {
        return Err(MatcherError::InvalidOpenId4Vp(
            OpenId4VpError::SignedRequestUnverified {
                protocol: protocol.to_string(),
            },
        ));
    }
    Ok(())
}

fn ensure_expected_origins(
    protocol: &str,
    request: &OpenId4VpRequest,
) -> Result<(), MatcherError> {
    let expected = expected_origins_from_request(request).ok_or_else(|| {
        MatcherError::InvalidOpenId4Vp(OpenId4VpError::ExpectedOriginsMissing {
            protocol: protocol.to_string(),
        })
    })?;
    let origin = calling_origin().ok_or_else(|| {
        MatcherError::InvalidOpenId4Vp(OpenId4VpError::OriginMissing {
            protocol: protocol.to_string(),
        })
    })?;
    if expected.iter().any(|value| value == &origin) {
        return Ok(());
    }
    Err(MatcherError::InvalidOpenId4Vp(
        OpenId4VpError::OriginMismatch {
            protocol: protocol.to_string(),
            origin,
        },
    ))
}

fn expected_origins_from_request(request: &OpenId4VpRequest) -> Option<Vec<String>> {
    let value = request.extra.get("expected_origins")?;
    let origins = value.as_array()?;
    if origins.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(origins.len());
    for entry in origins {
        let entry = entry.as_str()?;
        if entry.is_empty() {
            return None;
        }
        out.push(entry.to_string());
    }
    Some(out)
}

fn calling_origin() -> Option<String> {
    let app_info = get_calling_app_info();
    let origin = app_info.origin();
    if origin.is_empty() {
        None
    } else {
        Some(origin.to_string())
    }
}

fn decode_base64url_json(protocol: &str, input: &str) -> Result<Value, MatcherError> {
    let decoded = decode_base64url(input).map_err(MatcherError::InvalidBase64)?;
    serde_json::from_slice(&decoded).map_err(|err| {
        MatcherError::InvalidOpenId4Vp(OpenId4VpError::SignedPayloadNotSupported {
            protocol: protocol.to_string(),
            source: err,
        })
    })
}

fn match_openid4vp_request<'s, S, P>(
    request_index: usize,
    protocol: &str,
    mut request: OpenId4VpRequest,
    store: &'s S,
    config: &OpenId4VpConfig,
    options: &MatcherOptions,
    profile: &P,
) -> Result<MatcherResponse<'s>, MatcherError>
where
    S: MatcherStore,
    S::CredentialRef: Clone + Eq + Hash,
    P: Profile,
    P::Error: Into<ProfileError>,
{
    let scope_present = request.extra.get("scope").is_some();
    request = apply_openid4vp_profile(profile, protocol, request)?;

    let mut response = MatcherResponse::new();

    if request.response_mode.as_deref() == Some("dc_api.jwt") && !config.allow_response_mode_jwt {
        return Ok(response);
    }

    let dcql_query = match request.dcql_query.take() {
        Some(dcql_query) => {
            if !config.allow_dcql {
                return Ok(response);
            }
            dcql_query
        }
        None => {
            if scope_present {
                if !config.allow_dcql_scope {
                    return Ok(response);
                }
                return Err(MatcherError::InvalidOpenId4Vp(
                    OpenId4VpError::DcqlScopeUnsupported,
                ));
            }
            return Ok(response);
        }
    };

    if !config.allow_transaction_data && request.transaction_data.is_some() {
        return Ok(response);
    }
    let transaction_data = decode_transaction_data(request.transaction_data.as_deref());
    let transaction_data = if let Some(data) = transaction_data {
        ensure_transaction_data_satisfiable(&dcql_query, data.as_slice())
            .map_err(MatcherError::InvalidOpenId4Vp)?;
        Some(data)
    } else {
        None
    };
    let plan = match dcapi_dcql::plan_selection(
        &dcql_query,
        transaction_data.as_deref(),
        store,
        &options.dcql,
    ) {
        Ok(plan) => plan,
        Err(dcapi_dcql::PlanError::Unsatisfied) => {
            diagnostics::warn("dcql query unsatisfied; no matching credentials");
            return Ok(response);
        }
        Err(err) => return Err(MatcherError::Dcql(err)),
    };
    for (alternative_index, alternative) in plan.alternatives.iter().enumerate() {
        let set = set_from_dcql_alternative(
            store,
            request_index,
            alternative_index,
            alternative,
            transaction_data.as_deref().unwrap_or_default(),
            protocol,
            options,
        )?;
        response = response.add_group(set);
    }
    Ok(response)
}

fn apply_openid4vp_profile<P>(
    profile: &P,
    protocol: &str,
    request: OpenId4VpRequest,
) -> Result<OpenId4VpRequest, MatcherError>
where
    P: Profile,
    P::Error: Into<ProfileError>,
{
    profile
        .apply_openid4vp(protocol, request)
        .map_err(|err| MatcherError::Profile(err.into()))
}

fn set_from_dcql_alternative<'s, 't, S>(
    store: &'s S,
    request_index: usize,
    alternative_index: usize,
    alternative: &'t SelectionAlternative<S::CredentialRef>,
    transaction_data: &'t [TransactionData],
    protocol: &str,
    options: &MatcherOptions,
) -> Result<CredentialSet<'s>, MatcherError>
where
    S: MatcherStore,
    S::CredentialRef: Clone + Eq + Hash,
{
    let set_id = leak_c8string(set_id_for_dcql(protocol, request_index, alternative_index));
    let mut set = CredentialSet::new(set_id);

    for entry in &alternative.entries {
        let context = DcqlSelectionContext {
            request_index,
            alternative_index,
            query_id: entry.query.id.as_str(),
            selected_claims: entry.query.selected_claims.as_slice(),
            transaction_data,
            transaction_data_indices: entry.transaction_data_indices.as_slice(),
        };
        let alternatives = entry
            .query
            .credentials
            .iter()
            .filter(|cred| supports_protocol(store, cred, protocol))
            .filter_map(|cred| match build_entry(store, cred, &context, options) {
                Ok(entry) => Some(entry),
                Err(err) => {
                    err.error();
                    None
                }
            })
            .collect::<Vec<CredentialEntry<'s>>>();
        if alternatives.is_empty() {
            continue;
        }
        let slot = CredentialSlot::new(alternatives);
        set = set.add_slot(slot);
    }

    Ok(set)
}

fn supports_protocol<S: MatcherStore>(
    store: &S,
    cred: &S::CredentialRef,
    protocol: &str,
) -> bool {
    if store.supports_protocol(cred, protocol) {
        return true;
    }
    if protocol == PROTOCOL_OPENID4VP_V1_UNSIGNED {
        return store.supports_protocol(cred, PROTOCOL_OPENID4VP);
    }
    if protocol == PROTOCOL_OPENID4VP {
        return store.supports_protocol(cred, PROTOCOL_OPENID4VP_V1_UNSIGNED);
    }
    false
}

fn build_entry<'s, 'c, S>(
    store: &'s S,
    cred: &S::CredentialRef,
    context: &DcqlSelectionContext<'c>,
    _options: &MatcherOptions,
) -> Result<CredentialEntry<'s>, MatcherError>
where
    S: MatcherStore + ?Sized,
{
    let credential_id = store.credential_id(cred);
    let title = store.credential_title(cred);
    let icon = store.credential_icon(cred);
    let subtitle = store.credential_subtitle(cred);
    let disclaimer = store.credential_disclaimer(cred);
    let warning = store.credential_warning(cred);
    let ts12_display = ts12::build_display_for_context(
        store,
        cred,
        credential_id.as_ref(),
        context,
        store.locales(),
    )?;
    let (ts12_fields, payment_summary) = match ts12_display {
        Some(display) => (display.transaction_fields, display.payment_summary),
        None => (Vec::new(), None),
    };

    let mut fields = ts12_fields
        .into_iter()
        .map(|field| {
            Field::new(
                cstr_from_cow(field.display_name),
                Some(cstr_from_cow(field.display_value)),
            )
        })
        .collect::<Vec<_>>();
    for claim in context.selected_claims {
        if claim
            .path
            .iter()
            .any(|segment| matches!(segment, PathElement::Wildcard))
        {
            continue;
        }
        let Some(label) = store.get_credential_field_label(cred, &claim.path) else {
            continue;
        };
        let value = store.get_credential_field_value(cred, &claim.path);
        fields.push(Field::new(cstr_from_cow(label), value.map(cstr_from_cow)));
    }
    let metadata = build_metadata(context)?;

    let credential_id = cstr_from_cow(credential_id);
    let title = cstr_from_cow(title);
    let subtitle = subtitle.map(cstr_from_cow);
    let disclaimer = disclaimer.map(cstr_from_cow);
    let warning = warning.map(cstr_from_cow);

    if let Some(summary) = payment_summary {
        let mut entry = PaymentEntry::new(
            credential_id,
            cstr_from_cow(summary.merchant_name),
            cstr_from_cow(summary.transaction_amount),
        );
        entry.payment_method_name = Some(title);
        entry.payment_method_subtitle = subtitle;
        entry.payment_method_icon = icon.map(Cow::Borrowed);
        entry.additional_info = summary.additional_info.map(cstr_from_cow);
        entry.metadata = metadata;
        entry.fields = Cow::Owned(fields);
        return Ok(CredentialEntry::Payment(entry));
    }

    let mut entry = StringIdEntry::new(credential_id, title);
    entry.icon = icon.map(Cow::Borrowed);
    entry.subtitle = subtitle;
    entry.disclaimer = disclaimer;
    entry.warning = warning;
    entry.metadata = metadata;
    entry.fields = Cow::Owned(fields);

    Ok(CredentialEntry::StringId(entry))
}

fn build_metadata(
    context: &DcqlSelectionContext<'_>,
) -> Result<Option<&'static CStr>, MatcherError> {
    let mut obj = serde_json::Map::new();
    obj.insert(
        "credential_id".to_string(),
        Value::String(context.query_id.to_string()),
    );
    obj.insert(
        "transaction_data_indices".to_string(),
        Value::Array(
            context
                .transaction_data_indices
                .iter()
                .map(|idx| Value::from(*idx as u64))
                .collect(),
        ),
    );
    let value = Value::Object(obj);
    let bytes = serde_json::to_vec(&value)
        .map_err(|err| MatcherError::MetadataSerialization { source: err })?;
    Ok(Some(cstr_from_bytes(bytes)))
}

fn set_id_for_dcql(protocol: &str, request_index: usize, alternative_index: usize) -> C8String {
    let protocol_sanitized;
    let protocol = if protocol.as_bytes().contains(&0) {
        protocol_sanitized = protocol.replace('\0', "");
        protocol_sanitized.as_str()
    } else {
        protocol
    };
    c8format!("{protocol}:{request_index}:dcql:{alternative_index}")
}

fn c8string_from_bytes(bytes: impl Into<Vec<u8>>) -> C8String {
    let mut bytes = bytes.into();
    bytes.retain(|byte| *byte != 0);
    C8String::from_vec(bytes).unwrap_or_else(|_| C8String::new())
}

fn cstr_from_bytes(bytes: impl Into<Vec<u8>>) -> &'static CStr {
    leak_c8string(c8string_from_bytes(bytes))
}

fn cstr_from_cow<'a>(value: Cow<'a, C8Str>) -> &'a CStr {
    match value {
        Cow::Borrowed(value) => value.as_c_str(),
        Cow::Owned(value) => leak_c8string(value),
    }
}

fn leak_c8string(value: C8String) -> &'static CStr {
    Box::leak(value.into_c_string().into_boxed_c_str())
}

fn decode_transaction_data(
    transaction_data: Option<&[TransactionDataInput]>,
) -> Option<Vec<TransactionData>> {
    let transaction_data = transaction_data?;

    let mut out = Vec::with_capacity(transaction_data.len());
    for (index, item) in transaction_data.iter().enumerate() {
        let parsed = match item {
            TransactionDataInput::Decoded(data) => data.as_ref().clone(),
            TransactionDataInput::Encoded(encoded) => {
                let bytes = match decode_base64url(encoded) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        let warn = TransactionDataDecodeError::Base64 { index, source: err };
                        warn.warn();
                        continue;
                    }
                };
                match serde_json::from_slice::<TransactionData>(&bytes) {
                    Ok(parsed) => parsed,
                    Err(err) => {
                        let warn = TransactionDataDecodeError::Json { index, source: err };
                        warn.warn();
                        continue;
                    }
                }
            }
        };

        if parsed.r#type.is_empty() {
            let warn = TransactionDataDecodeError::MissingType { index };
            warn.warn();
            continue;
        }
        if parsed.credential_ids.is_empty() {
            let warn = TransactionDataDecodeError::MissingCredentialIds { index };
            warn.warn();
            continue;
        }
        if let Err(err) = ts12::validate_ts12_transaction_data(index, &parsed) {
            err.warn();
            continue;
        }

        out.push(parsed);
    }
    Some(out)
}

fn ensure_transaction_data_satisfiable(
    query: &dcapi_dcql::DcqlQuery,
    transaction_data: &[TransactionData],
) -> Result<(), OpenId4VpError> {
    for (index, data) in transaction_data.iter().enumerate() {
        let mut satisfiable = false;
        let mut first_error = None;
        for credential_id in &data.credential_ids {
            let Some(query_cred) = query
                .credentials
                .iter()
                .find(|candidate| candidate.id() == Some(credential_id.as_str()))
            else {
                if first_error.is_none() {
                    first_error = Some(TransactionDataDecodeError::UnknownCredentialId {
                        index,
                        credential_id: credential_id.clone(),
                    });
                }
                continue;
            };
            if query_cred.format() == CredentialFormat::DcSdJwt
                && query_cred.require_cryptographic_holder_binding() == Some(false)
            {
                if first_error.is_none() {
                    first_error = Some(TransactionDataDecodeError::HolderBindingRequired {
                        index,
                        credential_id: credential_id.clone(),
                    });
                }
                continue;
            }
            satisfiable = true;
            break;
        }
        if !satisfiable {
            if let Some(err) = first_error.as_ref() {
                err.warn();
            }
            return Err(OpenId4VpError::TransactionDataUnsatisfied {
                index,
                credential_ids: data.credential_ids.clone(),
            });
        }
    }
    Ok(())
}

fn decode_base64url(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    match engine.decode(input) {
        Ok(bytes) => Ok(bytes),
        Err(_) => {
            let padded = pad_base64url(input);
            engine.decode(padded)
        }
    }
}

fn pad_base64url(input: &str) -> String {
    let remainder = input.len() % 4;
    if remainder == 0 {
        return input.to_string();
    }
    let mut out = input.to_string();
    for _ in 0..(4 - remainder) {
        out.push('=');
    }
    out
}


/// Parses JSON from `RequestData` and deserializes into a target type.
pub fn decode_request_data<T: DeserializeOwned>(data: &RequestData) -> Result<T, MatcherError> {
    let value = data
        .to_value()
        .map_err(|err| MatcherError::InvalidRequestData(RequestDataError::Json { source: err }))?;
    serde_json::from_value(value)
        .map_err(|err| MatcherError::InvalidRequestData(RequestDataError::Json { source: err }))
}

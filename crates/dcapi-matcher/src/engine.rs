use crate::config::{OpenId4VciConfig, OpenId4VpConfig};
use crate::diagnostics::{self, ErrorExt};
use crate::error::{
    MatcherError, OpenId4VciError, OpenId4VpError, RequestDataError, TransactionDataDecodeError,
};
use crate::models::{
    CredentialOffer, DcApiRequest, OpenId4VciRequest, OpenId4VpRequest, PROTOCOL_OPENID4VCI,
    PROTOCOL_OPENID4VP, PROTOCOL_OPENID4VP_V1_MULTISIGNED, PROTOCOL_OPENID4VP_V1_SIGNED,
    PROTOCOL_OPENID4VP_V1_UNSIGNED, RequestData, TransactionDataInput,
};
use crate::profile::{Profile, ProfileError};
use crate::traits::{DcqlSelectionContext, MatcherStore};
use crate::ts12;
use alloc::borrow::Cow;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use android_credman::{
    CredentialEntry, CredentialSet, CredentialSlot, Field, InlineIssuanceEntry, MatcherResponse,
    PaymentEntry, StringIdEntry,
};
use android_credman::get_request_string;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use core::hash::Hash;
use dcapi_dcql::{CredentialFormat, PathElement, PlanOptions, SelectionAlternative, TransactionData};
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
    let vci_config = store.openid4vci_config();
    let mut response = MatcherResponse::new();

    for (request_index, item) in request.requests.iter().enumerate() {
        match item.protocol.as_str() {
            PROTOCOL_OPENID4VP
            | PROTOCOL_OPENID4VP_V1_UNSIGNED
            | PROTOCOL_OPENID4VP_V1_SIGNED
            | PROTOCOL_OPENID4VP_V1_MULTISIGNED => {
                if !vp_config.enabled {
                    continue;
                }
                let result = match_openid4vp_request(
                    request_index,
                    item.protocol.as_str(),
                    &item.data,
                    store,
                    &vp_config,
                    options,
                    profile,
                );
                match result {
                    Ok(result) => response.results.extend(result.results),
                    Err(MatcherError::Profile(err)) => {
                        err.error();
                        return Ok(MatcherResponse::new());
                    }
                    Err(err) => return Err(err),
                }
            }
            PROTOCOL_OPENID4VCI => {
                if !vci_config.enabled {
                    continue;
                }
                let result = match_openid4vci_request(&item.data, &vci_config, profile);
                match result {
                    Ok(result) => response.results.extend(result.results),
                    Err(MatcherError::Profile(err)) => {
                        err.error();
                        return Ok(MatcherResponse::new());
                    }
                    Err(err) => return Err(err),
                }
            }
            _ => {}
        }
    }

    Ok(response)
}

fn match_openid4vp_request<'s, S, P>(
    request_index: usize,
    protocol: &str,
    data: &RequestData,
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
    let is_signed_protocol = matches!(
        protocol,
        PROTOCOL_OPENID4VP_V1_SIGNED | PROTOCOL_OPENID4VP_V1_MULTISIGNED
    );
    if !config.allow_signed_requests
        && (protocol == PROTOCOL_OPENID4VP_V1_SIGNED
            || protocol == PROTOCOL_OPENID4VP_V1_MULTISIGNED)
    {
        return Ok(MatcherResponse::new());
    }

    let mut value = data
        .to_value()
        .map_err(|err| MatcherError::InvalidRequestData(RequestDataError::Json { source: err }))?;
    let request_override = value
        .as_object()
        .and_then(|obj| obj.get("request"))
        .cloned();
    if request_override.is_some() && !config.allow_signed_requests {
        return Ok(MatcherResponse::new());
    }
    if let Some(request_value) = request_override {
        value = decode_openid4vp_request_object(protocol, is_signed_protocol, request_value)?;
    } else if is_signed_protocol && let Value::String(raw) = &value {
        value = decode_openid4vp_signed_payload(protocol, raw)?;
    }
    let scope_present = value.as_object().and_then(|obj| obj.get("scope")).is_some();

    let mut request: OpenId4VpRequest = serde_json::from_value(value.clone()).map_err(|err| {
        if protocol == PROTOCOL_OPENID4VP_V1_SIGNED || protocol == PROTOCOL_OPENID4VP_V1_MULTISIGNED
        {
            MatcherError::InvalidOpenId4Vp(OpenId4VpError::SignedPayloadNotSupported {
                protocol: protocol.to_string(),
                source: err,
            })
        } else {
            MatcherError::InvalidOpenId4Vp(OpenId4VpError::Json { source: err })
        }
    })?;
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

fn decode_openid4vp_request_object(
    protocol: &str,
    is_signed_protocol: bool,
    request_value: Value,
) -> Result<Value, MatcherError> {
    match request_value {
        Value::String(raw) if is_signed_protocol => decode_openid4vp_signed_payload(protocol, &raw),
        Value::String(raw) => serde_json::from_str(&raw)
            .map_err(|err| MatcherError::InvalidOpenId4Vp(OpenId4VpError::Json { source: err })),
        Value::Object(obj) => Ok(Value::Object(obj)),
        other => Ok(other),
    }
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

fn apply_openid4vci_profile<P>(
    profile: &P,
    request: OpenId4VciRequest,
) -> Result<OpenId4VciRequest, MatcherError>
where
    P: Profile,
    P::Error: Into<ProfileError>,
{
    profile
        .apply_openid4vci(request)
        .map_err(|err| MatcherError::Profile(err.into()))
}

fn decode_openid4vp_signed_payload(protocol: &str, jwt: &str) -> Result<Value, MatcherError> {
    let mut parts = jwt.split('.');
    let _ = parts.next();
    let payload = parts.next().unwrap_or_default();
    let decoded = URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .map_err(MatcherError::InvalidBase64)?;
    serde_json::from_slice(&decoded).map_err(|err| {
        MatcherError::InvalidOpenId4Vp(OpenId4VpError::SignedPayloadNotSupported {
            protocol: protocol.to_string(),
            source: err,
        })
    })
}

fn match_openid4vci_request<'s, P>(
    data: &RequestData,
    config: &OpenId4VciConfig,
    profile: &P,
) -> Result<MatcherResponse<'s>, MatcherError>
where
    P: Profile,
    P::Error: Into<ProfileError>,
{
    if !config.allow_credential_offer {
        return Ok(MatcherResponse::new());
    }
    let value = data
        .to_value()
        .map_err(|err| MatcherError::InvalidRequestData(RequestDataError::Json { source: err }))?;
    let request = decode_openid4vci_request(&value)?;
    let request = apply_openid4vci_profile(profile, request)?;
    if request.credential_offer.is_some() && request.credential_offer_uri.is_some() {
        return Err(MatcherError::InvalidOpenId4Vci(
            OpenId4VciError::CredentialOfferConflict,
        ));
    }
    let Some(credential_offer) = request.credential_offer() else {
        if request.credential_offer_uri.is_some() {
            if !config.allow_credential_offer_uri {
                return Ok(MatcherResponse::new());
            }
            return Err(MatcherError::InvalidOpenId4Vci(
                OpenId4VciError::CredentialOfferUriUnsupported,
            ));
        }
        return Ok(MatcherResponse::new());
    };
    validate_credential_offer(credential_offer)?;
    if !credential_offer_has_supported_grant(credential_offer, config) {
        return Ok(MatcherResponse::new());
    }

    let response = MatcherResponse::new().add_inline_issuances(
        credential_offer
            .credential_configuration_ids
            .iter()
            .map(|configuration_id| {
                let configuration = request.credential_configuration(configuration_id);
                build_vci_entry(credential_offer, configuration_id.as_str(), configuration)
            })
            .collect::<Result<Vec<_>, _>>()?,
    );

    if response.results.is_empty() {
        return Ok(MatcherResponse::new());
    }

    Ok(response)
}

fn validate_credential_offer(credential_offer: &CredentialOffer) -> Result<(), MatcherError> {
    // OpenID4VCI defines credential_configuration_ids as a non-empty array of unique strings.
    if credential_offer.credential_configuration_ids.is_empty() {
        return Err(MatcherError::InvalidOpenId4Vci(
            OpenId4VciError::CredentialConfigurationIdsEmpty,
        ));
    }

    let mut seen: Vec<&str> = Vec::new();
    for id in &credential_offer.credential_configuration_ids {
        if id.is_empty() {
            return Err(MatcherError::InvalidOpenId4Vci(
                OpenId4VciError::CredentialConfigurationIdEmpty,
            ));
        }
        if seen.contains(&id.as_str()) {
            return Err(MatcherError::InvalidOpenId4Vci(
                OpenId4VciError::CredentialConfigurationIdsNotUnique,
            ));
        }
        seen.push(id.as_str());
    }
    Ok(())
}

fn credential_offer_has_supported_grant(
    credential_offer: &CredentialOffer,
    config: &OpenId4VciConfig,
) -> bool {
    let allow_authorization_code = config.allow_authorization_code
        && (config.allow_authorization_details || config.allow_scope);
    let allow_pre_authorized_code = config.allow_pre_authorized_code;

    if credential_offer.grants.is_empty() {
        return allow_authorization_code || allow_pre_authorized_code;
    }

    for (grant_type, grant_config) in &credential_offer.grants {
        match grant_type.as_str() {
            "authorization_code" => {
                if allow_authorization_code {
                    return true;
                }
            }
            "urn:ietf:params:oauth:grant-type:pre-authorized_code" => {
                if !allow_pre_authorized_code {
                    continue;
                }
                if grant_requires_tx_code(grant_config) && !config.allow_tx_code {
                    continue;
                }
                return true;
            }
            _ => {}
        }
    }

    false
}

fn grant_requires_tx_code(grant_config: &Value) -> bool {
    let Some(obj) = grant_config.as_object() else {
        return false;
    };
    obj.contains_key("tx_code")
}

fn build_vci_entry<'s>(
    credential_offer: &CredentialOffer,
    configuration_id: &str,
    configuration: Option<&Value>,
) -> Result<InlineIssuanceEntry<'s>, MatcherError> {
    let (title, subtitle, icon) = vci_display_from_configuration(configuration);
    let cred_id = configuration_id.to_string();
    let title = title.unwrap_or(configuration_id).to_string();
    let mut entry = InlineIssuanceEntry::new(cred_id, title);
    entry.subtitle = subtitle
        .map(|value| Cow::Owned(value.to_string()))
        .or_else(|| {
            if credential_offer.credential_issuer.is_empty() {
                None
            } else {
                Some(Cow::Owned(credential_offer.credential_issuer.clone()))
            }
        });
    if let Some(icon) = icon {
        entry.icon = Some(Cow::Owned(icon));
    }

    Ok(entry)
}

fn vci_display_from_configuration(
    configuration: Option<&Value>,
) -> (Option<&str>, Option<&str>, Option<Vec<u8>>) {
    let Some(configuration) = configuration else {
        return (None, None, None);
    };
    let display = configuration
        .get("credential_metadata")
        .and_then(|metadata| metadata.get("display"))
        .and_then(Value::as_array)
        .or_else(|| configuration.get("display").and_then(Value::as_array));
    let Some(entry) = display.and_then(|entries| entries.first()) else {
        return (None, None, None);
    };
    let Some(obj) = entry.as_object() else {
        return (None, None, None);
    };
    let title = obj.get("name").and_then(Value::as_str);
    let subtitle = obj.get("description").and_then(Value::as_str);
    let icon = vci_display_icon_bytes(obj);
    (title, subtitle, icon)
}

fn vci_display_icon_bytes(entry: &serde_json::Map<String, Value>) -> Option<Vec<u8>> {
    let logo_uri = match entry.get("logo") {
        Some(Value::String(value)) => Some(value.as_str()),
        Some(Value::Object(obj)) => obj
            .get("uri")
            .and_then(Value::as_str)
            .or_else(|| obj.get("url").and_then(Value::as_str)),
        _ => None,
    }
    .or_else(|| entry.get("logo_uri").and_then(Value::as_str))
    .or_else(|| entry.get("icon").and_then(Value::as_str))
    .or_else(|| entry.get("image").and_then(Value::as_str));

    logo_uri.and_then(decode_data_url)
}

fn decode_data_url(uri: &str) -> Option<Vec<u8>> {
    let uri = uri.trim();
    let rest = uri.strip_prefix("data:")?;
    let (meta, data) = rest.split_once(',')?;
    if !meta.contains(";base64") {
        return None;
    }
    if data.is_empty() {
        return None;
    }
    if let Ok(bytes) = STANDARD.decode(data.as_bytes())
        && !bytes.is_empty()
    {
        return Some(bytes);
    }
    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(data.as_bytes())
        && !bytes.is_empty()
    {
        return Some(bytes);
    }
    None
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
    let mut set = CredentialSet::new(format!(
        "{protocol}:{request_index}:dcql:{alternative_index}"
    ));

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
            .filter(|cred| store.supports_protocol(cred, protocol))
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
    let credential_id_str = credential_id;
    let ts12_display = ts12::build_display_for_context(
        store,
        cred,
        credential_id_str,
        context,
        store.preferred_locales(),
    )?;
    let (ts12_fields, payment_summary) = match ts12_display {
        Some(display) => (display.transaction_fields, display.payment_summary),
        None => (Vec::new(), None),
    };

    let mut fields = ts12_fields
        .into_iter()
        .map(|field| {
            Field::new(
                field.display_name.into_owned(),
                Some(field.display_value.into_owned()),
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
        fields.push(Field::new(label, value));
    }
    let metadata = build_metadata(context);
    let metadata = metadata
        .map(|value| serde_json::to_string(&value))
        .transpose()
        .map_err(|err| MatcherError::MetadataSerialization { source: err })?
        .map(Cow::Owned);

    if let Some(summary) = payment_summary {
        let mut entry = PaymentEntry::new(
            credential_id,
            summary.merchant_name,
            summary.transaction_amount,
        );
        entry.payment_method_name = Some(title.into());
        entry.payment_method_subtitle = subtitle.map(Cow::Borrowed);
        entry.payment_method_icon = icon.map(Cow::Borrowed);
        entry.additional_info = summary.additional_info;
        entry.metadata = metadata;
        entry.fields = fields;
        return Ok(CredentialEntry::Payment(entry));
    }

    let mut entry = StringIdEntry::new(credential_id, title);
    entry.icon = icon.map(Cow::Borrowed);
    entry.subtitle = subtitle.map(Cow::Borrowed);
    entry.disclaimer = disclaimer.map(Cow::Borrowed);
    entry.warning = warning.map(Cow::Borrowed);
    entry.metadata = metadata;
    entry.fields = fields;

    Ok(CredentialEntry::StringId(entry))
}

fn build_metadata(context: &DcqlSelectionContext<'_>) -> Option<Value> {
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
    Some(Value::Object(obj))
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

        if parsed.data_type.r#type.is_empty() {
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

fn decode_openid4vci_request(value: &Value) -> Result<OpenId4VciRequest, MatcherError> {
    if let Ok(request) = serde_json::from_value::<OpenId4VciRequest>(value.clone())
        && (request.credential_offer.is_some() || request.credential_offer_uri.is_some())
    {
        return Ok(request);
    }

    if let Ok(offer) = serde_json::from_value::<CredentialOffer>(value.clone()) {
        return Ok(OpenId4VciRequest {
            credential_offer: Some(offer),
            ..OpenId4VciRequest::default()
        });
    }

    Err(MatcherError::InvalidOpenId4Vci(
        OpenId4VciError::MissingCredentialOffer,
    ))
}

/// Parses JSON from `RequestData` and deserializes into a target type.
pub fn decode_request_data<T: DeserializeOwned>(data: &RequestData) -> Result<T, MatcherError> {
    let value = data
        .to_value()
        .map_err(|err| MatcherError::InvalidRequestData(RequestDataError::Json { source: err }))?;
    serde_json::from_value(value)
        .map_err(|err| MatcherError::InvalidRequestData(RequestDataError::Json { source: err }))
}

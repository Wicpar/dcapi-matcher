use crate::config::{OpenId4VciConfig, OpenId4VpConfig};
use crate::error::{
    MatcherError, OpenId4VpError, OpenId4VciError, RequestDataError, TransactionDataDecodeError,
    Ts12MetadataError,
};
use crate::models::{
    CredentialOffer, DcApiRequest, InputDescriptor, OpenId4VciRequest, OpenId4VpRequest,
    PROTOCOL_OPENID4VCI, PROTOCOL_OPENID4VP, PROTOCOL_OPENID4VP_V1_MULTISIGNED,
    PROTOCOL_OPENID4VP_V1_SIGNED, PROTOCOL_OPENID4VP_V1_UNSIGNED, RequestData,
    TransactionDataInput,
};
use crate::response::{
    ResolvedCredentialEntry, ResolvedCredentialSet, ResolvedCredentialSlot, ResolvedField,
    ResolvedMatcherResponse, ResolvedPaymentPresentation,
};
use crate::traits::{CredentialSelectionContext, CredentialDescriptor, MatcherStore};
use crate::ts12;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use base64::Engine;
use dcapi_dcql::{
    ClaimValue, ClaimsPathPointer, ClaimsQuery, CredentialFormat, CredentialQuery,
    CredentialStore, PlanOptions, SelectionAlternative, TransactionData, TransactionDataType,
    ValueMatch,
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use core::cell::RefCell;
use core::hash::Hash;

/// Matcher framework options.
#[derive(Debug, Clone)]
pub struct MatcherOptions {
    /// DCQL planner behavior.
    pub dcql: PlanOptions,
}

impl Default for MatcherOptions {
    fn default() -> Self {
        Self {
            dcql: PlanOptions::default(),
        }
    }
}

struct ValidatedStore<'a, S: MatcherStore> {
    inner: &'a S,
    preferred_locales: &'a [&'a str],
    credential_validity: RefCell<Vec<(S::CredentialRef, bool)>>,
    warned_metadata: RefCell<Vec<(S::CredentialRef, TransactionDataType)>>,
}

impl<'a, S> ValidatedStore<'a, S>
where
    S: MatcherStore,
    S::CredentialRef: Clone + Eq + Hash,
{
    fn new(inner: &'a S, preferred_locales: &'a [&'a str]) -> Self {
        Self {
            inner,
            preferred_locales,
            credential_validity: RefCell::new(Vec::new()),
            warned_metadata: RefCell::new(Vec::new()),
        }
    }

    fn is_valid(&self, cred: &S::CredentialRef) -> bool {
        if let Some((_, valid)) = self
            .credential_validity
            .borrow()
            .iter()
            .find(|(stored, _)| stored == cred)
        {
            return *valid;
        }
        let valid = match self.inner.validate_credential(cred) {
            Ok(()) => true,
            Err(err) => {
                tracing::warn!(error = %err, "credential validation warning");
                false
            }
        };
        self.credential_validity
            .borrow_mut()
            .push((cred.clone(), valid));
        valid
    }

    fn warn_metadata_once(
        &self,
        cred: &S::CredentialRef,
        data_type: &TransactionDataType,
        err: &Ts12MetadataError,
    ) {
        let mut warned = self.warned_metadata.borrow_mut();
        if warned
            .iter()
            .any(|(stored, stored_type)| stored == cred && stored_type == data_type)
        {
            return;
        }
        warned.push((cred.clone(), data_type.clone()));
        tracing::warn!(error = %err, "ts12 metadata warning");
    }
}

impl<'a, S> CredentialStore for ValidatedStore<'a, S>
where
    S: MatcherStore,
    S::CredentialRef: Clone + Eq + Hash,
{
    type CredentialRef = S::CredentialRef;

    fn list_credentials(&self, format: Option<&str>) -> Vec<Self::CredentialRef> {
        self.inner
            .list_credentials(format)
            .into_iter()
            .filter(|cred| self.is_valid(cred))
            .collect()
    }

    fn format(&self, cred: &Self::CredentialRef) -> CredentialFormat {
        self.inner.format(cred)
    }

    fn has_vct(&self, cred: &Self::CredentialRef, vct: &str) -> bool {
        self.is_valid(cred) && self.inner.has_vct(cred, vct)
    }

    fn supports_holder_binding(&self, cred: &Self::CredentialRef) -> bool {
        self.is_valid(cred) && self.inner.supports_holder_binding(cred)
    }

    fn has_doctype(&self, cred: &Self::CredentialRef, doctype: &str) -> bool {
        self.is_valid(cred) && self.inner.has_doctype(cred, doctype)
    }

    fn can_sign_transaction_data(
        &self,
        cred: &Self::CredentialRef,
        transaction_data: &TransactionData,
    ) -> bool {
        if !self.is_valid(cred) {
            return false;
        }
        if !self.inner.can_sign_transaction_data(cred, transaction_data) {
            return false;
        }
        let Some(payload) = transaction_data.payload.as_ref() else {
            return true;
        };
        let Some(metadata) = self.inner.ts12_transaction_metadata(cred, transaction_data) else {
            let credential_id = self.inner.describe_credential(cred).credential_id;
            let err = Ts12MetadataError::MissingMetadata {
                credential_id,
                data_type: transaction_data.data_type.clone(),
            };
            self.warn_metadata_once(cred, &transaction_data.data_type, &err);
            return false;
        };
        let credential_id = self.inner.describe_credential(cred).credential_id;
        match ts12::validate_ts12_metadata_for_payload(
            self,
            cred,
            credential_id.as_str(),
            transaction_data,
            payload,
            &metadata,
            self.preferred_locales,
        ) {
            Ok(()) => true,
            Err(err) => {
                self.warn_metadata_once(cred, &transaction_data.data_type, &err);
                false
            }
        }
    }

    fn has_claim_path(&self, cred: &Self::CredentialRef, path: &ClaimsPathPointer) -> bool {
        self.is_valid(cred) && self.inner.has_claim_path(cred, path)
    }

    fn match_claim_value(
        &self,
        cred: &Self::CredentialRef,
        path: &ClaimsPathPointer,
        expected_values: &[ClaimValue],
    ) -> ValueMatch {
        if !self.is_valid(cred) {
            return ValueMatch::NoMatch;
        }
        self.inner.match_claim_value(cred, path, expected_values)
    }

    fn matches_trusted_authorities(
        &self,
        cred: &Self::CredentialRef,
        trusted_authorities: &[dcapi_dcql::TrustedAuthority],
    ) -> bool {
        self.is_valid(cred) && self.inner.matches_trusted_authorities(cred, trusted_authorities)
    }

    fn match_claims(
        &self,
        cred: &Self::CredentialRef,
        query: &CredentialQuery,
    ) -> Option<Vec<ClaimsQuery>> {
        if !self.is_valid(cred) {
            return None;
        }
        self.inner.match_claims(cred, query)
    }
}

impl<'a, S> MatcherStore for ValidatedStore<'a, S>
where
    S: MatcherStore,
    S::CredentialRef: Clone + Eq + Hash,
{
    fn describe_credential(&self, cred: &Self::CredentialRef) -> CredentialDescriptor {
        self.inner.describe_credential(cred)
    }

    fn supports_protocol(&self, cred: &Self::CredentialRef, protocol: &str) -> bool {
        self.is_valid(cred) && self.inner.supports_protocol(cred, protocol)
    }

    fn metadata_for_credman(
        &self,
        cred: &Self::CredentialRef,
        context: &CredentialSelectionContext<'_>,
    ) -> Option<Value> {
        if !self.is_valid(cred) {
            return None;
        }
        self.inner.metadata_for_credman(cred, context)
    }

    fn validate_credential(
        &self,
        cred: &Self::CredentialRef,
    ) -> Result<(), crate::error::CredentialValidationError> {
        self.inner.validate_credential(cred)
    }

    fn ts12_transaction_metadata(
        &self,
        cred: &Self::CredentialRef,
        transaction_data: &TransactionData,
    ) -> Option<crate::ts12::Ts12TransactionMetadata> {
        if !self.is_valid(cred) {
            return None;
        }
        self.inner.ts12_transaction_metadata(cred, transaction_data)
    }

    fn format_ts12_value(
        &self,
        cred: &Self::CredentialRef,
        path: &ClaimsPathPointer,
        value: &Value,
        locale: &str,
    ) -> Option<String> {
        if !self.is_valid(cred) {
            return None;
        }
        self.inner.format_ts12_value(cred, path, value, locale)
    }

    fn ts12_payment_summary(
        &self,
        cred: &Self::CredentialRef,
        transaction_data: &TransactionData,
        payload: &Value,
        metadata: &crate::ts12::Ts12TransactionMetadata,
        locale: &str,
    ) -> Option<crate::ts12::Ts12PaymentSummary> {
        if !self.is_valid(cred) {
            return None;
        }
        self.inner
            .ts12_payment_summary(cred, transaction_data, payload, metadata, locale)
    }

    fn matches_presentation_definition(
        &self,
        cred: &Self::CredentialRef,
        descriptor: &InputDescriptor,
    ) -> bool {
        self.is_valid(cred) && self.inner.matches_presentation_definition(cred, descriptor)
    }

    fn matches_openid4vci_configuration(
        &self,
        cred: &Self::CredentialRef,
        credential_offer: &CredentialOffer,
        credential_configuration_id: &str,
        credential_configuration: Option<&Value>,
    ) -> bool {
        self.is_valid(cred)
            && self.inner.matches_openid4vci_configuration(
                cred,
                credential_offer,
                credential_configuration_id,
                credential_configuration,
            )
    }
}

/// Parses and matches a DC API request with the given credential store.
pub fn match_dc_api_request<S>(
    request_json: &str,
    store: &S,
    options: &MatcherOptions,
) -> Result<ResolvedMatcherResponse, MatcherError>
where
    S: MatcherStore,
    S::CredentialRef: Clone + Eq + Hash,
{
    crate::tracing_backend::set_level(store.log_level());
    let request: DcApiRequest = match serde_json::from_str(request_json) {
        Ok(request) => request,
        Err(err) => {
            let error = MatcherError::InvalidRequestJson(err);
            tracing::error!(error = %error, "matcher error");
            return Err(error);
        }
    };
    match_dc_api_request_value(&request, store, options)
}

/// Matches an already decoded DC API request object.
pub fn match_dc_api_request_value<S>(
    request: &DcApiRequest,
    store: &S,
    options: &MatcherOptions,
) -> Result<ResolvedMatcherResponse, MatcherError>
where
    S: MatcherStore,
    S::CredentialRef: Clone + Eq + Hash,
{
    crate::tracing_backend::set_level(store.log_level());
    let result = match_dc_api_request_value_impl(request, store, options);
    if let Err(err) = &result {
        tracing::error!(error = %err, "matcher error");
    }
    result
}

fn match_dc_api_request_value_impl<S>(
    request: &DcApiRequest,
    store: &S,
    options: &MatcherOptions,
) -> Result<ResolvedMatcherResponse, MatcherError>
where
    S: MatcherStore,
    S::CredentialRef: Clone + Eq + Hash,
{
    let validated_store = ValidatedStore::new(store, store.preferred_locales());
    let vp_config = store.openid4vp_config();
    let vci_config = store.openid4vci_config();
    let mut response = ResolvedMatcherResponse::new();

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
                    &validated_store,
                    &vp_config,
                    options,
                )?;
                response.results.extend(result.results);
            }
            PROTOCOL_OPENID4VCI => {
                if !vci_config.enabled {
                    continue;
                }
                let result =
                    match_openid4vci_request(request_index, &item.data, &validated_store, &vci_config, options)?;
                response.results.extend(result.results);
            }
            _ => {}
        }
    }

    Ok(response)
}

fn match_openid4vp_request<S>(
    request_index: usize,
    protocol: &str,
    data: &RequestData,
    store: &S,
    config: &OpenId4VpConfig,
    options: &MatcherOptions,
) -> Result<ResolvedMatcherResponse, MatcherError>
where
    S: MatcherStore,
    S::CredentialRef: Clone + Eq + Hash,
{
    if !config.allow_signed_requests
        && (protocol == PROTOCOL_OPENID4VP_V1_SIGNED
            || protocol == PROTOCOL_OPENID4VP_V1_MULTISIGNED)
    {
        return Ok(ResolvedMatcherResponse::new());
    }

    let value = data
        .to_value()
        .map_err(|err| MatcherError::InvalidRequestData(RequestDataError::Json { source: err }))?;
    let request: OpenId4VpRequest = serde_json::from_value(value).map_err(|err| {
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

    let mut response = ResolvedMatcherResponse::new();

    if let Some(dcql_query) = &request.dcql_query {
        if !config.allow_dcql {
            return Ok(response);
        }
        if !config.allow_transaction_data && request.transaction_data.is_some() {
            return Ok(response);
        }
        let transaction_data = decode_transaction_data(request.transaction_data.as_deref());
        let transaction_data = if let Some(data) = transaction_data {
            let filtered = filter_transaction_data_for_query(dcql_query, data.as_slice());
            if filtered.is_empty() {
                tracing::warn!("transaction_data filtered out; no valid entries remain");
                return Ok(response);
            }
            Some(filtered)
        } else {
            None
        };
        let plan = match dcapi_dcql::plan_selection(
            dcql_query,
            transaction_data.as_deref(),
            store,
            &options.dcql,
        ) {
            Ok(plan) => plan,
            Err(dcapi_dcql::PlanError::Unsatisfied) => {
                tracing::warn!("dcql query unsatisfied; no matching credentials");
                return Ok(response);
            }
            Err(err) => return Err(MatcherError::Dcql(err)),
        };
        for (alternative_index, alternative) in plan.alternatives.iter().enumerate() {
            let set = resolved_set_from_dcql_alternative(
                store,
                request_index,
                alternative_index,
                alternative,
                transaction_data.as_deref().unwrap_or_default(),
                protocol,
                options,
            )?;
            response = response.add_set(set);
        }
        return Ok(response);
    }

    if config.allow_presentation_definition
        && let Some(presentation_definition) = &request.presentation_definition
    {
        let mut set = ResolvedCredentialSet::new(format!(
            "{protocol}:{request_index}:presentation_definition"
        ));
        for descriptor in &presentation_definition.input_descriptors {
            let slot = resolved_slot_from_presentation_descriptor(
                store,
                request_index,
                descriptor,
                protocol,
                options,
            )?;
            if !slot.alternatives.is_empty() {
                set = set.add_slot(slot);
            }
        }
        if !set.slots.is_empty() {
            response = response.add_set(set);
        }
    }

    Ok(response)
}

fn match_openid4vci_request<S>(
    request_index: usize,
    data: &RequestData,
    store: &S,
    config: &OpenId4VciConfig,
    options: &MatcherOptions,
) -> Result<ResolvedMatcherResponse, MatcherError>
where
    S: MatcherStore,
    S::CredentialRef: Clone + Eq + Hash,
{
    if !config.allow_credential_offer {
        return Ok(ResolvedMatcherResponse::new());
    }
    let value = data
        .to_value()
        .map_err(|err| MatcherError::InvalidRequestData(RequestDataError::Json { source: err }))?;
    let request = decode_openid4vci_request(&value)?;
    if request.credential_offer.is_some() && request.credential_offer_uri.is_some() {
        return Err(MatcherError::InvalidOpenId4Vci(
            OpenId4VciError::CredentialOfferConflict,
        ));
    }
    let Some(credential_offer) = request.credential_offer() else {
        if request.credential_offer_uri.is_some() {
            if !config.allow_credential_offer_uri {
                return Ok(ResolvedMatcherResponse::new());
            }
            return Err(MatcherError::InvalidOpenId4Vci(
                OpenId4VciError::CredentialOfferUriUnsupported,
            ));
        }
        return Ok(ResolvedMatcherResponse::new());
    };
    validate_credential_offer(credential_offer)?;

    let mut set =
        ResolvedCredentialSet::new(format!("{PROTOCOL_OPENID4VCI}:{request_index}:offer"));
    for configuration_id in &credential_offer.credential_configuration_ids {
        let mut slot = ResolvedCredentialSlot::new(Some(configuration_id.clone()), true);
        let configuration = request.credential_configuration(configuration_id);
        for cred in store.list_credentials(None) {
            if !store.supports_protocol(&cred, PROTOCOL_OPENID4VCI) {
                continue;
            }
            if !store.matches_openid4vci_configuration(
                &cred,
                credential_offer,
                configuration_id.as_str(),
                configuration,
            ) {
                continue;
            }

            let context = CredentialSelectionContext::OpenId4VciOffer {
                request_index,
                credential_issuer: credential_offer.credential_issuer.as_str(),
                credential_configuration_id: configuration_id.as_str(),
                credential_configuration: configuration,
            };
            slot = slot.add_alternative(build_resolved_entry(store, &cred, &context, options)?);
        }
        if !slot.alternatives.is_empty() {
            set = set.add_slot(slot);
        }
    }

    if set.slots.is_empty() {
        return Ok(ResolvedMatcherResponse::new());
    }

    Ok(ResolvedMatcherResponse::new().add_set(set))
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
        if seen.iter().any(|existing| *existing == id.as_str()) {
            return Err(MatcherError::InvalidOpenId4Vci(
                OpenId4VciError::CredentialConfigurationIdsNotUnique,
            ));
        }
        seen.push(id.as_str());
    }
    Ok(())
}

fn resolved_set_from_dcql_alternative<S>(
    store: &S,
    request_index: usize,
    alternative_index: usize,
    alternative: &SelectionAlternative<S::CredentialRef>,
    transaction_data: &[TransactionData],
    protocol: &str,
    options: &MatcherOptions,
) -> Result<ResolvedCredentialSet, MatcherError>
where
    S: MatcherStore,
    S::CredentialRef: Clone + Eq + Hash,
{
    let mut set = ResolvedCredentialSet::new(format!(
        "{protocol}:{request_index}:dcql:{alternative_index}"
    ));

    for entry in &alternative.entries {
        let mut slot = ResolvedCredentialSlot::new(Some(entry.query.id.clone()), entry.required);
        for cred in &entry.query.credentials {
            if !store.supports_protocol(cred, protocol) {
                continue;
            }
            let context = CredentialSelectionContext::OpenId4VpDcql {
                request_index,
                alternative_index,
                query_id: entry.query.id.as_str(),
                transaction_data,
                transaction_data_indices: entry.transaction_data_indices.as_slice(),
            };
            slot = slot.add_alternative(build_resolved_entry(store, cred, &context, options)?);
        }
        if !slot.alternatives.is_empty() {
            set = set.add_slot(slot);
        }
    }

    Ok(set)
}

fn resolved_slot_from_presentation_descriptor<S>(
    store: &S,
    request_index: usize,
    descriptor: &InputDescriptor,
    protocol: &str,
    options: &MatcherOptions,
) -> Result<ResolvedCredentialSlot, MatcherError>
where
    S: MatcherStore,
    S::CredentialRef: Clone + Eq + Hash,
{
    let mut slot = ResolvedCredentialSlot::new(Some(descriptor.id.clone()), true);
    for cred in store.list_credentials(None) {
        if !store.supports_protocol(&cred, protocol) {
            continue;
        }
        if !store.matches_presentation_definition(&cred, descriptor) {
            continue;
        }
        let context = CredentialSelectionContext::OpenId4VpPresentationDefinition {
            request_index,
            input_descriptor_id: descriptor.id.as_str(),
        };
        slot = slot.add_alternative(build_resolved_entry(store, &cred, &context, options)?);
    }
    Ok(slot)
}

fn build_resolved_entry<S>(
    store: &S,
    cred: &S::CredentialRef,
    context: &CredentialSelectionContext<'_>,
    _options: &MatcherOptions,
) -> Result<ResolvedCredentialEntry, MatcherError>
where
    S: MatcherStore + ?Sized,
{
    let descriptor = store.describe_credential(cred);
    let credential_id = descriptor.credential_id.clone();
    let mut entry = ResolvedCredentialEntry::new(descriptor.credential_id, descriptor.title);
    entry.icon = descriptor.icon;
    entry.subtitle = descriptor.subtitle;
    entry.disclaimer = descriptor.disclaimer;
    entry.warning = descriptor.warning;
    entry.fields = descriptor
        .fields
        .into_iter()
        .map(|field| ResolvedField {
            display_name: field.display_name,
            display_value: field.display_value,
        })
        .collect();

    let ts12_display = ts12::build_display_for_context(
        store,
        cred,
        credential_id.as_str(),
        context,
        store.preferred_locales(),
    )?;
    if let Some(display) = ts12_display.as_ref() {
        entry.transaction_fields = display.transaction_fields.clone();
        entry.payment = display.payment_summary.as_ref().map(|summary| ResolvedPaymentPresentation {
            merchant_name: summary.merchant_name.clone(),
            transaction_amount: summary.transaction_amount.clone(),
            payment_method_name: Some(entry.title.clone()),
            payment_method_subtitle: entry.subtitle.clone(),
            payment_method_icon: entry.icon.clone(),
            bank_icon: None,
            payment_provider_icon: None,
            additional_info: summary.additional_info.clone(),
        });
    }

    let ts12_metadata = ts12_display.and_then(|display| display.metadata);
    let metadata = merged_metadata(
        descriptor.metadata,
        store.metadata_for_credman(cred, context),
        context,
        ts12_metadata,
    );
    entry.metadata_json = metadata
        .map(|value| serde_json::to_string(&value))
        .transpose()
        .map_err(|err| MatcherError::MetadataSerialization { source: err })?;

    Ok(entry)
}

fn merged_metadata(
    descriptor_metadata: Option<Value>,
    dynamic_metadata: Option<Value>,
    context: &CredentialSelectionContext<'_>,
    ts12_metadata: Option<Value>,
) -> Option<Value> {
    let context_metadata = context_metadata_value(context);
    let selection_metadata = merge_selection_metadata(dynamic_metadata, ts12_metadata);
    match (descriptor_metadata, selection_metadata) {
        (None, None) => Some(context_metadata),
        (Some(base), None) => Some(merge_metadata_blocks(base, context_metadata, None)),
        (None, Some(selection)) => Some(merge_metadata_blocks(
            Value::Null,
            context_metadata,
            Some(selection),
        )),
        (Some(base), Some(selection)) => {
            Some(merge_metadata_blocks(base, context_metadata, Some(selection)))
        }
    }
}

fn merge_selection_metadata(dynamic: Option<Value>, ts12: Option<Value>) -> Option<Value> {
    match (dynamic, ts12) {
        (None, None) => None,
        (Some(dynamic), None) => Some(dynamic),
        (None, Some(ts12)) => {
            let mut obj = serde_json::Map::new();
            obj.insert("ts12_display".to_string(), ts12);
            Some(Value::Object(obj))
        }
        (Some(dynamic), Some(ts12)) => match dynamic {
            Value::Object(mut obj) => {
                obj.insert("ts12_display".to_string(), ts12);
                Some(Value::Object(obj))
            }
            other => {
                let mut obj = serde_json::Map::new();
                obj.insert("dynamic".to_string(), other);
                obj.insert("ts12_display".to_string(), ts12);
                Some(Value::Object(obj))
            }
        },
    }
}

fn merge_metadata_blocks(base: Value, context: Value, selection: Option<Value>) -> Value {
    let mut obj = serde_json::Map::new();
    if !base.is_null() {
        obj.insert("credential_metadata".to_string(), base);
    }
    obj.insert("selection_context".to_string(), context);
    if let Some(selection) = selection {
        obj.insert("selection_metadata".to_string(), selection);
    }
    Value::Object(obj)
}

fn context_metadata_value(context: &CredentialSelectionContext<'_>) -> Value {
    let mut obj = serde_json::Map::new();
    obj.insert(
        "protocol".to_string(),
        Value::String(context.protocol().to_string()),
    );

    match context {
        CredentialSelectionContext::OpenId4VpDcql {
            request_index,
            alternative_index,
            query_id,
            transaction_data,
            transaction_data_indices,
        } => {
            obj.insert("source".to_string(), Value::String("dcql".to_string()));
            obj.insert(
                "request_index".to_string(),
                Value::from(*request_index as u64),
            );
            obj.insert(
                "alternative_index".to_string(),
                Value::from(*alternative_index as u64),
            );
            obj.insert(
                "credential_query_id".to_string(),
                Value::String((*query_id).to_string()),
            );
            obj.insert(
                "transaction_data_indices".to_string(),
                Value::Array(
                    transaction_data_indices
                        .iter()
                        .map(|idx| Value::from(*idx as u64))
                        .collect(),
                ),
            );
            let mut selected_transaction_data = Vec::new();
            for idx in *transaction_data_indices {
                if let Some(value) = transaction_data.get(*idx)
                    && let Ok(serialized) = serde_json::to_value(value)
                {
                    selected_transaction_data.push(serialized);
                }
            }
            obj.insert(
                "transaction_data".to_string(),
                Value::Array(selected_transaction_data),
            );
        }
        CredentialSelectionContext::OpenId4VpPresentationDefinition {
            request_index,
            input_descriptor_id,
        } => {
            obj.insert(
                "source".to_string(),
                Value::String("presentation_definition".to_string()),
            );
            obj.insert(
                "request_index".to_string(),
                Value::from(*request_index as u64),
            );
            obj.insert(
                "input_descriptor_id".to_string(),
                Value::String((*input_descriptor_id).to_string()),
            );
        }
        CredentialSelectionContext::OpenId4VciOffer {
            request_index,
            credential_issuer,
            credential_configuration_id,
            credential_configuration,
        } => {
            obj.insert(
                "source".to_string(),
                Value::String("credential_offer".to_string()),
            );
            obj.insert(
                "request_index".to_string(),
                Value::from(*request_index as u64),
            );
            obj.insert(
                "credential_issuer".to_string(),
                Value::String((*credential_issuer).to_string()),
            );
            obj.insert(
                "credential_configuration_id".to_string(),
                Value::String((*credential_configuration_id).to_string()),
            );
            if let Some(configuration) = credential_configuration {
                obj.insert(
                    "credential_configuration".to_string(),
                    (*configuration).clone(),
                );
            }
        }
    }
    Value::Object(obj)
}

fn decode_transaction_data(
    transaction_data: Option<&[TransactionDataInput]>,
) -> Option<Vec<TransactionData>> {
    let Some(transaction_data) = transaction_data else {
        return None;
    };

    let mut out = Vec::with_capacity(transaction_data.len());
    for (index, item) in transaction_data.iter().enumerate() {
        let parsed = match item {
            TransactionDataInput::Decoded(data) => data.clone(),
            TransactionDataInput::Encoded(encoded) => {
                let bytes = match decode_base64url(encoded) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        let warn = TransactionDataDecodeError::Base64 { index, source: err };
                        tracing::warn!(error = %warn, "transaction_data warning");
                        continue;
                    }
                };
                match serde_json::from_slice::<TransactionData>(&bytes) {
                    Ok(parsed) => parsed,
                    Err(err) => {
                        let warn = TransactionDataDecodeError::Json { index, source: err };
                        tracing::warn!(error = %warn, "transaction_data warning");
                        continue;
                    }
                }
            }
        };

        if parsed.data_type.r#type.is_empty() {
            let warn = TransactionDataDecodeError::MissingType { index };
            tracing::warn!(error = %warn, "transaction_data warning");
            continue;
        }
        if parsed.credential_ids.is_empty() {
            let warn = TransactionDataDecodeError::MissingCredentialIds { index };
            tracing::warn!(error = %warn, "transaction_data warning");
            continue;
        }
        if let Err(err) = ts12::validate_ts12_transaction_data(index, &parsed) {
            tracing::warn!(error = %err, "transaction_data warning");
            continue;
        }

        out.push(parsed);
    }
    Some(out)
}

fn filter_transaction_data_for_query(
    query: &dcapi_dcql::DcqlQuery,
    transaction_data: &[TransactionData],
) -> Vec<TransactionData> {
    let mut out = Vec::with_capacity(transaction_data.len());
    for (index, data) in transaction_data.iter().enumerate() {
        let mut valid = true;
        for credential_id in &data.credential_ids {
            let Some(query_cred) = query
                .credentials
                .iter()
                .find(|candidate| candidate.id() == Some(credential_id.as_str()))
            else {
                let warn = TransactionDataDecodeError::UnknownCredentialId {
                    index,
                    credential_id: credential_id.clone(),
                };
                tracing::warn!(error = %warn, "transaction_data warning");
                valid = false;
                break;
            };
            if query_cred.format() == Some("dc+sd-jwt")
                && query_cred.require_cryptographic_holder_binding() == Some(false)
            {
                let warn = TransactionDataDecodeError::HolderBindingRequired {
                    index,
                    credential_id: credential_id.clone(),
                };
                tracing::warn!(error = %warn, "transaction_data warning");
                valid = false;
                break;
            }
        }
        if valid {
            out.push(data.clone());
        }
    }
    out
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
    if let Ok(request) = serde_json::from_value::<OpenId4VciRequest>(value.clone()) {
        if request.credential_offer.is_some() || request.credential_offer_uri.is_some() {
            return Ok(request);
        }
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
    serde_json::from_value(value).map_err(|err| {
        MatcherError::InvalidRequestData(RequestDataError::Json { source: err })
    })
}

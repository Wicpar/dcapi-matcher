use android_credman::test_shim::{self, DisplayEvent};
use base64::Engine;
use dcapi_dcql::{
    ClaimValue, ClaimsPathPointer, CredentialFormat, CredentialStore, PathElement,
    TransactionDataType, ValueMatch,
};
use dcapi_matcher::{
    CredentialDescriptor, CredentialDescriptorField, CredentialSelectionContext,
    MatcherError, MatcherOptions, MatcherStore, PROTOCOL_OPENID4VCI,
    PROTOCOL_OPENID4VP_V1_MULTISIGNED, PROTOCOL_OPENID4VP_V1_SIGNED,
    PROTOCOL_OPENID4VP_V1_UNSIGNED, ResolvedMatcherResult, Ts12ClaimMetadata, Ts12LocalizedLabel,
    Ts12LocalizedValue, Ts12PaymentSummary, Ts12TransactionMetadata, decode_cbor_package,
    decode_json_package,
    match_dc_api_request,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashSet;

const TS12_TYPE_PAYMENT: &str = "urn:eudi:sca:payment:1";
const TS12_TYPE_GENERIC: &str = "urn:eudi:sca:generic:1";

#[derive(Clone)]
struct TestCredential {
    id: String,
    title: String,
    format: CredentialFormat,
    protocols: HashSet<String>,
    vcts: Vec<String>,
    doctype: Option<String>,
    holder_binding: bool,
    claims: Value,
    transaction_data_types: Vec<TransactionDataType>,
    ts12_metadata: Vec<Ts12TransactionMetadata>,
    credential_metadata: Option<Value>,
}

struct TestStore {
    credentials: Vec<TestCredential>,
    preferred_locales: Vec<&'static str>,
}

impl TestStore {
    fn new(credentials: Vec<TestCredential>) -> Self {
        Self {
            credentials,
            preferred_locales: vec!["en"],
        }
    }

    fn get(&self, idx: usize) -> &TestCredential {
        &self.credentials[idx]
    }
}

impl CredentialStore for TestStore {
    type CredentialRef = usize;

    fn list_credentials(&self, format: Option<&str>) -> Vec<Self::CredentialRef> {
        self.credentials
            .iter()
            .enumerate()
            .filter(|(_, credential)| {
                format.is_none_or(|requested| {
                    matches!(
                        (requested, &credential.format),
                        ("dc+sd-jwt", CredentialFormat::DcSdJwt)
                            | ("mso_mdoc", CredentialFormat::MsoMdoc)
                    )
                })
            })
            .map(|(idx, _)| idx)
            .collect()
    }

    fn format(&self, cred: &Self::CredentialRef) -> CredentialFormat {
        self.get(*cred).format.clone()
    }

    fn has_vct(&self, cred: &Self::CredentialRef, vct: &str) -> bool {
        self.get(*cred).vcts.iter().any(|entry| entry == vct)
    }

    fn supports_holder_binding(&self, cred: &Self::CredentialRef) -> bool {
        self.get(*cred).holder_binding
    }

    fn has_doctype(&self, cred: &Self::CredentialRef, doctype: &str) -> bool {
        self.get(*cred).doctype.as_deref() == Some(doctype)
    }

    fn can_sign_transaction_data(
        &self,
        cred: &Self::CredentialRef,
        transaction_data: &dcapi_dcql::TransactionData,
    ) -> bool {
        self.get(*cred)
            .transaction_data_types
            .iter()
            .any(|entry| entry == &transaction_data.data_type)
    }

    fn has_claim_path(&self, cred: &Self::CredentialRef, path: &ClaimsPathPointer) -> bool {
        dcapi_dcql::select_nodes(&self.get(*cred).claims, path).is_ok()
    }

    fn match_claim_value(
        &self,
        cred: &Self::CredentialRef,
        path: &ClaimsPathPointer,
        expected_values: &[ClaimValue],
    ) -> ValueMatch {
        let Ok(nodes) = dcapi_dcql::select_nodes(&self.get(*cred).claims, path) else {
            return ValueMatch::NoMatch;
        };
        for node in nodes {
            if expected_values.iter().any(|expected| match expected {
                ClaimValue::String(value) => node.as_str() == Some(value),
                ClaimValue::Integer(value) => node.as_i64() == Some(*value),
                ClaimValue::Boolean(value) => node.as_bool() == Some(*value),
            }) {
                return ValueMatch::Match;
            }
        }
        ValueMatch::NoMatch
    }
}

impl MatcherStore for TestStore {
    fn describe_credential(&self, cred: &Self::CredentialRef) -> CredentialDescriptor {
        let credential = self.get(*cred);
        let mut descriptor =
            CredentialDescriptor::new(credential.id.clone(), credential.title.clone());
        descriptor.subtitle = Some(format!("subtitle-{}", credential.id));
        descriptor.fields.push(CredentialDescriptorField {
            display_name: "name".to_string(),
            display_value: credential.title.clone(),
        });
        descriptor.metadata = credential.credential_metadata.clone();
        descriptor
    }

    fn supports_protocol(&self, cred: &Self::CredentialRef, protocol: &str) -> bool {
        self.get(*cred).protocols.contains(protocol)
    }

    fn metadata_for_credman(
        &self,
        cred: &Self::CredentialRef,
        context: &CredentialSelectionContext<'_>,
    ) -> Option<Value> {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "selected_credential".to_string(),
            Value::String(self.get(*cred).id.clone()),
        );
        obj.insert(
            "context_protocol".to_string(),
            Value::String(context.protocol().to_string()),
        );
        Some(Value::Object(obj))
    }

    fn ts12_transaction_metadata(
        &self,
        cred: &Self::CredentialRef,
        transaction_data: &dcapi_dcql::TransactionData,
    ) -> Option<Ts12TransactionMetadata> {
        self.get(*cred)
            .ts12_metadata
            .iter()
            .find(|meta| meta.data_type == transaction_data.data_type)
            .cloned()
    }

    fn ts12_payment_summary(
        &self,
        _cred: &Self::CredentialRef,
        transaction_data: &dcapi_dcql::TransactionData,
        payload: &Value,
        _metadata: &Ts12TransactionMetadata,
        _locale: &str,
    ) -> Option<Ts12PaymentSummary> {
        if transaction_data.data_type.r#type != TS12_TYPE_PAYMENT {
            return None;
        }
        let payload = payload.as_object()?;
        let merchant_name = payload
            .get("payee")
            .and_then(Value::as_object)
            .and_then(|payee| payee.get("name"))
            .and_then(Value::as_str)?
            .to_string();
        let amount = payload.get("amount")?.to_string();
        let currency = payload.get("currency").and_then(Value::as_str).unwrap_or("");
        let transaction_amount = if currency.is_empty() {
            amount
        } else {
            format!("{amount} {currency}")
        };
        Some(Ts12PaymentSummary {
            merchant_name,
            transaction_amount,
            additional_info: None,
        })
    }

    fn openid4vp_config(&self) -> dcapi_matcher::OpenId4VpConfig {
        dcapi_matcher::OpenId4VpConfig {
            enabled: true,
            allow_dcql: true,
            allow_dcql_scope: false,
            allow_transaction_data: true,
            allow_signed_requests: false,
            allow_response_mode_jwt: false,
        }
    }

    fn openid4vci_config(&self) -> dcapi_matcher::OpenId4VciConfig {
        dcapi_matcher::OpenId4VciConfig {
            enabled: true,
            allow_credential_offer: true,
            allow_credential_offer_uri: false,
            allow_authorization_code: true,
            allow_pre_authorized_code: true,
            allow_tx_code: true,
            allow_authorization_details: true,
            allow_scope: true,
        }
    }

    fn preferred_locales(&self) -> &[&str] {
        self.preferred_locales.as_slice()
    }
}

fn ts12_payment_metadata() -> Ts12TransactionMetadata {
    let ui_labels = vec![(
        "affirmative_action_label".to_string(),
        vec![Ts12LocalizedValue {
            locale: "en".to_string(),
            value: "Confirm".to_string(),
        }],
    )];
    let schema = json!({
        "type": "object",
        "required": ["transaction_id", "payee", "currency", "amount"],
        "properties": {
            "transaction_id": { "type": "string" },
            "payee": {
                "type": "object",
                "required": ["name", "id"],
                "properties": {
                    "name": { "type": "string" },
                    "id": { "type": "string" }
                }
            },
            "currency": { "type": "string" },
            "amount": { "type": "number" }
        }
    });
    Ts12TransactionMetadata {
        data_type: TransactionDataType {
            r#type: TS12_TYPE_PAYMENT.to_string(),
            subtype: None,
        },
        claims: vec![
            Ts12ClaimMetadata {
                path: vec![
                    PathElement::String("payload".to_string()),
                    PathElement::String("transaction_id".to_string()),
                ],
                display: vec![Ts12LocalizedLabel {
                    locale: "en".to_string(),
                    label: "Transaction ID".to_string(),
                    description: None,
                }],
            },
            Ts12ClaimMetadata {
                path: vec![
                    PathElement::String("payload".to_string()),
                    PathElement::String("payee".to_string()),
                    PathElement::String("name".to_string()),
                ],
                display: vec![Ts12LocalizedLabel {
                    locale: "en".to_string(),
                    label: "Payee".to_string(),
                    description: None,
                }],
            },
            Ts12ClaimMetadata {
                path: vec![
                    PathElement::String("payload".to_string()),
                    PathElement::String("payee".to_string()),
                    PathElement::String("id".to_string()),
                ],
                display: vec![Ts12LocalizedLabel {
                    locale: "en".to_string(),
                    label: "Payee ID".to_string(),
                    description: None,
                }],
            },
            Ts12ClaimMetadata {
                path: vec![
                    PathElement::String("payload".to_string()),
                    PathElement::String("currency".to_string()),
                ],
                display: vec![Ts12LocalizedLabel {
                    locale: "en".to_string(),
                    label: "Currency".to_string(),
                    description: None,
                }],
            },
            Ts12ClaimMetadata {
                path: vec![
                    PathElement::String("payload".to_string()),
                    PathElement::String("amount".to_string()),
                ],
                display: vec![Ts12LocalizedLabel {
                    locale: "en".to_string(),
                    label: "Amount".to_string(),
                    description: None,
                }],
            },
        ],
        ui_labels,
        schema,
    }
}

fn ts12_generic_metadata() -> Ts12TransactionMetadata {
    let ui_labels = vec![(
        "affirmative_action_label".to_string(),
        vec![Ts12LocalizedValue {
            locale: "en".to_string(),
            value: "Confirm".to_string(),
        }],
    )];
    let schema = json!({
        "type": "object",
        "required": ["transaction_id"],
        "properties": {
            "transaction_id": { "type": "string" },
            "channel": { "type": "string" },
            "payment_payload": { "type": "object" }
        },
        "additionalProperties": true
    });
    Ts12TransactionMetadata {
        data_type: TransactionDataType {
            r#type: TS12_TYPE_GENERIC.to_string(),
            subtype: Some("login".to_string()),
        },
        claims: vec![
            Ts12ClaimMetadata {
                path: vec![
                    PathElement::String("payload".to_string()),
                    PathElement::String("transaction_id".to_string()),
                ],
                display: vec![Ts12LocalizedLabel {
                    locale: "en".to_string(),
                    label: "Transaction ID".to_string(),
                    description: None,
                }],
            },
            Ts12ClaimMetadata {
                path: vec![
                    PathElement::String("payload".to_string()),
                    PathElement::String("channel".to_string()),
                ],
                display: vec![Ts12LocalizedLabel {
                    locale: "en".to_string(),
                    label: "Channel".to_string(),
                    description: None,
                }],
            },
        ],
        ui_labels,
        schema,
    }
}

fn ts12_options() -> MatcherOptions {
    MatcherOptions::default()
}

fn test_store() -> TestStore {
    TestStore::new(vec![
        TestCredential {
            id: "pid-1".to_string(),
            title: "PID One".to_string(),
            format: CredentialFormat::DcSdJwt,
            protocols: HashSet::from([
                "openid4vp-v1-unsigned".to_string(),
                PROTOCOL_OPENID4VCI.to_string(),
            ]),
            vcts: vec!["vct:pid".to_string()],
            doctype: None,
            holder_binding: true,
            claims: json!({"name": "Alice", "age": 30}),
            transaction_data_types: vec![
                TransactionDataType {
                    r#type: "payment".to_string(),
                    subtype: None,
                },
                TransactionDataType {
                    r#type: TS12_TYPE_PAYMENT.to_string(),
                    subtype: None,
                },
                TransactionDataType {
                    r#type: TS12_TYPE_GENERIC.to_string(),
                    subtype: Some("login".to_string()),
                },
            ],
            ts12_metadata: vec![ts12_payment_metadata(), ts12_generic_metadata()],
            credential_metadata: Some(json!({"k0": "v0"})),
        },
        TestCredential {
            id: "pid-2".to_string(),
            title: "PID Two".to_string(),
            format: CredentialFormat::DcSdJwt,
            protocols: HashSet::from(["openid4vp-v1-unsigned".to_string()]),
            vcts: vec!["vct:pid".to_string()],
            doctype: None,
            holder_binding: true,
            claims: json!({"name": "Bob", "age": 40}),
            transaction_data_types: vec![],
            ts12_metadata: vec![],
            credential_metadata: None,
        },
        TestCredential {
            id: "mdl-1".to_string(),
            title: "mDL One".to_string(),
            format: CredentialFormat::MsoMdoc,
            protocols: HashSet::from([
                "openid4vp-v1-unsigned".to_string(),
                PROTOCOL_OPENID4VCI.to_string(),
            ]),
            vcts: vec![],
            doctype: Some("org.iso.18013.5.1.mDL".to_string()),
            holder_binding: true,
            claims: json!({"org.iso.18013.5.1": {"family_name": "Doe"}}),
            transaction_data_types: vec![],
            ts12_metadata: vec![],
            credential_metadata: None,
        },
    ])
}

struct VciStore {
    config: dcapi_matcher::OpenId4VciConfig,
}

impl CredentialStore for VciStore {
    type CredentialRef = ();

    fn list_credentials(&self, _format: Option<&str>) -> Vec<Self::CredentialRef> {
        Vec::new()
    }

    fn format(&self, _cred: &Self::CredentialRef) -> CredentialFormat {
        CredentialFormat::DcSdJwt
    }

    fn has_vct(&self, _cred: &Self::CredentialRef, _vct: &str) -> bool {
        false
    }

    fn supports_holder_binding(&self, _cred: &Self::CredentialRef) -> bool {
        false
    }

    fn has_doctype(&self, _cred: &Self::CredentialRef, _doctype: &str) -> bool {
        false
    }

    fn can_sign_transaction_data(
        &self,
        _cred: &Self::CredentialRef,
        _transaction_data: &dcapi_dcql::TransactionData,
    ) -> bool {
        false
    }

    fn has_claim_path(&self, _cred: &Self::CredentialRef, _path: &ClaimsPathPointer) -> bool {
        false
    }

    fn match_claim_value(
        &self,
        _cred: &Self::CredentialRef,
        _path: &ClaimsPathPointer,
        _expected_values: &[ClaimValue],
    ) -> ValueMatch {
        ValueMatch::NoMatch
    }
}

impl MatcherStore for VciStore {
    fn describe_credential(&self, _cred: &Self::CredentialRef) -> CredentialDescriptor {
        CredentialDescriptor::new("unused", "unused")
    }

    fn supports_protocol(&self, _cred: &Self::CredentialRef, _protocol: &str) -> bool {
        false
    }

    fn openid4vp_config(&self) -> dcapi_matcher::OpenId4VpConfig {
        dcapi_matcher::OpenId4VpConfig::default()
    }

    fn openid4vci_config(&self) -> dcapi_matcher::OpenId4VciConfig {
        self.config.clone()
    }
}

struct VpOverride<'a> {
    inner: &'a TestStore,
    config: dcapi_matcher::OpenId4VpConfig,
}

impl<'a> CredentialStore for VpOverride<'a> {
    type CredentialRef = usize;

    fn list_credentials(&self, format: Option<&str>) -> Vec<Self::CredentialRef> {
        self.inner.list_credentials(format)
    }

    fn format(&self, cred: &Self::CredentialRef) -> CredentialFormat {
        self.inner.format(cred)
    }

    fn has_vct(&self, cred: &Self::CredentialRef, vct: &str) -> bool {
        self.inner.has_vct(cred, vct)
    }

    fn supports_holder_binding(&self, cred: &Self::CredentialRef) -> bool {
        self.inner.supports_holder_binding(cred)
    }

    fn has_doctype(&self, cred: &Self::CredentialRef, doctype: &str) -> bool {
        self.inner.has_doctype(cred, doctype)
    }

    fn can_sign_transaction_data(
        &self,
        cred: &Self::CredentialRef,
        transaction_data: &dcapi_dcql::TransactionData,
    ) -> bool {
        self.inner.can_sign_transaction_data(cred, transaction_data)
    }

    fn has_claim_path(&self, cred: &Self::CredentialRef, path: &ClaimsPathPointer) -> bool {
        self.inner.has_claim_path(cred, path)
    }

    fn match_claim_value(
        &self,
        cred: &Self::CredentialRef,
        path: &ClaimsPathPointer,
        expected_values: &[ClaimValue],
    ) -> ValueMatch {
        self.inner.match_claim_value(cred, path, expected_values)
    }
}

impl<'a> MatcherStore for VpOverride<'a> {
    fn describe_credential(&self, cred: &Self::CredentialRef) -> CredentialDescriptor {
        self.inner.describe_credential(cred)
    }

    fn supports_protocol(&self, cred: &Self::CredentialRef, protocol: &str) -> bool {
        self.inner.supports_protocol(cred, protocol)
    }

    fn openid4vp_config(&self) -> dcapi_matcher::OpenId4VpConfig {
        self.config.clone()
    }

    fn openid4vci_config(&self) -> dcapi_matcher::OpenId4VciConfig {
        self.inner.openid4vci_config()
    }
}

fn collect_set_configs(response: &dcapi_matcher::ResolvedMatcherResponse) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for result in &response.results {
        if let ResolvedMatcherResult::Set(set) = result {
            let mut ids = set
                .slots
                .iter()
                .filter_map(|slot| slot.id.clone())
                .collect::<Vec<_>>();
            ids.sort();
            out.push(ids);
        }
    }
    out
}

#[test]
fn openid4vp_dcql_generates_selection_sets() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } },
                        { "id": "mdl", "format": "mso_mdoc", "meta": { "doctype_value": "org.iso.18013.5.1.mDL" } }
                    ]
                }
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    assert_eq!(response.results.len(), 1);
    let configs = collect_set_configs(&response);
    assert_eq!(configs, vec![vec!["mdl".to_string(), "pid".to_string()]]);
}

#[test]
fn openid4vp_dcql_order_prefers_optional_presence_in_first_alternative() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } },
                        { "id": "mdl", "format": "mso_mdoc", "meta": { "doctype_value": "org.iso.18013.5.1.mDL" } }
                    ],
                    "credential_sets": [
                        { "required": true, "options": [["pid"]] },
                        { "required": false, "options": [["mdl"]] }
                    ]
                }
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    let configs = collect_set_configs(&response);
    assert_eq!(
        configs,
        vec![
            vec!["mdl".to_string(), "pid".to_string()],
            vec!["pid".to_string()]
        ]
    );
}

#[test]
fn openid4vp_transaction_data_encoded_is_decoded_and_attached() {
    let store = test_store();
    let transaction_data = json!({
        "type": "payment",
        "credential_ids": ["pid"]
    });
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&transaction_data).unwrap());
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } }
                    ]
                },
                "transaction_data": [encoded]
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    let ResolvedMatcherResult::Set(set) = &response.results[0] else {
        panic!("expected set");
    };
    let first = &set.slots[0].alternatives[0];
    let metadata = first.metadata_json.as_ref().unwrap();
    assert!(metadata.contains("\"credential_query_id\":\"pid\""));
    assert!(metadata.contains("\"transaction_data\""));
}

#[test]
fn openid4vp_ts12_payment_renders_payment_entry_with_fields() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } }
                    ]
                },
                "transaction_data": [{
                    "type": TS12_TYPE_PAYMENT,
                    "credential_ids": ["pid"],
                    "payload": {
                        "transaction_id": "tx-1",
                        "payee": { "name": "Example Shop", "id": "merchant-1" },
                        "currency": "EUR",
                        "amount": 42.50
                    }
                }]
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &ts12_options()).unwrap();
    let ResolvedMatcherResult::Set(set) = &response.results[0] else {
        panic!("expected set");
    };
    let first = &set.slots[0].alternatives[0];
    assert!(first.payment.is_some());
    assert!(!first.transaction_fields.is_empty());

    let _ = test_shim::take_display();
    response.apply();
    let events = test_shim::take_display().events;
    assert!(events.iter().any(|event| matches!(
        event,
        DisplayEvent::AddPaymentEntry { merchant_name, transaction_amount, .. }
            if merchant_name == "Example Shop" && transaction_amount == "42.5 EUR"
    ) || matches!(
        event,
        DisplayEvent::AddPaymentEntryToSet { merchant_name, transaction_amount, .. }
            if merchant_name == "Example Shop" && transaction_amount == "42.5 EUR"
    ) || matches!(
        event,
        DisplayEvent::AddPaymentEntryToSetV2 { merchant_name, transaction_amount, .. }
            if merchant_name == "Example Shop" && transaction_amount == "42.5 EUR"
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        DisplayEvent::AddFieldForStringIdEntry { display_name, .. }
            if display_name == "Transaction ID" || display_name == "name"
    ) || matches!(
        event,
        DisplayEvent::AddFieldToEntrySet { field_display_name, .. }
            if field_display_name == "Transaction ID" || field_display_name == "name"
    )));
}

#[test]
fn openid4vp_ts12_generic_requires_subtype() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } }
                    ]
                },
                "transaction_data": [{
                    "type": TS12_TYPE_GENERIC,
                    "credential_ids": ["pid"],
                    "transaction_data_hashes_alg": "sha-256",
                    "payload": {
                        "transaction_id": "tx-login-1",
                        "challenge": "abcd"
                    }
                }]
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &ts12_options()).unwrap();
    assert!(response.results.is_empty());
}

#[test]
fn openid4vp_ts12_generic_renders_transaction_fields() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } }
                    ]
                },
                "transaction_data": [{
                    "type": TS12_TYPE_GENERIC,
                    "subtype": "login",
                    "credential_ids": ["pid"],
                    "payload": {
                        "transaction_id": "tx-login-2",
                        "channel": "mobile"
                    }
                }]
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &ts12_options()).unwrap();
    let ResolvedMatcherResult::Set(set) = &response.results[0] else {
        panic!("expected set");
    };
    let first = &set.slots[0].alternatives[0];
    assert!(first.payment.is_none());
    assert!(!first.transaction_fields.is_empty());
}

#[test]
fn openid4vp_ts12_allows_fallback_locale() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } }
                    ]
                },
                "transaction_data": [{
                    "type": TS12_TYPE_PAYMENT,
                    "credential_ids": ["pid"],
                    "payload": {
                        "transaction_id": "tx-1",
                        "payee": { "name": "Example Shop", "id": "merchant-1" },
                        "currency": "EUR",
                        "amount": 42.50
                    }
                }]
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    assert!(!response.results.is_empty());
}


#[test]
fn openid4vp_signed_protocol_reports_unsupported() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_MULTISIGNED,
            "data": "eyJhbGciOiJFUzI1NiJ9..."
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    assert!(response.results.is_empty());
}

#[test]
fn openid4vp_single_signed_protocol_reports_unsupported() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_SIGNED,
            "data": "eyJhbGciOiJFUzI1NiJ9..."
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    assert!(response.results.is_empty());
}

#[test]
fn openid4vp_ignores_unknown_parameters() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } }
                    ]
                },
                "unknown_top_level": "ignored"
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    assert_eq!(response.results.len(), 1);
}

#[test]
fn openid4vp_unsigned_request_ignores_client_identification_fields() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "client_id": "ignored-client",
                "expected_origins": ["https://verifier.example"],
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } }
                    ]
                }
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    assert_eq!(response.results.len(), 1);
}

#[test]
fn openid4vp_dcql_disabled_returns_empty() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } }
                    ]
                }
            }
        }]
    })
    .to_string();

    let vp_config = dcapi_matcher::OpenId4VpConfig {
        enabled: true,
        allow_dcql: false,
        allow_dcql_scope: false,
        allow_transaction_data: true,
        allow_signed_requests: false,
        allow_response_mode_jwt: false,
    };
    let wrapped = VpOverride {
        inner: &store,
        config: vp_config.clone(),
    };
    let response = match_dc_api_request(&request, &wrapped, &MatcherOptions::default()).unwrap();
    assert!(response.results.is_empty());
}

#[test]
fn openid4vp_response_mode_jwt_is_gated() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "response_mode": "dc_api.jwt",
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } }
                    ]
                }
            }
        }]
    })
    .to_string();

    let vp_config = dcapi_matcher::OpenId4VpConfig {
        enabled: true,
        allow_dcql: true,
        allow_dcql_scope: false,
        allow_transaction_data: true,
        allow_signed_requests: false,
        allow_response_mode_jwt: false,
    };
    let wrapped = VpOverride {
        inner: &store,
        config: vp_config.clone(),
    };
    let response = match_dc_api_request(&request, &wrapped, &MatcherOptions::default()).unwrap();
    assert!(response.results.is_empty());

    let wrapped = VpOverride {
        inner: &store,
        config: dcapi_matcher::OpenId4VpConfig {
            allow_response_mode_jwt: true,
            ..vp_config
        },
    };
    let response = match_dc_api_request(&request, &wrapped, &MatcherOptions::default()).unwrap();
    assert!(!response.results.is_empty());
}

#[test]
fn openid4vp_scope_based_dcql_is_gated() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "scope": "dcql:pid"
            }
        }]
    })
    .to_string();

    let vp_config = dcapi_matcher::OpenId4VpConfig {
        enabled: true,
        allow_dcql: true,
        allow_dcql_scope: false,
        allow_transaction_data: true,
        allow_signed_requests: false,
        allow_response_mode_jwt: false,
    };
    let wrapped = VpOverride {
        inner: &store,
        config: vp_config.clone(),
    };
    let response = match_dc_api_request(&request, &wrapped, &MatcherOptions::default()).unwrap();
    assert!(response.results.is_empty());

    let wrapped = VpOverride {
        inner: &store,
        config: dcapi_matcher::OpenId4VpConfig {
            allow_dcql_scope: true,
            ..vp_config
        },
    };
    let err = match_dc_api_request(&request, &wrapped, &MatcherOptions::default()).unwrap_err();
    assert!(matches!(err, MatcherError::InvalidOpenId4Vp(_)));
}

#[test]
fn openid4vci_direct_offer_object_is_supported() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VCI,
            "data": {
                "credential_issuer": "https://issuer.example",
                "credential_configuration_ids": ["pid_config"]
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    let ResolvedMatcherResult::Set(set) = &response.results[0] else {
        panic!("expected set");
    };
    assert_eq!(set.slots.len(), 1);
    assert_eq!(set.slots[0].alternatives[0].credential_id, "pid_config");
}

#[test]
fn openid4vci_offer_wrapper_and_metadata_configuration_are_supported() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VCI,
            "data": {
                "credential_offer": {
                    "credential_issuer": "https://issuer.example",
                    "credential_configuration_ids": ["pid_config"]
                },
                "credential_issuer_metadata": {
                    "credential_configurations_supported": {
                        "pid_config": {
                            "format": "dc+sd-jwt",
                            "vct": "vct:pid"
                        }
                    }
                }
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    let ResolvedMatcherResult::Set(set) = &response.results[0] else {
        panic!("expected set");
    };
    assert_eq!(set.slots[0].alternatives[0].credential_id, "pid_config");
}

#[test]
fn openid4vci_offer_requires_non_empty_configuration_ids() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VCI,
            "data": {
                "credential_offer": {
                    "credential_issuer": "https://issuer.example",
                    "credential_configuration_ids": []
                }
            }
        }]
    })
    .to_string();

    let err = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap_err();
    assert!(matches!(err, MatcherError::InvalidOpenId4Vci(_)));
}

#[test]
fn openid4vci_offer_requires_unique_configuration_ids() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VCI,
            "data": {
                "credential_offer": {
                    "credential_issuer": "https://issuer.example",
                    "credential_configuration_ids": ["pid_config", "pid_config"]
                }
            }
        }]
    })
    .to_string();

    let err = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap_err();
    assert!(matches!(err, MatcherError::InvalidOpenId4Vci(_)));
}

#[test]
fn openid4vci_offer_rejects_mixed_value_and_uri_forms() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VCI,
            "data": {
                "credential_offer": {
                    "credential_issuer": "https://issuer.example",
                    "credential_configuration_ids": ["pid_config"]
                },
                "credential_offer_uri": "https://issuer.example/offer/123"
            }
        }]
    })
    .to_string();

    let err = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap_err();
    assert!(matches!(err, MatcherError::InvalidOpenId4Vci(_)));
}

#[test]
fn openid4vci_configuration_order_is_preserved_in_slots() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VCI,
            "data": {
                "credential_offer": {
                    "credential_issuer": "https://issuer.example",
                    "credential_configuration_ids": ["mdl_config", "pid_config"]
                }
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    let ResolvedMatcherResult::Set(set) = &response.results[0] else {
        panic!("expected set");
    };
    assert_eq!(
        set.slots
            .iter()
            .map(|slot| slot.id.clone().unwrap())
            .collect::<Vec<_>>(),
        vec!["mdl_config".to_string(), "pid_config".to_string()]
    );
}

#[test]
fn openid4vci_metadata_does_not_filter_configurations() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VCI,
            "data": {
                "credential_offer": {
                    "credential_issuer": "https://issuer.example",
                    "credential_configuration_ids": ["pid_config"]
                },
                "credential_issuer_metadata": {
                    "credential_configurations_supported": {
                        "pid_config": {
                            "format": "mso_mdoc",
                            "doctype": "org.iso.18013.5.1.mDL"
                        }
                    }
                }
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    assert!(!response.results.is_empty());
}

#[test]
fn openid4vci_offer_uri_is_rejected() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VCI,
            "data": {
                "credential_offer_uri": "https://issuer.example/offer/123"
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    assert!(response.results.is_empty());
}

#[test]
fn openid4vci_pre_authorized_grant_honors_tx_code_support() {
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VCI,
            "data": {
                "credential_offer": {
                    "credential_issuer": "https://issuer.example",
                    "credential_configuration_ids": ["pid_config"],
                    "grants": {
                        "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                            "pre-authorized_code": "code-123",
                            "tx_code": {}
                        }
                    }
                }
            }
        }]
    })
    .to_string();

    let store = VciStore {
        config: dcapi_matcher::OpenId4VciConfig {
            enabled: true,
            allow_credential_offer: true,
            allow_credential_offer_uri: false,
            allow_authorization_code: false,
            allow_pre_authorized_code: true,
            allow_tx_code: false,
            allow_authorization_details: false,
            allow_scope: false,
        },
    };
    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    assert!(response.results.is_empty());

    let store = VciStore {
        config: dcapi_matcher::OpenId4VciConfig {
            allow_tx_code: true,
            ..store.config
        },
    };
    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    assert!(!response.results.is_empty());
}

#[test]
fn openid4vci_authorization_code_requires_request_method_support() {
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VCI,
            "data": {
                "credential_offer": {
                    "credential_issuer": "https://issuer.example",
                    "credential_configuration_ids": ["pid_config"],
                    "grants": {
                        "authorization_code": {}
                    }
                }
            }
        }]
    })
    .to_string();

    let store = VciStore {
        config: dcapi_matcher::OpenId4VciConfig {
            enabled: true,
            allow_credential_offer: true,
            allow_credential_offer_uri: false,
            allow_authorization_code: true,
            allow_pre_authorized_code: false,
            allow_tx_code: false,
            allow_authorization_details: false,
            allow_scope: false,
        },
    };
    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    assert!(response.results.is_empty());

    let store = VciStore {
        config: dcapi_matcher::OpenId4VciConfig {
            allow_authorization_details: true,
            ..store.config
        },
    };
    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    assert!(!response.results.is_empty());
}

#[test]
fn matcher_options_can_disable_openid4vci_processing() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VCI,
            "data": {
                "credential_offer": {
                    "credential_issuer": "https://issuer.example",
                    "credential_configuration_ids": ["pid_config"]
                }
            }
        }]
    })
    .to_string();

    struct VciDisabled<'a> {
        inner: &'a TestStore,
    }

    impl<'a> CredentialStore for VciDisabled<'a> {
        type CredentialRef = usize;
        fn list_credentials(&self, format: Option<&str>) -> Vec<Self::CredentialRef> {
            self.inner.list_credentials(format)
        }
        fn format(&self, cred: &Self::CredentialRef) -> CredentialFormat {
            self.inner.format(cred)
        }
        fn has_vct(&self, cred: &Self::CredentialRef, vct: &str) -> bool {
            self.inner.has_vct(cred, vct)
        }
        fn supports_holder_binding(&self, cred: &Self::CredentialRef) -> bool {
            self.inner.supports_holder_binding(cred)
        }
        fn has_doctype(&self, cred: &Self::CredentialRef, doctype: &str) -> bool {
            self.inner.has_doctype(cred, doctype)
        }
        fn can_sign_transaction_data(
            &self,
            cred: &Self::CredentialRef,
            transaction_data: &dcapi_dcql::TransactionData,
        ) -> bool {
            self.inner.can_sign_transaction_data(cred, transaction_data)
        }
        fn has_claim_path(&self, cred: &Self::CredentialRef, path: &ClaimsPathPointer) -> bool {
            self.inner.has_claim_path(cred, path)
        }
        fn match_claim_value(
            &self,
            cred: &Self::CredentialRef,
            path: &ClaimsPathPointer,
            expected_values: &[ClaimValue],
        ) -> ValueMatch {
            self.inner.match_claim_value(cred, path, expected_values)
        }
    }

    impl<'a> MatcherStore for VciDisabled<'a> {
        fn describe_credential(&self, cred: &Self::CredentialRef) -> CredentialDescriptor {
            self.inner.describe_credential(cred)
        }
        fn supports_protocol(&self, cred: &Self::CredentialRef, protocol: &str) -> bool {
            self.inner.supports_protocol(cred, protocol)
        }
        fn openid4vci_config(&self) -> dcapi_matcher::OpenId4VciConfig {
            dcapi_matcher::OpenId4VciConfig {
                enabled: false,
                ..dcapi_matcher::OpenId4VciConfig::default()
            }
        }
    }

    let options = MatcherOptions::default();
    let wrapped = VciDisabled { inner: &store };
    let response = match_dc_api_request(&request, &wrapped, &options).unwrap();
    assert!(response.results.is_empty());
}


#[test]
fn unknown_protocol_is_ignored() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": "unknown-protocol",
            "data": {}
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    assert!(response.results.is_empty());
}

#[test]
fn metadata_preserves_object_key_order() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } }
                    ]
                }
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    let ResolvedMatcherResult::Set(set) = &response.results[0] else {
        panic!("expected set");
    };
    let metadata = set.slots[0].alternatives[0].metadata_json.as_ref().unwrap();
    let pos_credential = metadata.find("\"credential_metadata\"").unwrap();
    let pos_context = metadata.find("\"selection_context\"").unwrap();
    let pos_dynamic = metadata.find("\"selection_metadata\"").unwrap();
    assert!(pos_credential < pos_context && pos_context < pos_dynamic);
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct DemoPackage {
    version: u32,
    name: String,
}

#[test]
fn decode_helpers_support_cbor_and_json_packages() {
    let package = DemoPackage {
        version: 1,
        name: "cm-package".to_string(),
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&package, &mut cbor).unwrap();
    let decoded_cbor: DemoPackage = decode_cbor_package(&cbor).unwrap();
    assert_eq!(decoded_cbor, package);

    let json_bytes = serde_json::to_vec(&package).unwrap();
    let decoded_json: DemoPackage = decode_json_package(&json_bytes).unwrap();
    assert_eq!(decoded_json, package);
}

#[test]
fn openid4vp_accepts_object_and_string_data_forms() {
    let store = test_store();
    let body = json!({
        "dcql_query": {
            "credentials": [
                { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } }
            ]
        }
    });
    let request_object = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": body
        }]
    })
    .to_string();
    let request_string = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": serde_json::to_string(&body).unwrap()
        }]
    })
    .to_string();

    let a = match_dc_api_request(&request_object, &store, &MatcherOptions::default()).unwrap();
    let b = match_dc_api_request(&request_string, &store, &MatcherOptions::default()).unwrap();
    assert_eq!(a.results.len(), 1);
    assert_eq!(b.results.len(), 1);
}

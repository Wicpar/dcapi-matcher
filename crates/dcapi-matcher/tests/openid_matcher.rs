use android_credman::{CredmanRender, CredentialReader};
use android_credman::test_shim::{self, DisplayEvent};
use base64::Engine;
use dcapi_dcql::{
    ClaimValue, ClaimsPathPointer, CredentialFormat, CredentialStore, PathElement,
    TransactionDataType, ValueMatch,
};
use dcapi_matcher::{
    CredentialEntry, DefaultProfile, Field, MatcherError, MatcherOptions, MatcherResult,
    MatcherStore,
    PROTOCOL_OPENID4VCI, PROTOCOL_OPENID4VP_V1_MULTISIGNED, PROTOCOL_OPENID4VP_V1_SIGNED,
    PROTOCOL_OPENID4VP_V1_UNSIGNED, Ts12ClaimMetadata, Ts12LocalizedLabel, Ts12LocalizedValue,
    Ts12PaymentSummary, Ts12TransactionMetadata, decode_json_package,
    match_dc_api_request as match_dc_api_request_internal,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::borrow::Cow;
use std::collections::HashSet;

const TS12_TYPE_PAYMENT: &str = "urn:eudi:sca:payment:1";
const TS12_TYPE_GENERIC: &str = "urn:eudi:sca:generic:1";

fn match_dc_api_request<'a>(
    request: &str,
    store: &'a impl MatcherStore,
    options: &MatcherOptions,
) -> Result<dcapi_matcher::MatcherResponse<'a>, MatcherError> {
    test_shim::set_request(request.as_bytes());
    match_dc_api_request_internal(store, options, &DefaultProfile)
}

fn unsupported_reader<T>() -> Result<T, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "from_reader is not supported in tests",
    ))
}

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
    type ReadResult = Result<Self, std::io::Error>;

    fn from_reader(_reader: CredentialReader) -> Self::ReadResult {
        unsupported_reader()
    }

    fn list_credentials(&self, format: Option<CredentialFormat>) -> Vec<Self::CredentialRef> {
        self.credentials
            .iter()
            .enumerate()
            .filter(|(_, credential)| {
                format.map(|format| credential.format == format).unwrap_or(true)
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
        dcapi_dcql::select_nodes(&self.get(*cred).claims, path)
            .map(|nodes| !nodes.is_empty())
            .unwrap_or(false)
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
    fn credential_id<'a>(&'a self, cred: &Self::CredentialRef) -> &'a str {
        self.get(*cred).id.as_str()
    }

    fn credential_title<'a>(&'a self, cred: &Self::CredentialRef) -> &'a str {
        self.get(*cred).title.as_str()
    }

    fn get_credential_field_label<'a>(
        &'a self,
        _cred: &Self::CredentialRef,
        path: &ClaimsPathPointer,
    ) -> Option<&'a str> {
        if path.iter().any(|segment| matches!(segment, PathElement::Wildcard)) {
            return None;
        }
        Some("name")
    }

    fn get_credential_field_value<'a>(
        &'a self,
        cred: &Self::CredentialRef,
        path: &ClaimsPathPointer,
    ) -> Option<&'a str> {
        if path.iter().any(|segment| matches!(segment, PathElement::Wildcard)) {
            return None;
        }
        Some(self.get(*cred).title.as_str())
    }

    fn supports_protocol(&self, cred: &Self::CredentialRef, protocol: &str) -> bool {
        self.get(*cred).protocols.contains(protocol)
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

    fn ts12_payment_summary<'a>(
        &'a self,
        _cred: &Self::CredentialRef,
        transaction_data: &dcapi_dcql::TransactionData,
        payload: &Value,
        _metadata: &Ts12TransactionMetadata,
        _locale: &str,
    ) -> Option<Ts12PaymentSummary<'a>> {
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
        let currency = payload
            .get("currency")
            .and_then(Value::as_str)
            .unwrap_or("");
        let transaction_amount = if currency.is_empty() {
            amount
        } else {
            format!("{amount} {currency}")
        };
        Some(Ts12PaymentSummary {
            merchant_name: Cow::Owned(merchant_name),
            transaction_amount: Cow::Owned(transaction_amount),
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
        },
    ])
}

struct VciStore {
    config: dcapi_matcher::OpenId4VciConfig,
}

impl CredentialStore for VciStore {
    type CredentialRef = ();
    type ReadResult = Result<Self, std::io::Error>;

    fn from_reader(_reader: CredentialReader) -> Self::ReadResult {
        unsupported_reader()
    }

    fn list_credentials(&self, _format: Option<CredentialFormat>) -> Vec<Self::CredentialRef> {
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
    fn credential_id<'a>(&'a self, _cred: &Self::CredentialRef) -> &'a str {
        "unused"
    }

    fn credential_title<'a>(&'a self, _cred: &Self::CredentialRef) -> &'a str {
        "unused"
    }

    fn supports_protocol(&self, _cred: &Self::CredentialRef, _protocol: &str) -> bool {
        false
    }

    fn openid4vp_config(&self) -> dcapi_matcher::OpenId4VpConfig {
        dcapi_matcher::OpenId4VpConfig::default()
    }

    fn openid4vci_config(&self) -> dcapi_matcher::OpenId4VciConfig {
        self.config
    }

    fn preferred_locales(&self) -> &[&str] {
        &[]
    }
}

struct VpOverride<'a> {
    inner: &'a TestStore,
    config: dcapi_matcher::OpenId4VpConfig,
}

impl<'a> CredentialStore for VpOverride<'a> {
    type CredentialRef = usize;
    type ReadResult = Result<Self, std::io::Error>;

    fn from_reader(_reader: CredentialReader) -> Self::ReadResult {
        unsupported_reader()
    }

    fn list_credentials(&self, format: Option<CredentialFormat>) -> Vec<Self::CredentialRef> {
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
    fn credential_id<'b>(&'b self, cred: &Self::CredentialRef) -> &'b str {
        self.inner.credential_id(cred)
    }

    fn credential_title<'b>(&'b self, cred: &Self::CredentialRef) -> &'b str {
        self.inner.credential_title(cred)
    }

    fn credential_icon<'b>(&'b self, cred: &Self::CredentialRef) -> Option<&'b [u8]> {
        self.inner.credential_icon(cred)
    }

    fn credential_subtitle<'b>(&'b self, cred: &Self::CredentialRef) -> Option<&'b str> {
        self.inner.credential_subtitle(cred)
    }

    fn credential_disclaimer<'b>(&'b self, cred: &Self::CredentialRef) -> Option<&'b str> {
        self.inner.credential_disclaimer(cred)
    }

    fn credential_warning<'b>(&'b self, cred: &Self::CredentialRef) -> Option<&'b str> {
        self.inner.credential_warning(cred)
    }

    fn get_credential_field_label<'b>(
        &'b self,
        cred: &Self::CredentialRef,
        path: &ClaimsPathPointer,
    ) -> Option<&'b str> {
        self.inner.get_credential_field_label(cred, path)
    }

    fn get_credential_field_value<'b>(
        &'b self,
        cred: &Self::CredentialRef,
        path: &ClaimsPathPointer,
    ) -> Option<&'b str> {
        self.inner.get_credential_field_value(cred, path)
    }

    fn supports_protocol(&self, cred: &Self::CredentialRef, protocol: &str) -> bool {
        self.inner.supports_protocol(cred, protocol)
    }

    fn openid4vp_config(&self) -> dcapi_matcher::OpenId4VpConfig {
        self.config
    }

    fn openid4vci_config(&self) -> dcapi_matcher::OpenId4VciConfig {
        self.inner.openid4vci_config()
    }

    fn preferred_locales(&self) -> &[&str] {
        self.inner.preferred_locales()
    }
}

fn entry_metadata<'a>(entry: &'a CredentialEntry<'a>) -> Option<&'a str> {
    match entry {
        CredentialEntry::StringId(entry) => entry.metadata.as_deref(),
        CredentialEntry::Payment(entry) => entry.metadata.as_deref(),
    }
}

fn entry_cred_id<'a>(entry: &'a CredentialEntry<'a>) -> &'a str {
    match entry {
        CredentialEntry::StringId(entry) => entry.cred_id.as_ref(),
        CredentialEntry::Payment(entry) => entry.cred_id.as_ref(),
    }
}

fn entry_fields<'a>(entry: &'a CredentialEntry<'a>) -> &'a [Field<'a>] {
    match entry {
        CredentialEntry::StringId(entry) => entry.fields.as_slice(),
        CredentialEntry::Payment(entry) => entry.fields.as_slice(),
    }
}

fn collect_set_configs(response: &dcapi_matcher::MatcherResponse) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for result in &response.results {
        if let MatcherResult::Group(set) = result {
            let mut ids = set
                .slots
                .iter()
                .filter_map(|slot| {
                    let entry = slot.alternatives.first()?;
                    Some(
                        entry_cred_id(entry)
                            .split('-')
                            .next()
                            .unwrap_or("")
                            .to_string(),
                    )
                })
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
    let MatcherResult::Group(set) = &response.results[0] else {
        panic!("expected set");
    };
    let first = &set.slots[0].alternatives[0];
    let metadata = entry_metadata(first).unwrap();
    assert!(metadata.contains("\"credential_id\":\"pid\""));
    assert!(metadata.contains("\"transaction_data_indices\":[0]"));
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
    let MatcherResult::Group(set) = &response.results[0] else {
        panic!("expected set");
    };
    let first = &set.slots[0].alternatives[0];
    assert!(matches!(first, CredentialEntry::Payment(_)));
    assert!(!entry_fields(first).is_empty());

    let _ = test_shim::take_display();
    response.render();
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
    let MatcherResult::Group(set) = &response.results[0] else {
        panic!("expected set");
    };
    let first = &set.slots[0].alternatives[0];
    assert!(matches!(first, CredentialEntry::StringId(_)));
    assert!(!entry_fields(first).is_empty());
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
                },
                "transaction_data": [{
                    "type": "payment",
                    "credential_ids": ["pid"]
                }]
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
        config: vp_config,
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
        config: vp_config,
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
        config: vp_config,
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
    let entries = response
        .results
        .iter()
        .filter_map(|result| match result {
            MatcherResult::InlineIssuance(entry) => Some(entry),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].cred_id.as_ref(), "pid_config");
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
    let entries = response
        .results
        .iter()
        .filter_map(|result| match result {
            MatcherResult::InlineIssuance(entry) => Some(entry),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].cred_id.as_ref(), "pid_config");
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
    assert_eq!(
        response
            .results
            .iter()
            .filter_map(|result| match result {
                MatcherResult::InlineIssuance(entry) => Some(entry.cred_id.as_ref().to_string()),
                _ => None,
            })
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
        type ReadResult = Result<Self, std::io::Error>;

        fn from_reader(_reader: CredentialReader) -> Self::ReadResult {
            unsupported_reader()
        }
        fn list_credentials(&self, format: Option<CredentialFormat>) -> Vec<Self::CredentialRef> {
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
        fn credential_id<'b>(&'b self, cred: &Self::CredentialRef) -> &'b str {
            self.inner.credential_id(cred)
        }

        fn credential_title<'b>(&'b self, cred: &Self::CredentialRef) -> &'b str {
            self.inner.credential_title(cred)
        }

        fn credential_icon<'b>(&'b self, cred: &Self::CredentialRef) -> Option<&'b [u8]> {
            self.inner.credential_icon(cred)
        }

        fn credential_subtitle<'b>(&'b self, cred: &Self::CredentialRef) -> Option<&'b str> {
            self.inner.credential_subtitle(cred)
        }

        fn credential_disclaimer<'b>(&'b self, cred: &Self::CredentialRef) -> Option<&'b str> {
            self.inner.credential_disclaimer(cred)
        }

        fn credential_warning<'b>(&'b self, cred: &Self::CredentialRef) -> Option<&'b str> {
            self.inner.credential_warning(cred)
        }

        fn get_credential_field_label<'b>(
            &'b self,
            cred: &Self::CredentialRef,
            path: &ClaimsPathPointer,
        ) -> Option<&'b str> {
            self.inner.get_credential_field_label(cred, path)
        }

        fn get_credential_field_value<'b>(
            &'b self,
            cred: &Self::CredentialRef,
            path: &ClaimsPathPointer,
        ) -> Option<&'b str> {
            self.inner.get_credential_field_value(cred, path)
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

        fn preferred_locales(&self) -> &[&str] {
            self.inner.preferred_locales()
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
    let MatcherResult::Group(set) = &response.results[0] else {
        panic!("expected set");
    };
    let metadata = entry_metadata(&set.slots[0].alternatives[0]).unwrap();
    let pos_credential = metadata.find("\"credential_id\"").unwrap();
    let pos_indices = metadata.find("\"transaction_data_indices\"").unwrap();
    assert!(pos_credential < pos_indices);
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct DemoPackage {
    version: u32,
    name: String,
}

#[test]
fn decode_helpers_support_json_packages() {
    let package = DemoPackage {
        version: 1,
        name: "cm-package".to_string(),
    };
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

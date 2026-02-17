use android_credman::CredmanApplyExt;
use base64::Engine;
use dcapi_dcql::{
    ClaimValue, ClaimsPathPointer, CredentialFormat, CredentialStore, PlanOptions, TransactionData,
    TransactionDataType, ValueMatch, path_matches,
};
use dcapi_matcher::diagnostics::error;
use dcapi_matcher::{CredentialDescriptor, CredentialDescriptorField, LogLevel, MatcherOptions, MatcherStore, OpenId4VciConfig, OpenId4VpConfig, Ts12ClaimMetadata, Ts12LocalizedLabel, Ts12LocalizedValue, Ts12TransactionMetadata, Ts12UiLabels, dcapi_matcher, match_dc_api_request, decode_json_package};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::borrow::Cow;

#[derive(Debug, Deserialize)]
struct PackageConfig {
    default_id_prefix: Option<String>,
    #[serde(default)]
    openid4vp: OpenId4VpConfig,
    #[serde(default)]
    openid4vci: OpenId4VciConfig,
    #[serde(default)]
    dcql: PlanOptions,
    log_level: Option<LogLevel>,
    #[serde(default)]
    credentials: Vec<CredentialConfig>,
}

#[derive(Debug, Deserialize, Default)]
struct CredentialConfig {
    id: Option<String>,
    format: String,
    title: Option<String>,
    subtitle: Option<String>,
    disclaimer: Option<String>,
    warning: Option<String>,
    #[serde(default)]
    fields: Vec<CredentialFieldConfig>,
    metadata: Option<Value>,
    icon: Option<IconConfig>,
    #[serde(default)]
    vcts: Vec<String>,
    doctype: Option<String>,
    holder_binding: Option<bool>,
    claims: Option<Value>,
    protocols: Option<Vec<String>>,
    #[serde(default)]
    transaction_data_types: Vec<Ts12MetadataConfig>,
}

#[derive(Debug, Deserialize)]
struct CredentialFieldConfig {
    path: ClaimsPathPointer,
    display_name: String,
    display_value: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Ts12MetadataConfig {
    #[serde(flatten)]
    data_type: TransactionDataType,
    #[serde(default)]
    claims: Vec<Ts12ClaimConfig>,
    #[serde(default)]
    ui_labels: Vec<Ts12UiLabelConfig>,
    schema: Value,
}

#[derive(Debug, Deserialize)]
struct Ts12ClaimConfig {
    path: ClaimsPathPointer,
    #[serde(default)]
    display: Vec<Ts12LocalizedLabelConfig>,
}

#[derive(Debug, Deserialize)]
struct Ts12LocalizedLabelConfig {
    locale: String,
    label: String,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Ts12UiLabelConfig {
    key: String,
    #[serde(default)]
    values: Vec<Ts12LocalizedValueConfig>,
}

#[derive(Debug, Deserialize)]
struct Ts12LocalizedValueConfig {
    locale: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum IconConfig {
    Bytes(Vec<u8>),
    Base64(String),
}

#[derive(Debug, Clone)]
struct ResolvedCredential {
    id: String,
    format: String,
    title: String,
    subtitle: Option<String>,
    disclaimer: Option<String>,
    warning: Option<String>,
    fields: Vec<ResolvedFieldConfig>,
    metadata: Option<Value>,
    icon: Option<Vec<u8>>,
    vcts: Vec<String>,
    doctype: Option<String>,
    holder_binding: bool,
    claims: Value,
    protocols: Option<Vec<String>>,
    transaction_data_types: Vec<TransactionDataType>,
    ts12_metadata: Vec<Ts12TransactionMetadata>,
}

#[derive(Debug, Clone)]
struct ResolvedFieldConfig {
    path: ClaimsPathPointer,
    display_name: String,
    display_value: Option<String>,
}

#[derive(Debug, Clone)]
struct PackageStore {
    credentials: Vec<ResolvedCredential>,
    openid4vp: OpenId4VpConfig,
    openid4vci: OpenId4VciConfig,
    log_level: Option<LogLevel>,
}

impl PackageStore {
    fn from_config(config: PackageConfig) -> Result<(Self, PlanOptions), String> {
        let default_prefix = config.default_id_prefix.as_deref();

        let credentials = config
            .credentials
            .into_iter()
            .enumerate()
            .filter_map(|(index, credential)| {
                resolve_credential(credential, index, default_prefix)
                    .inspect_err(|err| {
                        dcapi_matcher::diagnostics::warn(format!(
                            "credential package warning: {}",
                            err
                        ));
                    })
                    .ok()
            })
            .collect::<Vec<_>>();

        Ok((
            Self {
                credentials,
                openid4vp: config.openid4vp,
                openid4vci: config.openid4vci,
                log_level: config.log_level,
            },
            config.dcql,
        ))
    }

    fn get(&self, idx: usize) -> &ResolvedCredential {
        &self.credentials[idx]
    }
}

impl CredentialStore for PackageStore {
    type CredentialRef = usize;

    fn list_credentials(&self, format: Option<&str>) -> Vec<Self::CredentialRef> {
        self.credentials
            .iter()
            .enumerate()
            .filter(|(_, credential)| format.is_none_or(|requested| credential.format == requested))
            .map(|(idx, _)| idx)
            .collect()
    }

    fn format(&self, cred: &Self::CredentialRef) -> CredentialFormat {
        CredentialFormat::from_query_format(&self.get(*cred).format)
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
        transaction_data: &TransactionData,
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
            if expected_values.iter().any(|value| match value {
                ClaimValue::String(v) => node.as_str() == Some(v),
                ClaimValue::Integer(v) => node.as_i64() == Some(*v),
                ClaimValue::Boolean(v) => node.as_bool() == Some(*v),
            }) {
                return ValueMatch::Match;
            }
        }
        ValueMatch::NoMatch
    }
}

impl MatcherStore for PackageStore {
    fn describe_credential<'a>(
        &'a self,
        cred: &Self::CredentialRef,
        context: &dcapi_matcher::DcqlSelectionContext<'_>,
    ) -> CredentialDescriptor<'a> {
        let credential = self.get(*cred);
        build_descriptor(credential, fields_from_selected_claims(credential, context.selected_claims))
    }

    fn supports_protocol(&self, cred: &Self::CredentialRef, protocol: &str) -> bool {
        match self.get(*cred).protocols.as_deref() {
            None => true,
            Some(protocols) => protocols.iter().any(|entry| entry == protocol),
        }
    }

    fn openid4vp_config(&self) -> OpenId4VpConfig {
        self.openid4vp.clone()
    }

    fn openid4vci_config(&self) -> OpenId4VciConfig {
        self.openid4vci.clone()
    }

    fn log_level(&self) -> Option<LogLevel> {
        self.log_level
    }

    fn ts12_transaction_metadata(
        &self,
        cred: &Self::CredentialRef,
        transaction_data: &dcapi_dcql::TransactionData,
    ) -> Option<Ts12TransactionMetadata> {
        self.get(*cred)
            .ts12_metadata
            .iter()
            .find(|entry| entry.data_type == transaction_data.data_type)
            .cloned()
    }
}

fn resolve_credential(
    credential: CredentialConfig,
    index: usize,
    default_id_prefix: Option<&str>,
) -> Result<ResolvedCredential, String> {
    if credential.format.trim().is_empty() {
        return Err("credential format must be non-empty".to_string());
    }
    let fallback_prefix = default_id_prefix.unwrap_or(credential.format.as_str());
    let id = credential
        .id
        .unwrap_or_else(|| format!("{fallback_prefix}-{index}"));
    let title = credential.title.unwrap_or_else(|| id.clone());
    let claims = credential
        .claims
        .unwrap_or_else(|| Value::Object(Map::new()));
    let icon = match credential.icon {
        Some(icon) => decode_icon(icon)?,
        None => None,
    };
    let holder_binding = credential.holder_binding.unwrap_or(true);
    let fields = credential
        .fields
        .into_iter()
        .map(|field| ResolvedFieldConfig {
            path: field.path,
            display_name: field.display_name,
            display_value: field.display_value,
        })
        .collect::<Vec<_>>();
    let ts12_metadata = credential
        .transaction_data_types
        .into_iter()
        .map(resolve_ts12_metadata)
        .collect::<Vec<_>>();
    let transaction_data_types = ts12_metadata
        .iter()
        .map(|entry| entry.data_type.clone())
        .collect();

    Ok(ResolvedCredential {
        id,
        format: credential.format,
        title,
        subtitle: credential.subtitle,
        disclaimer: credential.disclaimer,
        warning: credential.warning,
        fields,
        metadata: credential.metadata,
        icon,
        vcts: credential.vcts,
        doctype: credential.doctype,
        holder_binding,
        claims,
        protocols: credential.protocols,
        transaction_data_types,
        ts12_metadata,
    })
}

fn resolve_ts12_metadata(config: Ts12MetadataConfig) -> Ts12TransactionMetadata {
    let claims = config
        .claims
        .into_iter()
        .map(|claim| Ts12ClaimMetadata {
            path: claim.path,
            display: claim
                .display
                .into_iter()
                .map(|label| Ts12LocalizedLabel {
                    locale: label.locale,
                    label: label.label,
                    description: label.description,
                })
                .collect(),
        })
        .collect();
    let ui_labels: Ts12UiLabels = config
        .ui_labels
        .into_iter()
        .map(|entry| {
            let values = entry
                .values
                .into_iter()
                .map(|value| Ts12LocalizedValue {
                    locale: value.locale,
                    value: value.value,
                })
                .collect();
            (entry.key, values)
        })
        .collect();
    Ts12TransactionMetadata {
        data_type: config.data_type,
        claims,
        ui_labels,
        schema: config.schema,
    }
}

fn build_descriptor<'a>(
    credential: &'a ResolvedCredential,
    fields: Vec<CredentialDescriptorField<'a>>,
) -> CredentialDescriptor<'a> {
    let mut descriptor =
        CredentialDescriptor::new(credential.id.as_str(), credential.title.as_str());
    descriptor.subtitle = credential.subtitle.as_deref().map(Cow::Borrowed);
    descriptor.disclaimer = credential.disclaimer.as_deref().map(Cow::Borrowed);
    descriptor.warning = credential.warning.as_deref().map(Cow::Borrowed);
    descriptor.icon = credential.icon.as_deref().map(Cow::Borrowed);
    descriptor.fields = fields;
    descriptor.metadata = credential.metadata.clone();
    descriptor
}

fn fields_from_selected_claims<'a>(
    credential: &'a ResolvedCredential,
    selected_claims: &[dcapi_dcql::ClaimsQuery],
) -> Vec<CredentialDescriptorField<'a>> {
    selected_claims
        .iter()
        .filter_map(|claim| {
            if let Some(metadata) = credential.metadata.as_ref() {
                if let Some(display_name) =
                    claim_display_name_from_metadata(metadata, &claim.path)
                {
                    let display_value = value_from_claims(&credential.claims, &claim.path);
                    return Some(CredentialDescriptorField {
                        display_name,
                        display_value,
                    });
                }
            }

            field_from_config(credential, &claim.path)
        })
        .collect()
}

fn field_from_config<'a>(
    credential: &'a ResolvedCredential,
    claim_path: &ClaimsPathPointer,
) -> Option<CredentialDescriptorField<'a>> {
    let field = credential
        .fields
        .iter()
        .find(|field| path_matches(&field.path, claim_path))?;
    let display_name = Cow::Borrowed(field.display_name.as_str());
    let display_value = field
        .display_value
        .as_deref()
        .map(Cow::Borrowed)
        .or_else(|| value_from_claims(&credential.claims, claim_path));
    Some(CredentialDescriptorField {
        display_name,
        display_value,
    })
}

fn claim_display_name_from_metadata<'a>(
    metadata: &'a Value,
    claim_path: &ClaimsPathPointer,
) -> Option<Cow<'a, str>> {
    for claims in claims_description_arrays(metadata) {
        for entry in claims {
            let path_value = entry.get("path")?;
            let parsed: ClaimsPathPointer = serde_json::from_value(path_value.clone()).ok()?;
            if !path_matches(&parsed, claim_path) {
                continue;
            }
            if let Some(display) = entry.get("display").and_then(Value::as_array) {
                for display_entry in display {
                    if let Some(name) = display_entry.get("name").and_then(Value::as_str) {
                        if !name.is_empty() {
                            return Some(Cow::Borrowed(name));
                        }
                    }
                }
            }
        }
    }
    None
}

fn claims_description_arrays(metadata: &Value) -> Vec<&Vec<Value>> {
    let mut out = Vec::new();
    if let Some(entries) = metadata.get("claims").and_then(Value::as_array) {
        out.push(entries);
    }
    if let Some(entries) = metadata
        .get("credential_metadata")
        .and_then(|value| value.get("claims"))
        .and_then(Value::as_array)
    {
        out.push(entries);
    }
    out
}

fn value_from_claims<'a>(claims: &'a Value, path: &ClaimsPathPointer) -> Option<Cow<'a, str>> {
    let Ok(nodes) = dcapi_dcql::select_nodes(claims, path) else {
        return None;
    };
    nodes.first().map(|value| json_to_display(value))
}

fn json_to_display(value: &Value) -> Cow<str> {
    match value {
        Value::Null => Cow::Borrowed("null"),
        Value::Bool(v) => v.to_string().into(),
        Value::Number(v) => v.to_string().into(),
        Value::String(v) => Cow::Borrowed(v),
        Value::Array(_) => Cow::Borrowed("[Array]"),
        Value::Object(_) => Cow::Borrowed("[Object]"),
    }
}

fn decode_config(bytes: &[u8]) -> Option<PackageConfig> {
    decode_json_package::<PackageConfig>(bytes).ok()
}

fn decode_icon(icon: IconConfig) -> Result<Option<Vec<u8>>, String> {
    match icon {
        IconConfig::Bytes(bytes) => Ok(if bytes.is_empty() { None } else { Some(bytes) }),
        IconConfig::Base64(value) => {
            if value.is_empty() {
                return Ok(None);
            }
            let standard = base64::engine::general_purpose::STANDARD;
            if let Ok(bytes) = standard.decode(value.as_bytes()) {
                return Ok(if bytes.is_empty() { None } else { Some(bytes) });
            }
            let url_safe = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            if let Ok(bytes) = url_safe.decode(value.as_bytes()) {
                return Ok(if bytes.is_empty() { None } else { Some(bytes) });
            }
            Err("invalid icon base64".to_string())
        }
    }
}

/// Credman matcher entrypoint for aptitude consortium config packages.
#[dcapi_matcher]
pub fn matcher_entrypoint(request: String, credentials: String) {
    let Some(config) = decode_config(credentials.as_bytes()) else {
        return;
    };
    dcapi_matcher::diagnostics::set_level(config.log_level);

    let Ok((store, dcql_options)) = PackageStore::from_config(config)
        .inspect_err(|err| {
            error(format!(
                "credential package validation error: {}",
                err
            ))
        })
    else {
        return;
    };

    let options = MatcherOptions { dcql: dcql_options };
    let Ok(matched) = match_dc_api_request(&request, &store, &options) else {
        return;
    };
    matched.apply();
}

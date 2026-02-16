use android_credman::CredentialReader;
use dcapi_dcql::{
    ClaimValue, ClaimsPathPointer, CredentialFormat, CredentialSetOptionMode, CredentialStore,
    OptionalCredentialSetsMode, PlanOptions, TransactionData, TransactionDataType, ValueMatch,
};
use dcapi_matcher::{
    CredentialDescriptor, CredentialDescriptorField, LogLevel, MatcherOptions, MatcherStore,
    OpenId4VciConfig, OpenId4VpConfig, Ts12ClaimMetadata, Ts12LocalizedLabel,
    Ts12LocalizedValue, Ts12TransactionMetadata, Ts12UiLabels, dcapi_matcher, match_dc_api_request,
};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::io::Read;

#[derive(Debug, Deserialize)]
struct PackageConfig {
    #[serde(default)]
    default_id_prefix: Option<String>,
    #[serde(default)]
    openid4vp: Option<OpenId4VpConfigConfig>,
    #[serde(default)]
    openid4vci: Option<OpenId4VciConfigConfig>,
    #[serde(default)]
    dcql: Option<DcqlModeConfig>,
    #[serde(default)]
    log_level: Option<LogLevelConfig>,
    #[serde(default)]
    credentials: Vec<CredentialConfig>,
}

#[derive(Debug, Deserialize, Default)]
struct OpenId4VpConfigConfig {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    allow_dcql: Option<bool>,
    #[serde(default)]
    allow_presentation_definition: Option<bool>,
    #[serde(default)]
    allow_transaction_data: Option<bool>,
    #[serde(default)]
    allow_signed_requests: Option<bool>,
}

impl OpenId4VpConfigConfig {
    fn resolve(self) -> OpenId4VpConfig {
        OpenId4VpConfig {
            enabled: self.enabled.unwrap_or(false),
            allow_dcql: self.allow_dcql.unwrap_or(false),
            allow_presentation_definition: self.allow_presentation_definition.unwrap_or(false),
            allow_transaction_data: self.allow_transaction_data.unwrap_or(false),
            allow_signed_requests: self.allow_signed_requests.unwrap_or(false),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct OpenId4VciConfigConfig {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    allow_credential_offer: Option<bool>,
    #[serde(default)]
    allow_credential_offer_uri: Option<bool>,
}

impl OpenId4VciConfigConfig {
    fn resolve(self) -> OpenId4VciConfig {
        OpenId4VciConfig {
            enabled: self.enabled.unwrap_or(false),
            allow_credential_offer: self.allow_credential_offer.unwrap_or(false),
            allow_credential_offer_uri: self.allow_credential_offer_uri.unwrap_or(false),
        }
    }
}

#[derive(Debug, Deserialize)]
struct DcqlModeConfig {
    #[serde(default)]
    credential_set_option_mode: Option<CredentialSetOptionModeConfig>,
    #[serde(default)]
    optional_credential_sets_mode: Option<OptionalCredentialSetsModeConfig>,
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum CredentialSetOptionModeConfig {
    AllSatisfiable,
    FirstSatisfiableOnly,
}

impl From<CredentialSetOptionModeConfig> for CredentialSetOptionMode {
    fn from(value: CredentialSetOptionModeConfig) -> Self {
        match value {
            CredentialSetOptionModeConfig::AllSatisfiable => Self::AllSatisfiable,
            CredentialSetOptionModeConfig::FirstSatisfiableOnly => Self::FirstSatisfiableOnly,
        }
    }
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum OptionalCredentialSetsModeConfig {
    PreferPresent,
    PreferAbsent,
    AlwaysPresentIfSatisfiable,
}

impl From<OptionalCredentialSetsModeConfig> for OptionalCredentialSetsMode {
    fn from(value: OptionalCredentialSetsModeConfig) -> Self {
        match value {
            OptionalCredentialSetsModeConfig::PreferPresent => Self::PreferPresent,
            OptionalCredentialSetsModeConfig::PreferAbsent => Self::PreferAbsent,
            OptionalCredentialSetsModeConfig::AlwaysPresentIfSatisfiable => {
                Self::AlwaysPresentIfSatisfiable
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum LogLevelConfig {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogLevelConfig> for LogLevel {
    fn from(value: LogLevelConfig) -> Self {
        match value {
            LogLevelConfig::Error => LogLevel::ERROR,
            LogLevelConfig::Warn => LogLevel::WARN,
            LogLevelConfig::Info => LogLevel::INFO,
            LogLevelConfig::Debug => LogLevel::DEBUG,
            LogLevelConfig::Trace => LogLevel::TRACE,
        }
    }
}

#[derive(Debug, Deserialize)]
struct CredentialConfig {
    #[serde(default)]
    id: Option<String>,
    format: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    subtitle: Option<String>,
    #[serde(default)]
    disclaimer: Option<String>,
    #[serde(default)]
    warning: Option<String>,
    #[serde(default)]
    fields: Vec<CredentialFieldConfig>,
    #[serde(default)]
    metadata: Option<Value>,
    #[serde(default)]
    icon: Option<Vec<u8>>,
    #[serde(default)]
    vct: Option<String>,
    #[serde(default)]
    doctype: Option<String>,
    #[serde(default)]
    holder_binding: Option<bool>,
    #[serde(default)]
    claims: Option<Value>,
    #[serde(default)]
    protocols: Option<Vec<String>>,
    #[serde(default)]
    vci_configuration_ids: Vec<String>,
    #[serde(default)]
    transaction_data_types: Vec<Ts12MetadataConfig>,
}

#[derive(Debug, Deserialize)]
struct CredentialFieldConfig {
    display_name: String,
    #[serde(default)]
    display_value: String,
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
    #[serde(default)]
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

#[derive(Debug, Clone)]
struct ResolvedCredential {
    id: String,
    format: String,
    title: String,
    subtitle: Option<String>,
    disclaimer: Option<String>,
    warning: Option<String>,
    fields: Vec<CredentialDescriptorField>,
    metadata: Option<Value>,
    icon: Option<Vec<u8>>,
    vct: Option<String>,
    doctype: Option<String>,
    holder_binding: bool,
    claims: Value,
    protocols: Option<Vec<String>>,
    vci_configuration_ids: Vec<String>,
    transaction_data_types: Vec<TransactionDataType>,
    ts12_metadata: Vec<Ts12TransactionMetadata>,
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
        let dcql_options = resolve_dcql_options(config.dcql.as_ref());
        let openid4vp = config.openid4vp.unwrap_or_default().resolve();
        let openid4vci = config.openid4vci.unwrap_or_default().resolve();
        let log_level = config.log_level.map(LogLevel::from);
        let default_prefix = config.default_id_prefix.as_deref();

        let mut credentials = Vec::new();
        for (index, credential) in config.credentials.into_iter().enumerate() {
            credentials.push(resolve_credential(
                credential,
                index,
                default_prefix,
            )?);
        }

        Ok((
            Self {
                credentials,
                openid4vp,
                openid4vci,
                log_level,
            },
            dcql_options,
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
        self.get(*cred).vct.as_deref() == Some(vct)
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
    fn describe_credential(&self, cred: &Self::CredentialRef) -> CredentialDescriptor {
        let credential = self.get(*cred);
        let mut descriptor =
            CredentialDescriptor::new(credential.id.clone(), credential.title.clone());
        descriptor.subtitle = credential.subtitle.clone();
        descriptor.disclaimer = credential.disclaimer.clone();
        descriptor.warning = credential.warning.clone();
        descriptor.icon = credential.icon.clone();
        descriptor.fields = credential.fields.clone();
        descriptor.metadata = credential.metadata.clone();
        descriptor
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

    fn matches_openid4vci_configuration(
        &self,
        cred: &Self::CredentialRef,
        _credential_offer: &dcapi_matcher::CredentialOffer,
        credential_configuration_id: &str,
        _credential_configuration: Option<&Value>,
    ) -> bool {
        self.get(*cred)
            .vci_configuration_ids
            .iter()
            .any(|entry| entry == credential_configuration_id)
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

fn resolve_dcql_options(config: Option<&DcqlModeConfig>) -> PlanOptions {
    let mut options = PlanOptions {
        credential_set_option_mode: CredentialSetOptionMode::FirstSatisfiableOnly,
        optional_credential_sets_mode: OptionalCredentialSetsMode::PreferPresent,
    };
    let Some(config) = config else {
        return options;
    };
    if let Some(mode) = config.credential_set_option_mode.as_ref() {
        options.credential_set_option_mode = (*mode).into();
    }
    if let Some(mode) = config.optional_credential_sets_mode.as_ref() {
        options.optional_credential_sets_mode = (*mode).into();
    }
    options
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
    let holder_binding = credential.holder_binding.unwrap_or(true);
    let fields = credential
        .fields
        .into_iter()
        .map(|field| CredentialDescriptorField {
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
        icon: credential.icon,
        vct: credential.vct,
        doctype: credential.doctype,
        holder_binding,
        claims,
        protocols: credential.protocols,
        vci_configuration_ids: credential.vci_configuration_ids,
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

fn decode_config(bytes: &[u8]) -> Result<PackageConfig, String> {
    if let Ok(config) = serde_json::from_slice::<PackageConfig>(bytes) {
        return Ok(config);
    }
    ciborium::from_reader(bytes).map_err(|err| format!("invalid config cbor or json: {err}"))
}

/// Credman matcher entrypoint for aptitude consortium config packages.
#[dcapi_matcher]
pub fn matcher_entrypoint(request: String, mut credentials: CredentialReader) {
    let mut raw = Vec::new();
    if credentials.read_to_end(&mut raw).is_err() {
        return;
    }

    let Ok(config) = decode_config(raw.as_slice()) else {
        return;
    };
    let Ok((store, dcql_options)) = PackageStore::from_config(config) else {
        return;
    };
    let options = MatcherOptions { dcql: dcql_options };
    let Ok(response) = match_dc_api_request(&request, &store, &options) else {
        return;
    };
    response.apply();
}

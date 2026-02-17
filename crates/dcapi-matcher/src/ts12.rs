use crate::diagnostics::ErrorExt;
use crate::error::{MatcherError, Ts12Error, Ts12MetadataError};
use crate::traits::{DcqlSelectionContext, MatcherStore};
use alloc::borrow::Cow;
use dcapi_dcql::{
    ClaimsPathPointer, PathElement, TransactionData, TransactionDataType, path_matches,
};
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use serde_json::Value;

/// Localized label entry for TS12 claim metadata.
#[derive(Debug, Clone)]
pub struct Ts12LocalizedLabel {
    /// RFC5646 locale identifier.
    pub locale: String,
    /// Human-readable label for the field.
    pub label: String,
    /// Optional description text.
    pub description: Option<String>,
}

/// One claim metadata entry for TS12 transaction data.
#[derive(Debug, Clone)]
pub struct Ts12ClaimMetadata {
    /// Claims path pointer (relative to `payload`).
    pub path: ClaimsPathPointer,
    /// Localized display entries.
    pub display: Vec<Ts12LocalizedLabel>,
}

/// Localized UI label entry for TS12 UI elements.
#[derive(Debug, Clone)]
pub struct Ts12LocalizedValue {
    /// RFC5646 locale identifier.
    pub locale: String,
    /// Localized string value.
    pub value: String,
}

/// TS12 UI label catalogue (preserves insertion order).
pub type Ts12UiLabels = Vec<(String, Vec<Ts12LocalizedValue>)>;

/// Resolved TS12 transaction metadata for one transaction data type.
#[derive(Debug, Clone)]
pub struct Ts12TransactionMetadata {
    /// Transaction data type and optional subtype this metadata applies to.
    pub data_type: TransactionDataType,
    /// Claim metadata entries for the transaction payload.
    pub claims: Vec<Ts12ClaimMetadata>,
    /// Localised UI labels for transaction confirmation UI elements.
    pub ui_labels: Ts12UiLabels,
    /// JSON Schema object used to validate the transaction payload.
    pub schema: Value,
}

/// Payment rendering summary for TS12 flows.
#[derive(Debug, Clone)]
pub struct Ts12PaymentSummary<'a> {
    /// Merchant/payee name shown in payment UI.
    pub merchant_name: Cow<'a, str>,
    /// Transaction amount string shown in payment UI.
    pub transaction_amount: Cow<'a, str>,
    /// Optional extra context for payment UI.
    pub additional_info: Option<Cow<'a, str>>,
}

/// Display payload for one credential selection containing TS12 transaction data.
#[derive(Debug, Clone)]
pub(crate) struct Ts12Display<'a> {
    pub transaction_fields: Vec<Ts12DisplayField<'a>>,
    pub payment_summary: Option<Ts12PaymentSummary<'a>>,
}

#[derive(Debug, Clone)]
pub(crate) struct Ts12DisplayField<'a> {
    pub display_name: Cow<'a, str>,
    pub display_value: Cow<'a, str>,
}

#[derive(Debug, Clone)]
struct Ts12RenderedField {
    label: String,
    value: String,
}

#[derive(Debug, Clone)]
struct Ts12TransactionDisplay {
    locale: String,
    fields: Vec<Ts12RenderedField>,
}

/// Validates one transaction-data entry against TS12 structural requirements.
pub(crate) fn validate_ts12_transaction_data(
    index: usize,
    transaction_data: &TransactionData,
) -> Result<(), Ts12Error> {
    let Some(payload) = transaction_data.payload.as_ref() else {
        return Ok(());
    };

    let Value::Object(_) = payload else {
        return Err(Ts12Error::PayloadNotObject { index });
    };

    Ok(())
}

/// Builds TS12 display output for the provided selection context.
pub(crate) fn build_display_for_context<'a, S>(
    store: &'a S,
    cred: &S::CredentialRef,
    credential_id: &str,
    context: &DcqlSelectionContext<'_>,
    preferred_locales: &[&str],
) -> Result<Option<Ts12Display<'a>>, MatcherError>
where
    S: MatcherStore + ?Sized,
{
    let transaction_data = context.transaction_data;
    let transaction_data_indices = context.transaction_data_indices;

    let mut displays = Vec::new();
    let mut payment_summaries = Vec::new();

    for idx in transaction_data_indices {
        let Some(td) = transaction_data.get(*idx) else {
            continue;
        };
        let Some(payload) = td.payload.as_ref() else {
            continue;
        };
        let Some(metadata) = store.ts12_transaction_metadata(cred, td) else {
            let err = Ts12MetadataError::MissingMetadata {
                credential_id: credential_id.to_string(),
                data_type: td.data_type.clone(),
            };
            err.warn();
            continue;
        };
        let ctx = RenderContext {
            credential_id,
            transaction_data: td,
            payload,
            metadata: &metadata,
            preferred_locales,
            store,
            cred,
        };
        let display = match render_transaction_display(&ctx) {
            Ok(display) => display,
            Err(err) => {
                err.warn();
                continue;
            }
        };
        if let Some(summary) =
            store.ts12_payment_summary(cred, td, payload, &metadata, &display.locale)
        {
            payment_summaries.push(summary);
        }
        displays.push(display);
    }

    if displays.is_empty() {
        return Ok(None);
    }

    let transaction_fields = displays
        .iter()
        .flat_map(|display| {
            display.fields.iter().map(|field| Ts12DisplayField {
                display_name: Cow::Owned(field.label.clone()),
                display_value: Cow::Owned(field.value.clone()),
            })
        })
        .collect::<Vec<_>>();

    let payment_summary = if displays.len() == 1 && payment_summaries.len() == 1 {
        Some(payment_summaries.remove(0))
    } else {
        None
    };

    Ok(Some(Ts12Display {
        transaction_fields,
        payment_summary,
    }))
}

struct RenderContext<'a, S: MatcherStore + ?Sized> {
    credential_id: &'a str,
    transaction_data: &'a TransactionData,
    payload: &'a Value,
    metadata: &'a Ts12TransactionMetadata,
    preferred_locales: &'a [&'a str],
    store: &'a S,
    cred: &'a S::CredentialRef,
}

fn render_transaction_display<S>(
    ctx: &RenderContext<'_, S>,
) -> Result<Ts12TransactionDisplay, Ts12MetadataError>
where
    S: MatcherStore + ?Sized,
{
    let data_type = ctx.transaction_data.data_type.clone();
    if ctx.metadata.data_type != data_type {
        return Err(Ts12MetadataError::MetadataTypeMismatch {
            credential_id: ctx.credential_id.to_string(),
            expected: ctx.metadata.data_type.clone(),
            actual: data_type,
        });
    }
    validate_payload_schema(
        ctx.credential_id,
        &ctx.metadata.data_type,
        ctx.payload,
        &ctx.metadata.schema,
    )?;
    let mut fields = Vec::new();
    let mut collected = Vec::new();
    let mut path = vec![PathElement::String("payload".to_string())];
    collect_payload_fields(&mut path, ctx.payload, &mut collected);

    let mut used_claims = Vec::new();
    for (path, value) in &collected {
        let Some(claim) = find_claim_metadata(&ctx.metadata.claims, path) else {
            return Err(Ts12MetadataError::MissingClaimMetadata {
                credential_id: ctx.credential_id.to_string(),
                data_type: ctx.metadata.data_type.clone(),
                path: path.clone(),
            });
        };
        used_claims.push((path.clone(), value.clone(), claim));
    }

    let locale = select_locale(
        ctx.credential_id,
        &ctx.metadata.data_type,
        ctx.preferred_locales,
        &used_claims,
        &ctx.metadata.ui_labels,
    )?;

    ui_labels_for_locale(
        ctx.credential_id,
        &ctx.metadata.data_type,
        &ctx.metadata.ui_labels,
        &locale,
    )?;

    for (path, value, claim) in used_claims {
        let display = match_localized_label(&locale, &claim.display).ok_or_else(|| {
            Ts12MetadataError::MissingClaimLabel {
                credential_id: ctx.credential_id.to_string(),
                data_type: ctx.metadata.data_type.clone(),
                locale: locale.clone(),
                path: path.clone(),
            }
        })?;
        if display.label.is_empty() {
            return Err(Ts12MetadataError::EmptyClaimLabel {
                credential_id: ctx.credential_id.to_string(),
                data_type: ctx.metadata.data_type.clone(),
                locale: locale.clone(),
                path: path.clone(),
            });
        }
        let formatted = ctx
            .store
            .format_ts12_value(ctx.cred, &path, &value, &locale)
            .unwrap_or_else(|| format_value(&value));
        fields.push(Ts12RenderedField {
            label: display.label.clone(),
            value: formatted,
        });
    }

    Ok(Ts12TransactionDisplay {
        locale,
        fields,
    })
}

fn collect_payload_fields(
    path: &mut ClaimsPathPointer,
    value: &Value,
    out: &mut Vec<(ClaimsPathPointer, Value)>,
) {
    match value {
        Value::Object(map) => {
            for (key, item) in map {
                path.push(PathElement::String(key.clone()));
                collect_payload_fields(path, item, out);
                path.pop();
            }
        }
        Value::Array(arr) => {
            for (idx, item) in arr.iter().enumerate() {
                path.push(PathElement::Index(idx as u64));
                collect_payload_fields(path, item, out);
                path.pop();
            }
        }
        _ => out.push((path.clone(), value.clone())),
    }
}

fn find_claim_metadata<'a>(
    claims: &'a [Ts12ClaimMetadata],
    path: &ClaimsPathPointer,
) -> Option<&'a Ts12ClaimMetadata> {
    if let Some(found) = claims.iter().find(|claim| claim.path == *path) {
        return Some(found);
    }
    claims.iter().find(|claim| path_matches(&claim.path, path))
}

fn select_locale(
    credential_id: &str,
    data_type: &TransactionDataType,
    preferred_locales: &[&str],
    used_claims: &[(ClaimsPathPointer, Value, &Ts12ClaimMetadata)],
    ui_labels: &Ts12UiLabels,
) -> Result<String, Ts12MetadataError> {
    let Some(affirmative_labels) = ui_labels_entry(ui_labels, "affirmative_action_label") else {
        return Err(Ts12MetadataError::MissingUiLabels {
            credential_id: credential_id.to_string(),
            data_type: data_type.clone(),
            label: "affirmative_action_label",
        });
    };

    let candidates = if preferred_locales.is_empty() {
        fallback_locales(affirmative_labels)
    } else {
        preferred_locales
            .iter()
            .map(|value| (*value).to_string())
            .collect()
    };

    if candidates.is_empty() {
        return Err(Ts12MetadataError::MissingPreferredLocales {
            credential_id: credential_id.to_string(),
            data_type: data_type.clone(),
        });
    }

    let mut missing_claim_label = None;
    let mut missing_ui_label = true;

    for locale in &candidates {
        let ui_ok = match_localized_value(locale, affirmative_labels).is_some();
        if ui_ok {
            missing_ui_label = false;
        }
        let mut missing_path = None;
        for (path, _, claim) in used_claims {
            if match_localized_label(locale, &claim.display).is_none() {
                missing_path = Some(path.clone());
                break;
            }
        }
        if ui_ok && missing_path.is_none() {
            return Ok(locale.clone());
        }
        if missing_claim_label.is_none() {
            let Some(missing_path) = missing_path else {
                continue;
            };
            missing_claim_label = Some(Ts12MetadataError::MissingClaimLabel {
                credential_id: credential_id.to_string(),
                data_type: data_type.clone(),
                locale: locale.clone(),
                path: missing_path,
            });
        }
    }

    let Some(first_locale) = candidates.first().cloned() else {
        return Err(Ts12MetadataError::MissingPreferredLocales {
            credential_id: credential_id.to_string(),
            data_type: data_type.clone(),
        });
    };
    if missing_ui_label {
        return Err(Ts12MetadataError::MissingLocalizedUiLabel {
            credential_id: credential_id.to_string(),
            data_type: data_type.clone(),
            label: "affirmative_action_label",
            locale: first_locale.clone(),
        });
    }

    if let Some(err) = missing_claim_label {
        return Err(err);
    }

    Err(Ts12MetadataError::MissingLocalizedUiLabel {
        credential_id: credential_id.to_string(),
        data_type: data_type.clone(),
        label: "affirmative_action_label",
        locale: first_locale,
    })
}

fn fallback_locales(labels: &[Ts12LocalizedValue]) -> Vec<String> {
    let mut locales = Vec::new();
    for entry in labels {
        if locales.iter().any(|existing| existing == &entry.locale) {
            continue;
        }
        locales.push(entry.locale.clone());
    }
    locales
}

fn ui_labels_for_locale(
    credential_id: &str,
    data_type: &TransactionDataType,
    ui_labels: &Ts12UiLabels,
    locale: &str,
) -> Result<Vec<(String, String)>, Ts12MetadataError> {
    let mut out = Vec::new();
    for (key, values) in ui_labels {
        if let Some(entry) = match_localized_value(locale, values) {
            out.push((key.clone(), entry.value.clone()));
        }
    }
    if !out.iter().any(|(key, _)| key == "affirmative_action_label") {
        return Err(Ts12MetadataError::MissingLocalizedUiLabel {
            credential_id: credential_id.to_string(),
            data_type: data_type.clone(),
            label: "affirmative_action_label",
            locale: locale.to_string(),
        });
    }
    Ok(out)
}

fn ui_labels_entry<'a>(
    ui_labels: &'a Ts12UiLabels,
    key: &str,
) -> Option<&'a [Ts12LocalizedValue]> {
    ui_labels
        .iter()
        .find(|(label_key, _)| label_key == key)
        .map(|(_, values)| values.as_slice())
}

fn match_localized_label<'a>(
    preferred: &str,
    labels: &'a [Ts12LocalizedLabel],
) -> Option<&'a Ts12LocalizedLabel> {
    let preferred = canonical_locale(preferred);
    let preferred_primary = primary_locale(&preferred);
    labels
        .iter()
        .find(|label| canonical_locale(&label.locale) == preferred)
        .or_else(|| {
            labels
                .iter()
                .find(|label| primary_locale(&canonical_locale(&label.locale)) == preferred_primary)
        })
}

fn match_localized_value<'a>(
    preferred: &str,
    values: &'a [Ts12LocalizedValue],
) -> Option<&'a Ts12LocalizedValue> {
    let preferred = canonical_locale(preferred);
    let preferred_primary = primary_locale(&preferred);
    values
        .iter()
        .find(|value| canonical_locale(&value.locale) == preferred)
        .or_else(|| {
            values
                .iter()
                .find(|value| primary_locale(&canonical_locale(&value.locale)) == preferred_primary)
        })
}

fn canonical_locale(value: &str) -> String {
    value.trim().replace('_', "-").to_ascii_lowercase()
}

fn primary_locale(value: &str) -> &str {
    value.split('-').next().unwrap_or(value)
}

fn format_value(value: &Value) -> String {
    match value {
        Value::String(v) => v.to_string(),
        Value::Number(v) => v.to_string(),
        Value::Bool(v) => v.to_string(),
        Value::Null => String::new(),
        Value::Array(_) | Value::Object(_) => value.to_string(),
    }
}

fn validate_payload_schema(
    credential_id: &str,
    data_type: &TransactionDataType,
    payload: &Value,
    schema: &Value,
) -> Result<(), Ts12MetadataError> {
    let Value::Object(_) = schema else {
        return Err(Ts12MetadataError::SchemaNotObject {
            credential_id: credential_id.to_string(),
            data_type: data_type.clone(),
        });
    };

    ensure_local_schema_refs(credential_id, data_type, schema)?;

    let validator = json_schema_validator_core::JsonSchemaValidator::new(
        schema.clone(),
        json_schema_validator_core::ValidationOptions::default(),
    )
    .map_err(|error| Ts12MetadataError::SchemaInvalid {
        credential_id: credential_id.to_string(),
        data_type: data_type.clone(),
        error: Box::new(error),
    })?;

    let errors = validator.validate(payload);
    if !errors.is_empty() {
        return Err(Ts12MetadataError::SchemaValidation {
            credential_id: credential_id.to_string(),
            data_type: data_type.clone(),
            errors,
        });
    }

    Ok(())
}

fn ensure_local_schema_refs(
    credential_id: &str,
    data_type: &TransactionDataType,
    schema: &Value,
) -> Result<(), Ts12MetadataError> {
    match schema {
        Value::Object(map) => {
            if let Some(reference) = map.get("$ref").and_then(Value::as_str)
                && !reference.starts_with('#')
            {
                return Err(Ts12MetadataError::SchemaExternalRef {
                    credential_id: credential_id.to_string(),
                    data_type: data_type.clone(),
                    reference: reference.to_string(),
                });
            }
            for value in map.values() {
                ensure_local_schema_refs(credential_id, data_type, value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                ensure_local_schema_refs(credential_id, data_type, value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

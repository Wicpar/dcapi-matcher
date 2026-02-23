use dcapi_dcql::{
    ClaimValue, CredentialFormat, CredentialSetOptionMode, CredentialStore, DcqlOutput, DcqlQuery,
    OptionalCredentialSetsMode, PlanError, PlanOptions, TransactionData, TransactionDataType,
    TrustedAuthority, ValueMatch, plan_selection,
};
use serde::Deserialize;
use serde_json::{Map, Value};
use rustc_hash::FxHashMap;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

// -----------------------------
// JSON credential package model
// -----------------------------

#[derive(Debug, Clone, Deserialize)]
struct CredentialPackage {
    #[serde(default)]
    credentials: Vec<JsonCredential>,
}

#[derive(Debug, Clone, Deserialize)]
struct JsonCredential {
    id: String,
    format: CredentialFormat,

    #[serde(default)]
    holder_binding: bool,
    vct: Option<String>,
    extends_vcts: Option<Vec<String>>,
    doctype: Option<String>,

    #[serde(default)]
    trusted_authorities: Vec<TrustedAuthority>,

    #[serde(default)]
    transaction_data_types: Vec<TransactionDataType>,

    #[serde(default = "default_claims_value")]
    claims: Value,
}

fn default_claims_value() -> Value {
    Value::Object(Map::new())
}

#[derive(Debug, Clone, Deserialize)]
struct RequestFixture {
    #[serde(flatten)]
    dcql_query: DcqlQuery,
    transaction_data: Option<Vec<TransactionData>>,
}

// -----------------------------
// Minimal JSON-backed store impl
// -----------------------------

#[derive(Debug, Clone)]
struct JsonStore {
    creds: FxHashMap<String, JsonCredential>,
}

impl JsonStore {
    fn from_package(pkg: CredentialPackage) -> Self {
        let creds = pkg
            .credentials
            .into_iter()
            .map(|c| (c.id.clone(), c))
            .collect();
        Self { creds }
    }

    fn get(&self, id: &str) -> &JsonCredential {
        self.creds
            .get(id)
            .unwrap_or_else(|| panic!("missing credential id in store: {id}"))
    }
}

impl CredentialStore for JsonStore {
    type CredentialRef = String;
    type ReadError = std::io::Error;

    fn from_reader(reader: &mut dyn std::io::Read) -> Result<Self, Self::ReadError> {
        let package: CredentialPackage = serde_json::from_reader(reader)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        Ok(Self::from_package(package))
    }

    fn list_credentials(&self, format: Option<CredentialFormat>) -> Vec<Self::CredentialRef> {
        self.creds
            .values()
            .filter(|c| format.map(|f| c.format == f).unwrap_or(true))
            .map(|c| c.id.clone())
            .collect()
    }

    fn format(&self, cred: &Self::CredentialRef) -> CredentialFormat {
        self.get(cred).format
    }

    fn has_vct(&self, cred: &Self::CredentialRef, vct: &str) -> bool {
        let c = self.get(cred);
        let Some(current_vct) = c.vct.as_deref() else {
            return false;
        };
        if current_vct == vct {
            return true;
        }
        c.extends_vcts
            .as_ref()
            .is_some_and(|chain| chain.iter().any(|entry| entry == vct))
    }

    fn supports_holder_binding(&self, cred: &Self::CredentialRef) -> bool {
        self.get(cred).holder_binding
    }

    fn has_doctype(&self, cred: &Self::CredentialRef, doctype: &str) -> bool {
        self.get(cred).doctype.as_deref() == Some(doctype)
    }

    fn can_sign_transaction_data(
        &self,
        cred: &Self::CredentialRef,
        transaction_data: &dcapi_dcql::TransactionData,
    ) -> bool {
        self.get(cred)
            .transaction_data_types
            .iter()
            .any(|t| t.r#type == transaction_data.r#type)
    }

    fn has_claim_path(
        &self,
        cred: &Self::CredentialRef,
        path: &dcapi_dcql::ClaimsPathPointer,
    ) -> bool {
        let c = self.get(cred);
        dcapi_dcql::select_nodes(&c.claims, path).is_ok()
    }

    fn match_claim_value(
        &self,
        cred: &Self::CredentialRef,
        path: &dcapi_dcql::ClaimsPathPointer,
        expected_values: &[ClaimValue],
    ) -> ValueMatch {
        let c = self.get(cred);
        let Ok(nodes) = dcapi_dcql::select_nodes(&c.claims, path) else {
            return ValueMatch::NoMatch;
        };
        for node in nodes {
            if expected_values
                .iter()
                .any(|value| claim_value_matches_json(value, node))
            {
                return ValueMatch::Match;
            }
        }
        ValueMatch::NoMatch
    }

    fn matches_trusted_authorities(
        &self,
        cred: &Self::CredentialRef,
        trusted_authorities: &[TrustedAuthority],
    ) -> bool {
        if trusted_authorities.is_empty() {
            return true;
        }
        let c = self.get(cred);
        for ta in trusted_authorities {
            // A credential matches a TrustedAuthority constraint if it has *any* entry
            // of the same type, with at least one overlapping value.
            let matches = c.trusted_authorities.iter().any(|cred_ta| {
                cred_ta.r#type == ta.r#type && cred_ta.values.iter().any(|v| ta.values.contains(v))
            });
            if !matches {
                return false;
            }
        }
        true
    }

    // `match_claims` uses the library default implementation (DCQL engine).
}

// -----------------------------
// Expected output JSON model
// -----------------------------

#[derive(Debug, Deserialize)]
#[serde(tag = "result", rename_all = "lowercase")]
enum Expected {
    Plan {
        presentation_sets: Vec<Vec<SlotExpectation>>,
    },
    Error {
        error: String,
        #[serde(default)]
        message: Option<String>,
    },
    #[serde(rename = "parse_error")]
    ParseError {
        #[serde(default)]
        message: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
struct SlotExpectation {
    #[serde(default)]
    transaction_data_ids: Vec<usize>,
    alternatives: Vec<SelectionExpectation>,
}

#[derive(Debug, Deserialize)]
struct SelectionExpectation {
    dcql_id: String,
    #[serde(default)]
    credential_id: Option<String>,
    #[serde(default)]
    selected_claim_ids: Vec<String>,
}

// -----------------------------
// Tests
// -----------------------------

macro_rules! case_test {
    ($name:ident, $dir:literal) => {
        #[test]
        fn $name() {
            let case_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests")
                .join("cases")
                .join($dir);
            run_case(&case_dir);
        }
    };
}

case_test!(
    case_01_no_credential_sets_all_required,
    "01_no_credential_sets_all_required"
);
case_test!(
    case_02_required_sets_factorization_optional,
    "02_required_sets_factorization_optional"
);
case_test!(
    case_03_conditional_outer_alternatives,
    "03_conditional_outer_alternatives"
);
case_test!(case_04_unsatisfied_due_to_vct, "04_unsatisfied_due_to_vct");
case_test!(
    case_05_invalid_claim_sets_without_claims,
    "05_invalid_claim_sets_without_claims"
);
case_test!(
    case_06_invalid_claim_sets_missing_claim_id,
    "06_invalid_claim_sets_missing_claim_id"
);
case_test!(
    case_07_claim_sets_select_second_option,
    "07_claim_sets_select_second_option"
);
case_test!(case_08_values_filtering, "08_values_filtering");
case_test!(
    case_09_mdoc_invalid_claim_path_unsatisfied,
    "09_mdoc_invalid_claim_path_unsatisfied"
);
case_test!(
    case_10_trusted_authorities_filtering,
    "10_trusted_authorities_filtering"
);
case_test!(
    case_11_holder_binding_required_default,
    "11_holder_binding_required_default"
);
case_test!(
    case_12_holder_binding_not_required_allows,
    "12_holder_binding_not_required_allows"
);
case_test!(
    case_13_vct_extends_chain_matches,
    "13_vct_extends_chain_matches"
);
case_test!(
    case_14_optional_set_only_allows_empty,
    "14_optional_set_only_allows_empty"
);
case_test!(
    case_15_optional_dedup_when_option_is_forced,
    "15_optional_dedup_when_option_is_forced"
);
case_test!(
    case_16_mismatched_meta_for_special_format_rejects,
    "16_mismatched_meta_for_special_format_rejects"
);
case_test!(
    case_17_meta_other_allows_any_format,
    "17_meta_other_allows_any_format"
);
case_test!(
    case_18_sdjwt_meta_on_other_format_allowed,
    "18_sdjwt_meta_on_other_format_allowed"
);
case_test!(
    case_19_empty_credentials_invalid,
    "19_empty_credentials_invalid"
);
case_test!(case_20_empty_option_ignored, "20_empty_option_ignored");
case_test!(
    case_21_empty_claim_path_filters_out,
    "21_empty_claim_path_filters_out"
);
case_test!(
    case_22_transaction_data_single_id_match,
    "22_transaction_data_single_id_match"
);
case_test!(
    case_23_transaction_data_single_id_no_match_unsatisfied,
    "23_transaction_data_single_id_no_match_unsatisfied"
);
case_test!(
    case_24_transaction_data_single_id_multiple_types_all_required,
    "24_transaction_data_single_id_multiple_types_all_required"
);
case_test!(
    case_25_transaction_data_single_id_missing_second_unsatisfied,
    "25_transaction_data_single_id_missing_second_unsatisfied"
);
case_test!(
    case_26_transaction_data_multi_id_filters_configs,
    "26_transaction_data_multi_id_filters_configs"
);
case_test!(
    case_27_transaction_data_multi_id_none_match_unsatisfied,
    "27_transaction_data_multi_id_none_match_unsatisfied"
);
case_test!(
    case_28_transaction_data_subtype_match,
    "28_transaction_data_subtype_match"
);
case_test!(
    case_29_transaction_data_subtype_mismatch_unsatisfied,
    "29_transaction_data_subtype_mismatch_unsatisfied"
);
case_test!(
    case_30_transaction_data_empty_credential_ids_invalid,
    "30_transaction_data_empty_credential_ids_invalid"
);
case_test!(
    case_31_transaction_data_unknown_credential_id_invalid,
    "31_transaction_data_unknown_credential_id_invalid"
);
case_test!(
    case_32_transaction_data_multiple_constraints_filter,
    "32_transaction_data_multiple_constraints_filter"
);
case_test!(
    case_33_transaction_data_empty_array_ignored,
    "33_transaction_data_empty_array_ignored"
);
case_test!(
    case_34_transaction_data_affects_claim_sets_selection,
    "34_transaction_data_affects_claim_sets_selection"
);
case_test!(
    case_35_transaction_data_singleton_option_prunes_candidates,
    "35_transaction_data_singleton_option_prunes_candidates"
);
case_test!(
    case_36_unknown_format_is_ignored,
    "36_unknown_format_is_ignored"
);
case_test!(
    case_37_transaction_data_requires_consistent_credential_per_id,
    "37_transaction_data_requires_consistent_credential_per_id"
);
case_test!(
    case_38_mdoc_meta_optional_broad_match,
    "38_mdoc_meta_optional_broad_match"
);
case_test!(
    case_39_transaction_data_requires_holder_binding,
    "39_transaction_data_requires_holder_binding"
);
case_test!(
    case_40_sdjwt_meta_unknown_fields_ignored,
    "40_sdjwt_meta_unknown_fields_ignored"
);
case_test!(
    case_41_transaction_data_overlap_single_keeps_other_unconstrained,
    "41_transaction_data_overlap_single_keeps_other_unconstrained"
);
case_test!(
    case_42_transaction_data_overlap_multi_assignment_domains,
    "42_transaction_data_overlap_multi_assignment_domains"
);
case_test!(
    case_43_options_required_disjunction_matrix,
    "43_options_required_disjunction_matrix"
);
case_test!(
    case_44_options_optional_set_matrix,
    "44_options_optional_set_matrix"
);
case_test!(
    case_45_options_optional_multi_option_matrix,
    "45_options_optional_multi_option_matrix"
);
case_test!(
    case_46_single_set_single_query_multiple_candidates,
    "46_single_set_single_query_multiple_candidates"
);
case_test!(
    case_47_single_set_two_options_multi_format,
    "47_single_set_two_options_multi_format"
);

fn run_case(case_dir: &Path) {
    let request_path = case_dir.join("request.json");
    let credentials_path = case_dir.join("credentials.json");
    let expected_path = case_dir.join("expected.json");

    let expected: Expected = read_json(&expected_path);
    let request_text = fs::read_to_string(&request_path)
        .unwrap_or_else(|e| panic!("failed to read {request_path:?}: {e}"));
    let request_result = serde_json::from_str::<RequestFixture>(&request_text);

    let request = match request_result {
        Ok(request) => {
            if let Expected::ParseError { message } = &expected {
                panic!(
                    "{case_dir:?}: expected parse error {:?} but request parsed successfully",
                    message
                );
            }
            request
        }
        Err(err) => {
            if let Expected::ParseError { message } = &expected {
                assert_parse_error(case_dir, &err, message.as_deref());
                return;
            }
            panic!("failed to parse {request_path:?} as RequestFixture: {err}\n{request_text}");
        }
    };

    let pkg: CredentialPackage = read_json(&credentials_path);

    let store = JsonStore::from_package(pkg);

    assert_outcome_with_expected(
        case_dir,
        &request,
        &store,
        &PlanOptions::default(),
        expected,
    );
    assert_option_matrix_if_present(case_dir, &request, &store);
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {path:?}: {e}"));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("failed to parse {path:?} as json: {e}\n{text}"))
}

const OPTION_COMBINATIONS: [(&str, PlanOptions); 6] = [
    (
        "all_satisfiable.prefer_present",
        PlanOptions {
            credential_set_option_mode: CredentialSetOptionMode::AllSatisfiable,
            optional_credential_sets_mode: OptionalCredentialSetsMode::PreferPresent,
        },
    ),
    (
        "all_satisfiable.prefer_absent",
        PlanOptions {
            credential_set_option_mode: CredentialSetOptionMode::AllSatisfiable,
            optional_credential_sets_mode: OptionalCredentialSetsMode::PreferAbsent,
        },
    ),
    (
        "all_satisfiable.always_present_if_satisfiable",
        PlanOptions {
            credential_set_option_mode: CredentialSetOptionMode::AllSatisfiable,
            optional_credential_sets_mode: OptionalCredentialSetsMode::AlwaysPresentIfSatisfiable,
        },
    ),
    (
        "first_satisfiable_only.prefer_present",
        PlanOptions {
            credential_set_option_mode: CredentialSetOptionMode::FirstSatisfiableOnly,
            optional_credential_sets_mode: OptionalCredentialSetsMode::PreferPresent,
        },
    ),
    (
        "first_satisfiable_only.prefer_absent",
        PlanOptions {
            credential_set_option_mode: CredentialSetOptionMode::FirstSatisfiableOnly,
            optional_credential_sets_mode: OptionalCredentialSetsMode::PreferAbsent,
        },
    ),
    (
        "first_satisfiable_only.always_present_if_satisfiable",
        PlanOptions {
            credential_set_option_mode: CredentialSetOptionMode::FirstSatisfiableOnly,
            optional_credential_sets_mode: OptionalCredentialSetsMode::AlwaysPresentIfSatisfiable,
        },
    ),
];

fn option_expected_path(case_dir: &Path, slug: &str) -> PathBuf {
    case_dir.join(format!("expected.option.{slug}.json"))
}

fn assert_option_matrix_if_present(case_dir: &Path, request: &RequestFixture, store: &JsonStore) {
    let present = OPTION_COMBINATIONS
        .iter()
        .filter(|(slug, _)| option_expected_path(case_dir, slug).exists())
        .count();

    if present == 0 {
        return;
    }

    assert_eq!(
        present,
        OPTION_COMBINATIONS.len(),
        "{case_dir:?}: option matrix is partial; provide all {} expected.option.*.json files",
        OPTION_COMBINATIONS.len()
    );

    for (slug, options) in OPTION_COMBINATIONS {
        let expected_path = option_expected_path(case_dir, slug);
        let expected: Expected = read_json(&expected_path);
        if matches!(expected, Expected::ParseError { .. }) {
            panic!(
                "{case_dir:?}: parse_error is not valid for option matrix file {expected_path:?}"
            );
        }
        assert_outcome_with_expected(case_dir, request, store, &options, expected);
    }
}

fn assert_outcome_with_expected(
    case_dir: &Path,
    request: &RequestFixture,
    store: &JsonStore,
    options: &PlanOptions,
    expected: Expected,
) {
    let actual = plan_selection(
        &request.dcql_query,
        request.transaction_data.as_deref(),
        store,
        options,
    );

    match (actual, expected) {
        (
            Ok(plan),
            Expected::Plan {
                presentation_sets,
            },
        ) => {
            assert_plan(
                case_dir,
                &request.dcql_query,
                request.transaction_data.as_deref(),
                &plan,
                &presentation_sets,
            );
        }
        (Err(err), Expected::Error { error, message }) => {
            assert_error(case_dir, err, &error, message.as_deref());
        }
        (Ok(plan), Expected::Error { error, .. }) => {
            panic!(
                "{case_dir:?}: expected error {error:?} but got plan with {} outer alternatives",
                plan.presentation_sets.len()
            );
        }
        (Err(err), Expected::Plan { .. }) => {
            panic!("{case_dir:?}: expected plan but got error: {err:?}");
        }
        (_, Expected::ParseError { message }) => {
            panic!(
                "{case_dir:?}: expected parse error {:?} but query parsed and planner ran",
                message
            );
        }
    }
}

fn assert_error(case_dir: &Path, err: PlanError, expected_err: &str, expected_msg: Option<&str>) {
    match err {
        PlanError::Unsatisfied => {
            assert_eq!(
                expected_err, "Unsatisfied",
                "{case_dir:?}: wrong error kind"
            );
        }
        PlanError::InvalidQuery(msg) => {
            assert_eq!(
                expected_err, "InvalidQuery",
                "{case_dir:?}: wrong error kind"
            );
            if let Some(expected) = expected_msg {
                assert_eq!(msg, expected, "{case_dir:?}: wrong invalid query message");
            }
        }
    }
}

fn assert_parse_error(case_dir: &Path, err: &serde_json::Error, expected_msg: Option<&str>) {
    if let Some(expected) = expected_msg {
        assert!(
            err.to_string().contains(expected),
            "{case_dir:?}: parse error mismatch, expected substring {expected:?}, got {err}"
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn assert_plan(
    case_dir: &Path,
    _request: &DcqlQuery,
    expected_transaction_data: Option<&[TransactionData]>,
    plan: &DcqlOutput<String>,
    expected_presentation_sets: &[Vec<SlotExpectation>],
) {
    assert_presentation_sets(case_dir, plan, expected_presentation_sets);

    // Verify transaction-data bindings are coherent with entries and fully assigned.
    let expected_transaction_data_len = expected_transaction_data.map_or(0, |data| data.len());
    for set in &plan.presentation_sets {
        let mut covered = BTreeSet::new();
        for slot in set {
            for index in &slot.transaction_data_ids {
                assert!(
                    *index < expected_transaction_data_len,
                    "{case_dir:?}: transaction_data index {} out of bounds",
                    index
                );
                covered.insert(*index);
            }
        }
        assert_eq!(
            covered.len(),
            expected_transaction_data_len,
            "{case_dir:?}: each presentation set must cover all transaction_data entries"
        );
    }
}

fn claim_value_matches_json(expected: &ClaimValue, actual: &Value) -> bool {
    match expected {
        ClaimValue::String(value) => actual.as_str() == Some(value),
        ClaimValue::Integer(value) => actual.as_i64() == Some(*value),
        ClaimValue::Boolean(value) => actual.as_bool() == Some(*value),
    }
}

fn assert_presentation_sets(
    case_dir: &Path,
    plan: &DcqlOutput<String>,
    expected: &[Vec<SlotExpectation>],
) {
    let mut actual = plan
        .presentation_sets
        .iter()
        .map(|set| canonicalize_actual_set(set))
        .collect::<Vec<_>>();
    actual.sort();

    let mut expected = expected
        .iter()
        .map(|set| canonicalize_expected_set(set))
        .collect::<Vec<_>>();
    expected.sort();

    assert_eq!(
        actual, expected,
        "{case_dir:?}: presentation_sets mismatch with expected"
    );
}

fn canonicalize_actual_set(set: &[dcapi_dcql::SetAlternative<String>]) -> String {
    let mut slot_parts = set
        .iter()
        .map(canonicalize_actual_slot)
        .collect::<Vec<_>>();
    slot_parts.sort();
    slot_parts.join("||")
}

fn canonicalize_expected_set(set: &[SlotExpectation]) -> String {
    let mut slot_parts = set
        .iter()
        .map(canonicalize_expected_slot)
        .collect::<Vec<_>>();
    slot_parts.sort();
    slot_parts.join("||")
}

fn canonicalize_actual_slot(slot: &dcapi_dcql::SetAlternative<String>) -> String {
    let mut transaction_data_ids = slot.transaction_data_ids.clone();
    transaction_data_ids.sort();
    let mut alt_parts = Vec::new();
    for selection in &slot.alternatives {
        if selection.credential_id.is_none() {
            alt_parts.push("__none__".to_string());
            continue;
        }
        let mut claim_ids = selection
            .selected_claims
            .iter()
            .filter_map(|claim| claim.id.clone())
            .collect::<Vec<_>>();
        claim_ids.sort();
        let cred_id = selection.credential_id.as_ref().unwrap();
        alt_parts.push(format!(
            "{}:{}:claims=[{}]",
            selection.dcql_id,
            cred_id,
            claim_ids.join(",")
        ));
    }
    alt_parts.sort();
    format!(
        "tx=[{}];alts=[{}]",
        join_indices(&transaction_data_ids),
        alt_parts.join("|")
    )
}

fn canonicalize_expected_slot(slot: &SlotExpectation) -> String {
    let mut transaction_data_ids = slot.transaction_data_ids.clone();
    transaction_data_ids.sort();
    let mut alt_parts = Vec::new();
    for selection in &slot.alternatives {
        if selection.credential_id.is_none() {
            alt_parts.push("__none__".to_string());
            continue;
        }
        let mut claim_ids = selection.selected_claim_ids.clone();
        claim_ids.sort();
        let cred_id = selection.credential_id.as_ref().unwrap();
        alt_parts.push(format!(
            "{}:{}:claims=[{}]",
            selection.dcql_id,
            cred_id,
            claim_ids.join(",")
        ));
    }
    alt_parts.sort();
    format!(
        "tx=[{}];alts=[{}]",
        join_indices(&transaction_data_ids),
        alt_parts.join("|")
    )
}

fn join_indices(indices: &[usize]) -> String {
    indices
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

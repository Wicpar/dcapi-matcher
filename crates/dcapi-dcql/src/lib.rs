#![doc = include_str!("../README.md")]
mod models;
mod path;
mod planner;
mod store;

pub use models::*;
pub use path::{
    ClaimsPathPointer, PathElement, PathError, is_mdoc_path, path_matches, select_nodes,
};
pub use planner::{
    CredentialSetOptionMode, OptionalCredentialSetsMode, PlanError, PlanOptions, QueryMatches,
    SelectionAlternative, SelectionEntry, SelectionPlan, TransactionDataAssignment, plan_selection,
    pointer_from_strings,
};
pub use store::{CredentialFormat, CredentialStore, ValueMatch};

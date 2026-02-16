# dcapi-matcher

`dcapi-matcher` is a reusable matcher framework for:

- OpenID4VP (`dcql_query`, `presentation_definition`)
- OpenID4VCI (`credential_offer`)
- Android Credential Manager output building

## Purpose

The crate is designed so wallet projects only need to:

1. Define their credential package format.
2. Implement matching/display behavior through `MatcherStore`.

The framework handles request parsing, DCQL planning integration, and conversion to Credman
entry/set structures.

## Main API

- `match_dc_api_request(request_json, store, options)`
- `MatcherStore` (your package adapter trait)
- `ResolvedMatcherResponse` (owned response; convert to Credman with `as_credman_response()` or apply with `apply()`)
- `diagnostics` (collect and render execution diagnostics as Credman entries)

## Package Decode Helpers

- `decode_cbor_package`
- `decode_cbor_package_from_reader`
- `decode_json_package`

## Metadata Model

For each candidate credential, metadata passed to Credman can combine:

- `CredentialDescriptor.metadata` (credential-level metadata),
- framework-generated `selection_context` metadata (protocol/query context),
- `MatcherStore::metadata_for_credman` (dynamic app-defined metadata).

JSON object insertion order is preserved (workspace uses `serde_json` with `preserve_order`).

## Diagnostics Rendering

`dcapi-matcher` can collect execution diagnostics and render them as one final
credential set (`dcapi:diagnostics`).

- Scope lifecycle:
  - each `#[dcapi_matcher]` invocation starts a fresh diagnostics scope.
  - the macro flushes diagnostics at the end, after your matcher function returns (or panics).
- Severity filtering:
  - levels are `Trace`, `Debug`, `Info`, `Warn`, `Error`.
  - default render threshold is `Error`.
  - lower the threshold with `diagnostics::set_render_level(...)` inside your matcher call.
  - set a process-wide default for future invocations with `diagnostics::set_default_render_level(...)`.
- Automatic recording:
  - matcher framework errors returned by `match_dc_api_request` (and package decode helpers)
    are recorded automatically.
  - panics caught by `#[dcapi_matcher]` are recorded as error diagnostics.
- Manual recording:
  - use `diagnostics::trace/debug/info/warn/error`, `diagnostics::push(...)`, or
    `diagnostics::push_with_detail(...)`
    to add app-specific diagnostics.

## OpenID Compliance Profile

The matcher currently enforces and/or supports the following OpenID behavior:

- OpenID4VP:
  - `dcql_query` evaluation (delegated to `dcapi-dcql`) with optional `transaction_data`.
  - `presentation_definition` fallback matching when enabled.
  - unknown request parameters are ignored.
  - `openid4vp-v1-signed` and `openid4vp-v1-multisigned` are parsed as unsupported (no JWS verification in this crate).
  - TS12 SCA transaction-data support:
    - built-in validation for `urn:eudi:sca:payment:1` and `urn:eudi:sca:generic:1`.
    - TS12 display is driven by credential-provided transaction metadata
      (`MatcherStore::ts12_transaction_metadata`) with localized claim labels and UI labels.
    - TS12 payloads are validated against the JSON Schema object provided in that metadata
      (no built-in schemas are embedded in the matcher). External `$ref` references are forbidden;
      only local fragment refs (starting with `#`) are accepted.
    - `MatcherStore::preferred_locales` must be provided for TS12; missing localized labels cause
      the matcher to return an error.
    - transaction fields are emitted separately (`ResolvedCredentialEntry.transaction_fields`)
      and appear before claim fields in string-id entries.
    - payment-style rendering is only used when a single TS12 entry provides payment payload data,
      and additional info is derived from localized transaction fields (no hardcoded labels).
    - optional `MatcherStore::format_ts12_value` hook lets wallets localize value codes
      (for example, recurrence frequency identifiers) without hardcoded strings in the matcher.
- OpenID4VCI:
  - `credential_offer` by value (direct object or wrapped form) is supported.
  - `credential_offer_uri` is explicitly unsupported in this runtime.
  - `credential_offer` and `credential_offer_uri` are treated as mutually exclusive.
  - `credential_configuration_ids` must be non-empty, unique, and contain non-empty strings.
  - slot ordering follows `credential_configuration_ids` order from the request.

This split is intentional: `dcapi-matcher` provides deterministic matching and response shaping,
while network retrieval and cryptographic verification for signed flows can be layered on top by the integrator.

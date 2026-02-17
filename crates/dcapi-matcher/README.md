# dcapi-matcher

`dcapi-matcher` is a reusable matcher framework for:

- OpenID4VP (`dcql_query`)
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
- `MatcherResponse` (owned response; apply with `apply()`)
- `diagnostics` (collect and render execution diagnostics as Credman entries)

## Package Decode Helpers

- `decode_json_package`

## Metadata Model

For each candidate credential, metadata passed to Credman includes only:

- `credential_id` (the DCQL credential query id)
- `transaction_data_indices` (indices into the request `transaction_data` array)

## Diagnostics Rendering

`dcapi-matcher` can collect execution diagnostics and render them as one final
credential set (`dcapi:diagnostics`).

- Scope lifecycle:
  - `match_dc_api_request` and `match_dc_api_request_value` clear diagnostics at the start of matching.
  - the `#[dcapi_matcher]` macro flushes diagnostics at the end, after your matcher function returns (or panics).
- Severity filtering:
  - levels are `Trace`, `Debug`, `Info`, `Warn`, `Error`.
  - logging is disabled unless you call `diagnostics::set_level(...)` (for example via `MatcherStore::log_level`).
- Automatic recording:
  - matcher framework errors returned by `match_dc_api_request` (and package decode helpers)
    are recorded automatically.
  - panics caught by `#[dcapi_matcher]` are recorded as error diagnostics.
- Manual recording:
  - use `diagnostics::trace/debug/info/warn/error` to add app-specific diagnostics.

## OpenID Compliance Profile

The matcher currently enforces and/or supports the following OpenID behavior:

- OpenID4VP:
  - `dcql_query` evaluation (delegated to `dcapi-dcql`) with optional `transaction_data`.
  - `scope`-based DCQL queries are not supported (enable `allow_dcql_scope` to surface an error).
  - `response_mode = dc_api.jwt` is gated by `OpenId4VpConfig::allow_response_mode_jwt`.
  - unknown request parameters are ignored.
  - `openid4vp-v1-signed` and `openid4vp-v1-multisigned` require decoded request objects;
    raw `request` objects are rejected (no JWS verification in this crate).
  - TS12 SCA transaction-data support:
    - built-in validation for `urn:eudi:sca:payment:1` and `urn:eudi:sca:generic:1`.
    - TS12 display is driven by credential-provided transaction metadata
      (`MatcherStore::ts12_transaction_metadata`) with localized claim labels and UI labels.
    - TS12 payloads are validated against the JSON Schema object provided in that metadata
      (no built-in schemas are embedded in the matcher). External `$ref` references are forbidden;
      only local fragment refs (starting with `#`) are accepted.
    - `MatcherStore::preferred_locales` must be provided for TS12; missing localized labels cause
      the matcher to return an error.
    - transaction fields are emitted as entry fields and appear before claim fields in string-id entries.
    - payment-style rendering is only used when a single TS12 entry provides payment payload data,
      and additional info is derived from localized transaction fields (no hardcoded labels).
    - optional `MatcherStore::format_ts12_value` hook lets wallets localize value codes
      (for example, recurrence frequency identifiers) without hardcoded strings in the matcher.
- OpenID4VCI:
  - matching uses only the credential offer + optional issuer metadata; it does not consult the
    credential store.
  - `credential_offer` by value (direct object or wrapped form) is supported.
  - `credential_offer_uri` is ignored when disabled; when enabled it returns an error because this
    runtime does not perform network fetches.
  - `credential_offer` and `credential_offer_uri` are treated as mutually exclusive.
  - `credential_configuration_ids` must be non-empty, unique, and contain non-empty strings.
  - slot ordering follows `credential_configuration_ids` order from the request.
  - grant types are filtered using `OpenId4VciConfig` (authorization code, pre-authorized code,
    and transaction code support).
  - authorization code is only considered supported when either `authorization_details` or
    `scope` support is enabled.

This split is intentional: `dcapi-matcher` provides deterministic matching and response shaping,
while network retrieval and cryptographic verification for signed flows can be layered on top by the integrator.

## Building and testing:
Thism will build the matcher and copy it over to the expo project
```sh
cargo build -p aptitude-consortium-dcapi-matcher --target wasm32-wasip1 --release && wasm-opt --enable-bulk-memory -Oz -o ./target/wasm32-wasip1/release/aptitude-consortium-dcapi-matcher.opt.wasm ./target/wasm32-wasip1/release/aptitude-consortium-dcapi-matcher.wasm && gzip -9 -c ./target/wasm32-wasip1/release/aptitude-consortium-dcapi-matcher.opt.wasm > ../expo-digital-credentials-api/android/src/main/assets/aptitude-consortium-matcher.wasm
```

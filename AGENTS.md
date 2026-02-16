# dcapi-matcher Operating Notes

**Purpose**
`dcapi-matcher` is a no_std + alloc WASM matcher for the Digital Credentials API. It parses DC API requests, matches credentials using DCQL/Presentation Definition/OpenID4VCI, and emits Credman-compatible selection plans. If a protocol or feature is disabled in `MatcherOptions`, the matcher returns an empty response for that request.

**TS12 Handling**
- No built-in TS12 transaction data types exist in this library. The credential package must provide fully resolved metadata for each supported transaction data type.
- The store must supply `Ts12TransactionMetadata` with `type`, optional `subtype`, a concrete JSON Schema object, `claims`, and `ui_labels`. Any `claims_uri`/`ui_labels_uri` resolution and `extends` merging must be done by the store.
- Schema validation uses `jsonschema` v0.42.0 with default features disabled. External references are forbidden: `$ref` values must be local (`#...`). The matcher never performs network or file resolution.
- Internationalization is enforced: UI labels and claim display labels must exist for the selected locale. If localized labels are missing, the transaction data entry is skipped with a warning.
- Payment rendering is store-driven. Use `MatcherStore::ts12_payment_summary` to indicate a transaction should render as a payment entry. The matcher does not infer payment types.

**Transaction Data Warnings**
- Invalid `transaction_data` entries (bad base64, invalid JSON, missing `type`/`credential_ids`, or invalid TS12 payload shape) are dropped and logged as warnings.
- Errors tied to credential packages (e.g., invalid TS12 metadata, schema validation failures) remove that credential from transaction data matching and emit warnings.
- If no valid `transaction_data` entries remain, the request yields an empty response.

**Logging and Errors**
- Runtime diagnostics are collected via the `dcapi-matcher-tracing` backend (no std/syscalls). Logs are flushed into a Credman credential entry at the end of execution.
- The matcher avoids hardcoded UI strings. Only error/log messages are formatted in code; all display strings must come from credential metadata or store-provided formatting hooks.

**JSON Order**
`serde_json` is configured with `preserve_order` at the workspace level to keep field order stable across all crates.

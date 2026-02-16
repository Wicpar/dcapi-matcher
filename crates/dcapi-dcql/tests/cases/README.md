# DCQL JSON test cases

This directory contains **golden JSON fixtures** used by the integration test `tests/dcql_json_suite.rs`.

Each case is a folder with:

- `request.json` – a request containing `DcqlQuery` fields plus optional `transaction_data`.
- `credentials.json` – a minimal "credential package" consumed by the test-only JSON-backed `CredentialStore` implementation.
- `expected.json` – the expected outcome expressed as **properties** (configs + per-query matches), with optional strict alternative-level checks when needed.
- `expected.option.<credential_set_option_mode>.<optional_credential_sets_mode>.json` – optional full option matrix expectations. When one option file is present, all 6 combinations are required.

The suite asserts the constraints you described:

1. The planner output is an outer list of coherent inner alternatives.
2. The alternatives cover **exactly** the feasible credential-set configurations (`configs`).
3. Each alternative has explicit `transaction_data` bindings to credential ids.
4. Per-credential query matching (VCT / doctype / holder-binding / trusted authorities / claims / claim_sets) matches expectations.

## `credentials.json` schema (test-only)

```jsonc
{
  "credentials": [
    {
      "id": "cred1",
      "format": "dc+sd-jwt",
      "holder_binding": true,
      "vct": "vct:child",
      "extends_vcts": ["vct:base", "vct:root"], // optional full chain
      "doctype": "org.iso.18013.5.1.mDL",
      "trusted_authorities": [
        { "type": "ca", "values": ["TA1"] }
      ],
      "claims": { "name": "Alice" }
    }
  ]
}
```

Notes:

- `extends_vcts` is optional; omit it when a credential does not extend another VCT.
- `extends_vcts` is the full ancestor chain used transitively by `has_vct`.
- `claims` defaults to `{}` if omitted.
- Only the fields needed for DCQL planning are modeled.

## `expected.json` schema

### Plan

```jsonc
{
  "result": "plan",
  "min_outer_alternatives": 1, // optional metadata for fixture readers
  "configs": [
    ["a"],
    ["a", "nice_to_have"],
    []
  ],
  "query_matches": {
    "a": {
      "credentials": ["sd_a"],
      "selected_claim_ids": ["name"]
    }
  },
  "alternatives": [ // optional strict check, ignored when omitted
    {
      "transaction_data": [
        { "index": 0, "credential_id": "a" }
      ],
      "entries": {
        "a": {
          "credentials": ["sd_a"],
          "transaction_data_indices": [0]
        }
      }
    }
  ]
}
```

### Error

```jsonc
{ "result": "error", "error": "Unsatisfied" }
```

```jsonc
{ "result": "error", "error": "InvalidQuery", "message": "..." }
```

## Option Matrix File Names

If a case defines option-matrix expectations, these exact files are expected:

- `expected.option.all_satisfiable.prefer_present.json`
- `expected.option.all_satisfiable.prefer_absent.json`
- `expected.option.all_satisfiable.always_present_if_satisfiable.json`
- `expected.option.first_satisfiable_only.prefer_present.json`
- `expected.option.first_satisfiable_only.prefer_absent.json`
- `expected.option.first_satisfiable_only.always_present_if_satisfiable.json`

# HAIP Audit (Matcher Scope)

Source: OpenID4VC High Assurance Interoperability Profile 1.0 draft-04
(`/Users/administrator/IdeaProjects/dcapi-matcher/docs/openid4vc-high-assurance-interoperability-profile-1_0-04.md`)

Scope for this audit: requirements that can be validated or enforced by the matcher’s request
parsing, DCQL planning, and selection output. Protocol flows, network operations, cryptographic
verification, token issuance/presentation, and transport security are excluded.

## Checklist

### 5. OpenID for Verifiable Presentations (General)
- [ ] The Wallet and Verifier MUST support at least one of the following Credential Format
  Profiles defined in Section 6: IETF SD-JWT VC or ISO mdoc.
  Status: Partially supported. The DCQL planner supports both formats, but availability depends
  on the wallet’s credential store and is not enforced.
  Evidence: `/Users/administrator/IdeaProjects/dcapi-matcher/crates/dcapi-dcql/src/store.rs`,
  `/Users/administrator/IdeaProjects/dcapi-matcher/crates/dcapi-dcql/src/models.rs`.

- [ ] The Response type MUST be `vp_token`.
  Status: Not implemented. Request parsing does not validate `response_type`.
  Evidence: `/Users/administrator/IdeaProjects/dcapi-matcher/crates/dcapi-matcher/src/engine.rs`.

- [ ] The DCQL query and response as defined in Section 6 of OID4VP MUST be used.
  Status: Partially supported. The matcher uses `dcql_query` for selection and ignores
  Presentation Definition; it does not construct VP responses.
  Evidence: `/Users/administrator/IdeaProjects/dcapi-matcher/crates/dcapi-matcher/src/models.rs`,
  `/Users/administrator/IdeaProjects/dcapi-matcher/crates/dcapi-matcher/src/engine.rs`.

- [x] The `trusted_authorities` (aki-based) DCQL query constraint MUST be supported.
  Status: Implemented. Enforced through store hook during DCQL planning.
  Evidence: `/Users/administrator/IdeaProjects/dcapi-matcher/crates/dcapi-dcql/src/models.rs`,
  `/Users/administrator/IdeaProjects/dcapi-matcher/crates/dcapi-dcql/src/planner.rs`,
  `/Users/administrator/IdeaProjects/dcapi-matcher/crates/dcapi-dcql/src/store.rs`.

### 5.2. OpenID4VP via W3C Digital Credentials API
- [ ] The Response Mode MUST be `dc_api.jwt`.
  Status: Not enforced. The matcher only gates `dc_api.jwt` when present and when
  `allow_response_mode_jwt` is enabled.
  Evidence: `/Users/administrator/IdeaProjects/dcapi-matcher/crates/dcapi-matcher/src/engine.rs`,
  `/Users/administrator/IdeaProjects/dcapi-matcher/crates/dcapi-matcher/src/config.rs`.

- [ ] The Wallet MUST support both signed and unsigned requests (Annex A.3.1 / A.3.2).
  Status: Partially supported. Unsigned requests are accepted; signed request parsing is gated
  by `allow_signed_requests` and does not verify JWS.
  Evidence: `/Users/administrator/IdeaProjects/dcapi-matcher/crates/dcapi-matcher/src/engine.rs`,
  `/Users/administrator/IdeaProjects/dcapi-matcher/crates/dcapi-matcher/src/config.rs`.

### 5.3. Credential Formats
- [x] For ISO mdoc, the Credential Format identifier MUST be `mso_mdoc`.
  Status: Implemented in DCQL parsing and format matching.
  Evidence: `/Users/administrator/IdeaProjects/dcapi-matcher/crates/dcapi-dcql/src/store.rs`,
  `/Users/administrator/IdeaProjects/dcapi-matcher/crates/dcapi-dcql/src/models.rs`.

- [ ] For ISO mdoc, `intent_to_retain` MUST be present in the DCQL credential query.
  Status: Not implemented. `intent_to_retain` is optional and not validated or consumed.
  Evidence: `/Users/administrator/IdeaProjects/dcapi-matcher/crates/dcapi-dcql/src/models.rs`.

- [x] For SD-JWT VC, the Credential Format identifier MUST be `dc+sd-jwt`.
  Status: Implemented in DCQL parsing and format matching.
  Evidence: `/Users/administrator/IdeaProjects/dcapi-matcher/crates/dcapi-dcql/src/store.rs`,
  `/Users/administrator/IdeaProjects/dcapi-matcher/crates/dcapi-dcql/src/models.rs`.

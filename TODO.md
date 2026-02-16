# Todo

Here are the necessary tasks to complete to achive the following phase, do not proceed to future phase before completing previous.

# 1. MVP
- [ ] Ensure `dcapi-matcher` can be cleanly and easily implemented. it must ensure:
  1. A credential store format can be established and accessed by implementing the CredentialStore Trait
  2. The configurations options of openid4vp and openid4vci can be specified by the credential package in a detailed manner. It must be able to describe ALL supported features by the wallet (Holder) in the protocols
  3. The credential store must be able to define the locale to use as a `&[&str]`
  4. The credential store must be able to set the logging level, or disable logs entirely. Logs must be OFF by default, and enabled with log_level() -> Option<Level>, it must be injected into the logger backend.
  5. Sensible defaults must be returned from the CredentialMatcher: 
     - TransactionData -> false, as in unknown transaction data = Unsatisfiable
     - Supported algs and configurations for openid4vp, openid4vci: none
     - etc... essentially off by default.
  6. Test cases cover 100% of the code.
  7. An additional pass to check all validations and default params conform to [openid4vp](docs/openid_fullspec_bundle_2026-02-13/OpenID4VP_1.0.md) and [openid4vci](docs/openid_fullspec_bundle_2026-02-13/OpenID4VCI_1.0.md)


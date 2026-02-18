|  | openid4vc-high-assurance-interoperability | September 2025 |
|----|----|----|
| Yasuda & Lodderstedt | Standards Track | [Page] |

Workgroup:  
Digital Credentials Protocols

Published:  
19 September 2025

Authors:  

K. Yasuda

SPRIND

T. Lodderstedt

SPRIND

# OpenID4VC High Assurance Interoperability Profile 1.0 - draft 04

## Abstract

This document defines a profile of OpenID for Verifiable Credentials in
combination with the credential formats IETF SD-JWT VC
[I-D.ietf-oauth-sd-jwt-vc] and ISO mdoc
[ISO.18013-5]. The aim is
to select features and to define a set of requirements for the existing
specifications to enable interoperability among Issuers, Wallets and
Verifiers of Credentials where a high level of security and privacy is
required. The profiled specifications include OpenID for Verifiable
Credential Issuance
[OIDF.OID4VCI], OpenID
for Verifiable Presentations
[OIDF.OID4VP], IETF
SD-JWT VC [I-D.ietf-oauth-sd-jwt-vc], and ISO mdoc
[ISO.18013-5].

## 1. Introduction

This document defines a set of requirements for the existing
specifications to enable interoperability among Issuers, Wallets and
Verifiers of Credentials where a high level of security and privacy is
required. This document is an interoperability profile that can be used
by implementations in various contexts, be it a certain industry or a
certain regulatory environment. Note that while this profile is aimed at
high assurance use-cases, it can also be used for lower assurance
use-cases.

This document is not a specification, but a profile. It refers to the
specifications required for implementations to interoperate among each
other and for the optionalities mentioned in the referenced
specifications, defines the set of features to be mandatory to
implement.

The profile uses OpenID for Verifiable Credential Issuance
[OIDF.OID4VCI] and
OpenID for Verifiable Presentations
[OIDF.OID4VP] as the base
protocols for issuance and presentation of Credentials, respectively.
The credential formats used are IETF SD-JWT VC as specified in
[I-D.ietf-oauth-sd-jwt-vc] and ISO mdoc
[ISO.18013-5].
Additionally, considerations are given on how the issuance of
Credentials in both IETF SD-JWT VC [I-D.ietf-oauth-sd-jwt-vc] and ISO mdoc
[ISO.18013-5] formats can
be performed in the same
transaction.

A full list of the open standards used in this profile can be found in
Overview of the Open Standards Requirements
(reference).

### 1.1. Target Audience/Usage

The target audience of this document is implementers who require a high
level of security and privacy for their solutions. A non-exhaustive list
of the interested parties includes anyone implementing [eIDAS
2.0](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202401183),
[California Department of Motor
Vehicles](https://www.dmv.ca.gov/portal/), [Open Wallet Foundation
(OWF)](https://openwallet.foundation/),
[IDunion](https://idunion.org/?lang=en), [GAIN](https://gainforum.org/),
and [the Trusted Web project of the Japanese
government](https://trustedweb.go.jp/en), but is expected to grow to
include other jurisdictions and private sector
companies.

## 2. Terminology

This specification uses the terms "Holder", "Issuer", "Verifier",
"Wallet", "Wallet Attestation", "Credential Type" and "Verifiable
Credential" as defined in
[OIDF.OID4VCI] and
[OIDF.OID4VP].

## 3. Scope

This specification enables interoperable implementations of the
following flows:

- Issuance using OpenID4VCI for IETF SD-JWT VC
  and ISO mdocs
- Presentation using OpenID4VP via redirects or
  the W3C Digital Credentials API for IETF SD-JWT VC and ISO
  mdocs
- OpenID4VC Credential Format
  Profiles

Implementations of this specification do not have to implement all of
the flows listed above, but they MUST be compliant to all of the
requirements for a particular flow they chose to
implement.

A parameter that is listed as optional to be implemented in a
specification that is being profiled (i.e., OpenID4VCI, OpenID4VP, W3C
Digital Credentials API, IETF SD-JWT VC, and ISO mdoc) remains optional
unless it is stated otherwise in this
specification.

The Profile of OpenID4VCI defines Wallet Attestation and Key
Attestation.

The Profile of IETF SD-JWT VC defines the following
aspects:

- Status management of the Credentials,
  including
  revocation
- Cryptographic Key
  Binding
- Issuer key
  resolution
- Issuer identification (as prerequisite for
  trust management)

Mandatory to implement crypto suites are defined for all of the
flows.

Note that when OpenID4VP is used, the Wallet and the Verifier can either
be remote or in-person.

### 3.1. Assumptions

Assumptions made are the
following:

- The Issuers and Verifiers cannot
  pre-discover Wallet's
  capability
- The Issuer is talking to the Wallet
  supporting the features defined in this profile (via Wallet invocation
  mechanism)
- There are mechanisms in place for Verifiers
  to discover Wallets' and Issuers'
  capabilities
- There are mechanisms in place for Wallets
  to discover Verifiers'
  capabilities
- There are mechanisms in place for Issuers
  to discover Wallets'
  capabilities

### 3.2. Scenarios/Business Requirements

- Combined Issuance of IETF SD-JWT VC and ISO
  mdoc
- Both issuer-initiated and wallet-initiated
  issuance
- Presentation and Issuance of PID and (Q)EAA
  as defined in Architecture and Reference Framework
  [EU.ARF] implementing
  [eIDAS2.0].
- Issuance and presentation of Credentials
  with and without cryptographic holder
  binding

### 3.3. Standards Requirements

The standards that are being profiled in this specification
are:

- OpenID for Verifiable Credential Issuance
  [OIDF.OID4VCI]
- OpenID for Verifiable Presentations
  [OIDF.OID4VP]
- W3C Digital Credentials API
  [w3c.digital_credentials_api]
- SD-JWT-based Verifiable Credentials (SD-JWT
  VC) [I-D.ietf-oauth-sd-jwt-vc]
- ISO/IEC 18013-5:2021 Personal
  identification - ISO-compliant driving licence Part 5: Mobile driving
  licence (mDL) application
  [ISO.18013-5]

Note that these standards in turn build upon other underlying standards,
and requirements in those underlying standards also need to be
followed.

### 3.4. Out of Scope

The following items are out of scope for the current version of this
document, but might be added in future
versions:

- Trust Management refers to authorization of
  an Issuer to issue certain types of credentials, authorization of the
  Wallet to be issued certain types of credentials, authorization of the
  Verifier to receive certain types of credentials. Although X.509 PKI
  is extensively utilized in this profile, the methods for establishing
  trust or obtaining root certificates are out of the scope of this
  specification.
- Protocol for presentation of Verifiable
  Credentials for offline use-cases, e.g. over
  BLE.

## 4. OpenID for Verifiable Credential Issuance

Both the Wallet and the Credential
Issuer:

- MUST support the authorization code
  flow.
- MUST support at least one of the following
  Credential Format Profiles defined in
  Section 6: IETF
  SD-JWT VC or ISO mdoc. Ecosystems SHOULD clearly indicate which of
  these formats, IETF SD-JWT VC, ISO mdoc, or both, are required to be
  supported.
- MUST support sender-constrained tokens using
  the mechanism defined in
  [RFC9449]. Note this
  requires Wallets to be prepared to handle the `DPoP-Nonce` HTTP
  response header from the Credential Issuer's Nonce Endpoint, as well
  as from other applicable endpoints of the Credential Issuer and
  Authorization
  Server.
- MUST support
  [RFC7636] with `S256` as
  the code challenge
  method.

Both Wallet initiated and Issuer initiated issuance are
supported.

### 4.1. Issuer Metadata

The Authorization Server MUST support metadata according to
[RFC8414].

The Credential Issuer MUST support metadata retrieval according to
Section 12.2.2 of
[OIDF.OID4VCI]. The
Credential Issuer metadata MUST include a scope for every Credential
Configuration it supports.

When ecosystem policies require Issuer Authentication to a higher level
than possible with TLS alone, signed Credential Issuer Metadata as
specified in Section 11.2.3 in
[OIDF.OID4VCI] MUST be
supported by both the Wallet and the Issuer. Key resolution to validate
the signed Issuer Metadata MUST be supported using the `x5c` JOSE header
parameter as defined in
[RFC7515]. In this case, the
X.509 certificate of the trust anchor MUST NOT be included in the `x5c`
JOSE header of the signed request. The X.509 certificate signing the
request MUST NOT be
self-signed.

If the Issuer supports Credential Configurations that require key
binding, as indicated by the presence of
`cryptographic_binding_methods_supported`, the `nonce_endpoint` MUST be
present in the Credential Issuer
Metadata.

### 4.2. Credential Offer

- The Grant Type `authorization_code` MUST be
  supported as defined in Section 4.1.1 in
  [OIDF.OID4VCI]
- For Grant Type `authorization_code`, the
  Issuer MUST include a scope value in order to allow the Wallet to
  identify the desired Credential Type. The Wallet MUST use that value
  in the `scope` Authorization
  parameter.
- As a way to invoke the Wallet the custom
  URL scheme `haip-vci://` MAY be supported. Implementations MAY support
  other ways to invoke Wallets as agreed upon by trust
  frameworks/ecosystems/jurisdictions, including but not limited to
  using other custom URL schemes or claimed "https" scheme
  URIs.

Note: The Authorization Code flow does not require a Credential Offer
from the Issuer to the Wallet. However, it is included in the feature
set to allow for Issuer initiated Credential
issuance.

Both Issuer and Wallet MUST support Credential Offer in both same-device
and cross-device flows.

### 4.3. Authorization Endpoint

- MUST use Pushed Authorization Requests
  (PAR) [RFC9126] to send the
  Authorization
  Request.
- Wallets MUST authenticate themselves at the
  PAR endpoint using the same rules as defined in
  Section 4.4
  for client authentication at the token
  endpoint.
- MUST use the `scope` parameter to
  communicate Credential Type(s) to be issued. The scope value MUST map
  to a specific Credential Type. The scope value may be pre-agreed,
  obtained from the Credential Offer, or the Credential Issuer
  Metadata.
- The `client_id` value in the PAR request
  MUST be a string that the Wallet has used as the `sub` value in the
  client attestation
  JWT.

### 4.4. Token Endpoint

- The Wallets MUST perform client
  authentication as defined in
  Section
  4.4.1.
- Refresh tokens are RECOMMENDED to be
  supported for Credential refresh. For details, see Section 13.5 in
  [OIDF.OID4VCI].

Note: Issuers SHOULD be mindful of how long the usage of the refresh
token is allowed to refresh a credential, as opposed to starting the
issuance flow from the beginning. For example, if the User is trying to
refresh a Credential more than a year after its original issuance, the
usage of the refresh tokens is NOT
RECOMMENDED.

#### 4.4.1. Wallet Attestation

Wallets MUST use Wallet Attestations as defined in Annex E of
[OIDF.OID4VCI].

The public key certificate, and optionally a trust certificate chain,
used to validate the signature on the Wallet Attestation MUST be
included in the `x5c` JOSE header of the Client Attestation
JWT.

Individual Wallet Attestations MUST be used for each Issuer and they
MUST not contain unique identifiers that would enable linkability
between issuance processes. See section 14.4.4 of
[OIDF.OID4VCI] for
details on the Wallet Attestation
subject.

### 4.5. Credential Endpoint

The following proof types MUST be
supported:

- `jwt` proof type using
  `key_attestation`
- `attestation` proof
  type

#### 4.5.1. Key Attestation

Wallets MUST support key attestations. Ecosystems that desire
wallet-issuer interoperability on the level of key attestations SHOULD
require Wallets to support the format specified in Annex D of
[OIDF.OID4VCI].
Alternatively, ecosystems MAY choose to rely on other key attestation
formats.

If batch issuance is used and the Credential Issuer has indicated (via
`cryptographic_binding_methods_supported` metadata parameter) that
cryptographic holder binding is required, all public keys used in
Credential Request SHOULD be attested within a single key
attestation.

## 5. OpenID for Verifiable Presentations

The following requirements apply to OpenID4VP, irrespective of the flow
and Credential Format, unless specified
otherwise:

- The Wallet and Verifier MUST support at least
  one of the following Credential Format Profiles defined in
  Section 6: IETF
  SD-JWT VC or ISO mdoc. Ecosystems SHOULD clearly indicate which of
  these formats, IETF SD-JWT VC, ISO mdoc, or both, are required to be
  supported.
- The Response type MUST be
  `vp_token`.
- For signed requests, the Verifier MUST use,
  and the Wallet MUST accept the Client Identifier Prefix `x509_hash` as
  defined in Section 5.9.3 of
  [OIDF.OID4VP]. The
  X.509 certificate of the trust anchor MUST NOT be included in the
  `x5c` JOSE header of the signed request. The X.509 certificate signing
  the request MUST NOT be self-signed. X.509 certificate profiles to be
  used with `x509_hash` are out of scope of this specification.
  Ecosystems MAY define their own X.509 certificate profiles for
  `x509_hash` and use them accordingly. For example, an mDL ecosystem
  can use the Reader Authentication Certificate profile defined in
  ISO/IEC 18013-5, Annex B with
  `x509_hash`.
- The DCQL query and response as defined in
  Section 6 of
  [OIDF.OID4VP] MUST be
  used.
- Response encryption MUST be performed as
  specified in Section 8.3 of
  [OIDF.OID4VP]. The JWE
  `alg` (algorithm) header parameter (see
  Section
  4.1.1 of [RFC7516])
  value `ECDH-ES` (as defined in
  Section
  4.6 of [RFC7518]), with
  key agreement utilizing keys on the `P-256` curve (see
  Section
  6.2.1.1 of [RFC7518])
  MUST be supported. The JWE `enc` (encryption algorithm) header
  parameter (see
  Section
  4.1.2 of [RFC7516])
  value `A128GCM` (as defined in
  Section
  5.3 of [RFC7518]) MUST
  be supported.
- Verifiers MUST use ephemeral encryption keys
  specific to each Authorization Request passed via client metadata as
  specified in Section 8.3 of
  [OIDF.OID4VP].
- The Authority Key Identifier (`aki`)-based
  Trusted Authority Query (`trusted_authorities`) for DCQL, as defined
  in section 6.1.1.1 of
  [OIDF.OID4VP], MUST be
  supported. Note that the Authority Key Identifiers mechanism can be
  used to support multiple X.509-based trust mechanisms, such as ISO mDL
  VICAL (as introduced in
  [ISO.18013-5]) or ETSI
  Trusted Lists [ETSI.TL].
  This is achieved by collecting the relevant X.509 certificates for the
  trusted Issuers and including the encoded Key Identifiers from the
  certificates in the `aki` array
  .

Additional requirements for OpenID4VP are defined in
Section 5.1,
Section 5.2 and
Section
5.3.

Note that while this document does not define profiles for X.509
certificates used in Verifier authentication (e.g., with the `x509_hash`
Client Identifier Prefix), ecosystems are encouraged to define their own
certificate issuing policies and certificate profiles. Such policies and
profiles MAY specify how information in the certificate corresponds to
information in the presentation flows. For example, an ecosystem might
require that the Wallet verifies that the `redirect_uri`,
`response_uri`, `origin`, or `expected_origin` request parameters match
with information contained in the Verifier's end-entity certificate
(e.g., its DNS name).

### 5.1. OpenID for Verifiable Presentations via Redirects

The following requirements apply to OpenID4VP via redirects, unless
specified otherwise:

- As a way to invoke the Wallet, the custom
  URL scheme `haip-vp://` MAY be supported by the Wallet and the
  Verifier. Implementations MAY support other ways to invoke the Wallets
  as agreed upon by trust frameworks/ecosystems/jurisdictions, including
  but not limited to using other custom URL schemes or claimed "https"
  scheme URIs.
- Signed Authorization Requests MUST be used
  by utilizing JWT-Secured Authorization Request (JAR)
  [RFC9101] with the
  `request_uri`
  parameter.
- Response encryption MUST be used by
  utilizing response mode `direct_post.jwt`, as defined in Section 8.3
  of [OIDF.OID4VP].
  Security Considerations in Section 14.3 of
  [OIDF.OID4VP] MUST be
  applied.

### 5.2. OpenID for Verifiable Presentations via W3C Digital Credentials API

The following requirements apply to OpenID4VP via the W3C Digital
Credentials API, unless specified
otherwise:

- Wallet Invocation is done via the W3C
  Digital Credentials API or an equivalent platform API. Any other
  mechanism, including Custom URL schemes, MUST NOT be
  used.
- The Response Mode MUST be
  `dc_api.jwt`.
- The Verifier and Wallet MUST use Annex A in
  [OIDF.OID4VP] that
  defines how to use OpenID4VP over the W3C Digital Credentials
  API.
- The Wallet MUST support both signed and
  unsigned requests as defined in Annex A.3.1 and A.3.2 of
  [OIDF.OID4VP]. The
  Verifier MAY support signed requests, unsigned requests, or
  both.

### 5.3. Requirements specific to Credential Formats

#### 5.3.1. ISO Mobile Documents or mdocs (ISO/IEC 18013 and ISO/IEC 23220 series)

The following requirements apply to all OpenID4VP flows when the mdoc
Credential Format is
used:

- The Credential Format identifier MUST be
  `mso_mdoc`.
- The ISO mdoc Credential Format specific
  DCQL parameter, `intent_to_retain` defined in Annex B.3.1 of
  [OIDF.OID4VP] MUST be
  present.
- When multiple ISO mdocs are being
  returned, each ISO mdoc MUST be returned in a separate
  `DeviceResponse` (as defined in 8.3.2.1.2.2 of
  [ISO.18013-5]), each
  matching to a respective DCQL query. Therefore, the resulting
  `vp_token` contains multiple `DeviceResponse`
  instances.

#### 5.3.2. IETF SD-JWT VC

The following requirements apply to all OpenID4VP flows when the SD-JWT
VC Credential Format is
used:

- The Credential Format identifier MUST be
  `dc+sd-jwt`.

## 6. OpenID4VC Credential Format Profiles

Credential Format Profiles are defined as
follows:

  IETF SD-JWT VCs (as specified in [I-D.ietf-oauth-sd-jwt-vc]), subject to the
  additional requirements defined in
  Section 6.1:

  - [OIDF.OID4VCI] -
    Annex A.3
  - [OIDF.OID4VP] -
    Annex B.3

  ISO mdocs:

  - [OIDF.OID4VCI] -
    Annex A.2
  - [OIDF.OID4VP] -
    Annex B.2

  

### 6.1. IETF SD-JWT VC Profile

This profile defines the following additional requirements for IETF
SD-JWT VCs as defined in [I-D.ietf-oauth-sd-jwt-vc].

- Compact serialization MUST be supported as
  defined in [I-D.ietf-oauth-selective-disclosure-jwt]. JSON
  serialization MAY be
  supported.
- It is at the discretion of the Issuer
  whether to use `exp` claim and/or a `status` claim to express the
  validity period of an SD-JWT VC. The Wallet and the Verifier MUST
  support both
  mechanisms.
- The `iss` claim, if present, MUST be an
  HTTPS URL.
- The `cnf` claim
  [RFC7800] MUST conform to
  the definition given in [I-D.ietf-oauth-sd-jwt-vc]. Implementations
  conforming to this profile MUST include the JSON Web Key
  [RFC7517] in the `jwk`
  member if the corresponding Credential Configuration requires
  cryptographic holder
  binding.
- The public key used to validate the
  signature on the Status List Token MUST be included in the `x5c` JOSE
  header of the Token. The X.509 certificate of the trust anchor MUST
  NOT be included in the `x5c` JOSE header of the Status List Token. The
  X.509 certificate signing the request MUST NOT be
  self-signed.

Note: Re-using the same Credential across Verifiers, or re-using the
same JWK value across multiple Credentials gives colluding Verifiers a
mechanism to correlate the User. There are currently two known ways to
address this with SD-JWT VCs. First is to issue multiple instances of
the same Credentials with different JWK values, so that if each instance
of the Credential is used at only one Verifier, it can be reused
multiple times. Another is to use each Credential only once (ephemeral
Credentials). It is RECOMMENDED to adopt one of these
mechanisms.

Note: If there is a requirement to communicate information about the
verification status and identity assurance data of the claims about the
subject, the syntax defined by
[OIDF.ekyc-ida] SHOULD
be used. It is up to each jurisdiction and ecosystem, whether to require
it to the implementers of this
profile.

Note: If there is a requirement to provide the Subject's identifier
assigned and maintained by the Issuer, the `sub` claim MAY be used.
There is no requirement for a binding to exist between the `sub` and
`cnf` claims. See the Implementation Considerations section in
[I-D.ietf-oauth-sd-jwt-vc].

Note: In some Credential Types, it is not desirable to include an
expiration date (e.g., diploma attestation). Therefore, this profile
leaves its inclusion to the Issuer, or the body defining the respective
Credential Type.

#### 6.1.1. Issuer identification and key resolution to validate an issued Credential

This profile mandates the support for X.509 certificate-based key
resolution to validate the issuer signature of an SD-JWT VC. This MUST
be supported by all entities (Issuer, Wallet, Verifier). The SD-JWT VC
MUST contain the credential issuer's signing certificate along with a
trust chain in the `x5c` JOSE header parameter as described in section
3.5 of [I-D.ietf-oauth-sd-jwt-vc]. The X.509 certificate
of the trust anchor MUST NOT be included in the `x5c` JOSE header of the
SD-JWT VC. The X.509 certificate signing the request MUST NOT be
self-signed.

##### 6.1.1.1. Cryptographic Holder Binding between VC and VP

- If the credential has cryptographic
  holder binding, a KB-JWT, as defined in
  [I-D.ietf-oauth-sd-jwt-vc], MUST always be
  present when presenting an SD-JWT
  VC.

## 7. Crypto Suites

Cryptography is required by the following
operations:

- to sign and validate the signature on the
  Wallet Attestation and its proof of
  possession
- to sign and validate the Issuer's signature
  on the Verifiable
  Credential
- to sign and validate the Holder's signature
  on the Verifiable
  Presentation
- to sign and validate the Verifier's signature
  on the Presentation
  Request

Issuers, Holders, and Verifiers MUST support P-256 (secp256r1) as a key
type with the ES256 JWT algorithm
[RFC7518] for the creation
and verification of the above
signatures.

When using this profile alongside other crypto suites, each entity
SHOULD make it explicit in its metadata which other algorithms and key
types are supported for the cryptographic
operations.

## 8. Hash Algorithms

The hash algorithm SHA-256 MUST be supported by all the entities to
generate and validate the digests in the IETF SD-JWT VC and ISO
mdoc.

When using this profile alongside other hash algorithms, each entity
SHOULD make it explicit in its metadata which other algorithms are
supported.

## 9. Implementations Considerations

### 9.1. Validity Period of the Signature and the Claim Values

`iat` and `exp` JWT claims express both the validity period of both the
signature and the claims about the subject, unless there is a separate
claim used to express the validity of the
claims.

### 9.2. Interoperable Key Attestations

Wallet implementations using the key attestation format specified in
Annex D of
[OIDF.OID4VCI] might
need to utilize a transformation (backend) service to create such
attestations based on data as provided in other formats by the
respective platform or secure key management module. The dependency on
such a service might impact the availability of the wallet app as well
as the performance of the issuance process. This could be mitigated by
creating keys and obtaining the respective key attestations in
advance.

## 10. Security Considerations

The security considerations in
[OIDF.OID4VCI] and
[OIDF.OID4VP]
apply.

## 11. Privacy Considerations

### 11.1. Interoperable Key Attestations

Wallet implementations using the key attestation format specified in
Annex D of
[OIDF.OID4VCI] might
need to utilize a transformation (backend) service to create such
attestations based on data as provided in other formats by the
respective platform or secure key management module. Such a backend
service MUST be designed considering the privacy of its users. For
example, the service could be stateless and just perform the
transformation of the attestation data without binding the process in
any way to a unique user
identifier.

## 12. Normative References

[I-D.ietf-oauth-sd-jwt-vc]  
Terbu, O., Fett,
D., and B. Campbell,
"SD-JWT-based Verifiable Credentials (SD-JWT
VC)", Work in Progress,
Internet-Draft,
draft-ietf-oauth-sd-jwt-vc-11, 15 September 2025,
<<https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-11>\>.

[I-D.ietf-oauth-selective-disclosure-jwt]  
Fett, D., Yasuda,
K., and B. Campbell,
"Selective Disclosure for JWTs (SD-JWT)",
Work in Progress,
Internet-Draft,
draft-ietf-oauth-selective-disclosure-jwt-22, 29 May 2025,
<<https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-22>\>.

[ISO.18013-5]  
ISO/IEC JTC 1/SC 17 Cards and security devices
for personal identification, "ISO/IEC
18013-5:2021 Personal identification -- ISO-compliant driving license --
Part 5: Mobile driving license (mDL) application", 2021,
<<https://www.iso.org/standard/69084.html>\>.

[OIDF.OID4VCI]  
Lodderstedt, T.,
Yasuda, K.,
Looker, T., and
P. Bastian,
"OpenID for Verifiable Credential Issuance
1.0", 16 September 2025,
<<https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>\>.

[OIDF.OID4VP]  
Terbu, O.,
Lodderstedt, T.,
Yasuda, K., Fett,
D., and J. Heenan,
"OpenID for Verifiable Presentations 1.0",
9 July 2025,
<<https://openid.net/specs/openid-4-verifiable-presentations-1_0.html>\>.

[OIDF.ekyc-ida]  
yes, Fett,
D., Haine, M.,
Pulido, A.,
Lehmann, K., and
K. Koiwai, "OpenID
Connect for Identity Assurance 1.0", 19 August 2022,
<<https://openid.net/specs/openid-connect-4-identity-assurance-1_0-ID4.html>\>.

[RFC7515]  
Jones, M.,
Bradley, J., and
N. Sakimura, "JSON
Web Signature (JWS)", RFC 7515,
DOI 10.17487/RFC7515, May 2015,
<<https://www.rfc-editor.org/info/rfc7515>\>.

[RFC7516]  
Jones, M. and J.
Hildebrand, "JSON Web Encryption
(JWE)", RFC 7516,
DOI 10.17487/RFC7516, May 2015,
<<https://www.rfc-editor.org/info/rfc7516>\>.

[RFC7517]  
Jones, M., "JSON
Web Key (JWK)", RFC 7517,
DOI 10.17487/RFC7517, May 2015,
<<https://www.rfc-editor.org/info/rfc7517>\>.

[RFC7518]  
Jones, M., "JSON
Web Algorithms (JWA)", RFC 7518,
DOI 10.17487/RFC7518, May 2015,
<<https://www.rfc-editor.org/info/rfc7518>\>.

[RFC7636]  
Sakimura, N., Ed.,
Bradley, J., and
N. Agarwal, "Proof
Key for Code Exchange by OAuth Public Clients",
RFC 7636, DOI
10.17487/RFC7636, September 2015,
<<https://www.rfc-editor.org/info/rfc7636>\>.

[RFC7800]  
Jones, M.,
Bradley, J., and
H. Tschofenig,
"Proof-of-Possession Key Semantics for JSON Web
Tokens (JWTs)", RFC 7800,
DOI 10.17487/RFC7800, April 2016,
<<https://www.rfc-editor.org/info/rfc7800>\>.

[RFC8414]  
Jones, M.,
Sakimura, N., and
J. Bradley, "OAuth
2.0 Authorization Server Metadata", RFC
8414, DOI 10.17487/RFC8414, June
2018, <<https://www.rfc-editor.org/info/rfc8414>\>.

[RFC9101]  
Sakimura, N.,
Bradley, J., and
M. Jones, "The
OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request
(JAR)", RFC 9101,
DOI 10.17487/RFC9101, August 2021,
<<https://www.rfc-editor.org/info/rfc9101>\>.

[RFC9126]  
Lodderstedt, T.,
Campbell, B.,
Sakimura, N.,
Tonge, D., and F.
Skokan, "OAuth 2.0 Pushed Authorization
Requests", RFC 9126,
DOI 10.17487/RFC9126, September 2021,
<<https://www.rfc-editor.org/info/rfc9126>\>.

[RFC9449]  
Fett, D.,
Campbell, B.,
Bradley, J.,
Lodderstedt, T.,
Jones, M., and D.
Waite, "OAuth 2.0 Demonstrating Proof of
Possession (DPoP)", RFC 9449,
DOI 10.17487/RFC9449, September 2023,
<<https://www.rfc-editor.org/info/rfc9449>\>.

## 13. Informative References

[ETSI.TL]  
European Telecommunications Standards Institute
(ETSI), "ETSI TS 119 612 V2.4.1 Electronic
Signatures and Trust Infrastructures (ESI); Trusted Lists",
August 2025,
<<https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf>\>.

[EU.ARF]  
European Commission,
"European Digital Identity Wallet Architecture
and Reference Framework", 2025,
<<https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/latest/>\>.

[IANA.URI.Schemes]  
IANA, "Uniform
Resource Identifier (URI) Schemes",
<<https://www.iana.org/assignments/uri-schemes>\>.

[eIDAS2.0]  
European Union,
"REGULATION (EU) 2024/1183 OF THE EUROPEAN
PARLIAMENT AND OF THE COUNCIL of 11 April 2024 amending Regulation (EU)
No 910/2014 as regards establishing the European Digital Identity
Framework", 2024,
<<https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202401183>\>.

[w3c.digital_credentials_api]  
Caceres, M.,
Cappalli, T., and
M. A. Yosef,
"Digital Credentials API", 17 September
2025, <<https://www.w3.org/TR/digital-credentials/>\>.

## Appendix A. IANA Considerations

### A.1. Uniform Resource Identifier (URI) Schemes Registry

This specification registers the following URI schemes in the IANA
"Uniform Resource Identifier (URI) Schemes" registry
[IANA.URI.Schemes].

#### A.1.1. haip-vci

- URI Scheme:
  haip-vci
- Description: Custom scheme used for
  invoking wallets that implement the OIDF HAIP profile to offer a
  Credential
- Status:
  Permanent
- Well-Known URI Support:

- Change Controller: OpenID Foundation
  Digital Credentials Protocols Working Group -
  openid-specs-digital-credentials-protocols@lists.openid.net
- Reference:
  Section 4.2
  of this
  specification

#### A.1.2. haip-vp

- URI Scheme:
  haip-vp
- Description: Custom scheme used for
  invoking wallets that implement the OIDF HAIP profile to request the
  presentation of
  Credentials
- Status:
  Permanent
- Well-Known URI Support:

- Change Controller: OpenID Foundation
  Digital Credentials Protocols Working Group -
  openid-specs-digital-credentials-protocols@lists.openid.net
- Reference:
  Section 5.1
  of this
  specification

## Appendix B. Acknowledgements

We would like to thank Paul Bastian, Christian Bormann, Brian Campbell,
Stefan Charsley, Andrii Deinega, Timo Glastra, Martijn Haring, Lukasz
Jaromin, Mike Jones, Philipp Lehwalder, Oliver Terbu, Daniel Fett,
Giuseppe De Marco, Joel Posti, and Andreea Prian for their valuable
feedback and contributions to this
specification.

## Appendix C. Notices

Copyright (c) 2025 The OpenID
Foundation.

The OpenID Foundation (OIDF) grants to any Contributor, developer,
implementer, or other interested party a non-exclusive, royalty free,
worldwide copyright license to reproduce, prepare derivative works from,
distribute, perform and display, this Implementers Draft, Final
Specification, or Final Specification Incorporating Errata Corrections
solely for the purposes of (i) developing specifications, and (ii)
implementing Implementers Drafts, Final Specifications, and Final
Specification Incorporating Errata Corrections based on such documents,
provided that attribution be made to the OIDF as the source of the
material, but that such attribution does not indicate an endorsement by
the OIDF.

The technology described in this specification was made available from
contributions from various sources, including members of the OpenID
Foundation and others. Although the OpenID Foundation has taken steps to
help ensure that the technology is available for distribution, it takes
no position regarding the validity or scope of any intellectual property
or other rights that might be claimed to pertain to the implementation
or use of the technology described in this specification or the extent
to which any license under such rights might or might not be available;
neither does it represent that it has made any independent effort to
identify any such rights. The OpenID Foundation and the contributors to
this specification make no (and hereby expressly disclaim any)
warranties (express, implied, or otherwise), including implied
warranties of merchantability, non-infringement, fitness for a
particular purpose, or title, related to this specification, and the
entire risk as to implementing this specification is assumed by the
implementer. The OpenID Intellectual Property Rights policy (found at
openid.net) requires contributors to offer a patent promise not to
assert certain patent claims against other contributors and against
implementers. OpenID invites any interested party to bring to its
attention any copyrights, patents, patent applications, or other
proprietary rights that may cover technology that may be required to
practice this
specification.

## Appendix D. Document History

[[ To be removed from the final specification
]]

-04

- update etsi tl and DC API
  references
- update VP & VCI references to be to 1.0
  Final
- add separate custom url schemes for issuance
  and presentation to replace the haip://
  scheme
- support for haip-vp:// and haip-vci://
  custom url schemes is now an ecosystem
  decision
- allow ecosystems the option to use key
  attestations other than those defined in Annex D of
  [OIDF.OID4VCI] in some
  cases
- clarify nonce endpoint must be present when
  cryptographic_binding_methods_supported
  is
- remove various requirements around claims
  present in SD-JWT VC as upstream spec covers
  them
- require ephemeral encryption keys in
  VP
- add note that lower assurance credentials
  can also be conveyed using this
  profile
- add note on verifier certificate
  profiling
- added support for credentials without
  cryptographic holder
  binding
- mandate support for aki trusted_authorities
  method
- remove presentation exchange reference
  since it was removed in
  openid4vp
- Authorization Server and Credential Issuer
  must support
  metadata
- x509_san_dns & verifier_attestations client
  id prefixes are no longer permitted, x509_hash must be
  used
- x.509 certificates are now the mandatory
  mechanism for SD-JWT VC issuer key
  resolution
- `x5c` header in Status List Token must be
  present
- clarify that Wallet Attestations must not
  contain linkable
  information.
- add signed Issuer
  Metadata
- require key attestation for
  OpenID4VCI
- clarify text regarding mdoc specific
  parameters
- add small note that establishing trust in
  and retrieving root certs is out
  scope
- update wording from Client Identifier
  Scheme to Client Identifier Prefix
  #182
- fix reference to ARF
  #177
- remove old link in section 8 & clarify a
  note on claim based binding in OpenID4VP in HAIP
  #183
- Clarify clause 4.1 statement
  #169
- add a list of all specifications being
  profiled #145
- say something about DPoP
  nonces
- refactor to separate generic and SD-JWT
  clauses
- add support for ISO mdoc
  isssuance
- add support for ISO mdoc when using
  redirect-based
  OID4VP
- remove requirement to support batch
  endpoint (it was removed from
  OID4VP)
- remove SIOPv2 (webauthn is now the
  recommended way to handle pseudonymous
  login)
- prohibit self-signed certificates for
  signing with
  `x509_hash`
- trust anchor certificates must not be
  included in `x5c`
  headers

-03

- Add initial security considerations
  section
- Update notices section to match latest OIDF
  process document

-02

- Mandate DCQL instead of presentation
  exchange
- Refactor HAIP and add details for mdoc
  profile over DC
  API
- Add specific requirements for response
  encryption
- Add SessionTranscript
  requirements
- Update OID4VP reference to draft
  24

-01

- Remove the Wallet Attestation Schema and
  point to OpenID4VCI
  instead
- Rename specification to enable non-SD-JWT
  credential formats to be
  included
- Require encrypted
  responses
- Remove reference to `client_id_scheme`
  parameter that no longer exists in
  OpenID4VP
- Refresh tokens are now
  optional

-00

- initial
  revision

## Authors' Addresses

Kristina Yasuda

SPRIND

Email: <kristina.yasuda@sprind.org>

Torsten Lodderstedt

SPRIND

Email: <torsten@lodderstedt.net>


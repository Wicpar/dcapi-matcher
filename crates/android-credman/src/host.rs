//! Version-aware high-level host facade for Credential Manager matcher output.
//!
//! # Purpose
//! This module exposes a single borrowed-data API over the raw ABI:
//! - `default_credman()` returns a process-wide `&dyn Credman`.
//! - Version-specific capabilities are discovered through `as_v2()/as_v3()/as_v4()`.
//! - Request structs borrow caller data to minimize copies.
//!
//! # Typical Flow
//! 1. Build borrowed request structs (`StringIdEntryRequest`, `PaymentEntryToSetV2Request`, ...).
//! 2. Call base APIs on `&dyn Credman`.
//! 3. Probe for newer APIs when needed.
//!
//! ```rust
//! use android_credman::{default_credman, EntrySetRequest, StringIdEntryRequest, EntryToSetRequest};
//!
//! let host = default_credman();
//! host.add_string_id_entry(&StringIdEntryRequest {
//!     cred_id: "pid-1",
//!     icon: None,
//!     title: "EU PID",
//!     subtitle: Some("Issuer Example"),
//!     disclaimer: None,
//!     warning: None,
//! });
//!
//! if let Some(v2) = host.as_v2() {
//!     v2.add_entry_set(&EntrySetRequest { set_id: "set:pid", set_length: 1 });
//!     v2.add_entry_to_set(&EntryToSetRequest {
//!         cred_id: "pid-1",
//!         icon: None,
//!         title: "EU PID",
//!         subtitle: None,
//!         disclaimer: None,
//!         warning: None,
//!         metadata: Some("{\"dcql_cred_id\":\"pid\"}"),
//!         set_id: "set:pid",
//!         set_index: 0,
//!     });
//! }
//! ```

use crate::abi;

/// Borrowed request for `AddStringIdEntry`.
///
/// # Purpose
/// Describes one standalone credential row in the system picker.
///
/// # Zero-Copy
/// All fields borrow caller-owned data. The only unavoidable copy is temporary
/// NUL-terminated string conversion at the FFI boundary.
#[derive(Debug, Clone, Copy)]
pub struct StringIdEntryRequest<'a> {
    /// Identifier returned by the host when this row is selected.
    pub cred_id: &'a str,
    /// Optional icon bytes (PNG/WEBP/etc) displayed by the host.
    pub icon: Option<&'a [u8]>,
    /// Primary text shown on the row.
    pub title: &'a str,
    /// Optional secondary text shown under `title`.
    pub subtitle: Option<&'a str>,
    /// Optional legal/disclaimer text.
    pub disclaimer: Option<&'a str>,
    /// Optional warning text highlighted by the host.
    pub warning: Option<&'a str>,
}

/// Borrowed request for `AddFieldForStringIdEntry`.
#[derive(Debug, Clone, Copy)]
pub struct FieldForStringIdEntryRequest<'a> {
    /// Entry identifier that previously appeared in `add_string_id_entry`.
    pub cred_id: &'a str,
    /// User-facing field label.
    pub field_display_name: &'a str,
    /// Optional value (some hosts allow value-less fields).
    pub field_display_value: Option<&'a str>,
}

/// Borrowed request for `AddEntrySet`.
#[derive(Debug, Clone, Copy)]
pub struct EntrySetRequest<'a> {
    /// Stable set identifier used by subsequent set APIs.
    pub set_id: &'a str,
    /// Number of set slots (not alternatives) expected by the host.
    pub set_length: i32,
}

/// Borrowed request for `AddEntryToSet`.
#[derive(Debug, Clone, Copy)]
pub struct EntryToSetRequest<'a> {
    /// Identifier returned by the host when this set option is selected.
    pub cred_id: &'a str,
    /// Optional icon bytes for the entry.
    pub icon: Option<&'a [u8]>,
    /// Primary row text.
    pub title: &'a str,
    /// Optional secondary row text.
    pub subtitle: Option<&'a str>,
    /// Optional disclaimer text.
    pub disclaimer: Option<&'a str>,
    /// Optional warning text.
    pub warning: Option<&'a str>,
    /// Optional opaque callback payload.
    pub metadata: Option<&'a str>,
    /// Target set identifier.
    pub set_id: &'a str,
    /// 0-based slot index within `set_id`.
    pub set_index: i32,
}

/// Borrowed request for `AddFieldToEntrySet`.
#[derive(Debug, Clone, Copy)]
pub struct FieldToEntrySetRequest<'a> {
    /// Entry identifier previously emitted for this set slot.
    pub cred_id: &'a str,
    /// User-facing field label.
    pub field_display_name: &'a str,
    /// Optional field value.
    pub field_display_value: Option<&'a str>,
    /// Target set identifier.
    pub set_id: &'a str,
    /// 0-based slot index for the entry.
    pub set_index: i32,
}

/// Borrowed request for `AddPaymentEntry`.
#[derive(Debug, Clone, Copy)]
pub struct PaymentEntryRequest<'a> {
    /// Identifier returned by the host when selected.
    pub cred_id: &'a str,
    /// Merchant/payee label.
    pub merchant_name: &'a str,
    /// Optional payment method title.
    pub payment_method_name: Option<&'a str>,
    /// Optional payment method subtitle.
    pub payment_method_subtitle: Option<&'a str>,
    /// Optional payment method icon bytes.
    pub payment_method_icon: Option<&'a [u8]>,
    /// Formatted transaction amount shown to the user.
    pub transaction_amount: &'a str,
    /// Optional bank icon bytes.
    pub bank_icon: Option<&'a [u8]>,
    /// Optional payment provider icon bytes.
    pub payment_provider_icon: Option<&'a [u8]>,
}

/// Borrowed request for `AddPaymentEntryToSet` (v2).
#[derive(Debug, Clone, Copy)]
pub struct PaymentEntryToSetRequest<'a> {
    /// Identifier returned by the host when selected.
    pub cred_id: &'a str,
    /// Merchant/payee label.
    pub merchant_name: &'a str,
    /// Optional payment method title.
    pub payment_method_name: Option<&'a str>,
    /// Optional payment method subtitle.
    pub payment_method_subtitle: Option<&'a str>,
    /// Optional payment method icon bytes.
    pub payment_method_icon: Option<&'a [u8]>,
    /// Formatted transaction amount shown to the user.
    pub transaction_amount: &'a str,
    /// Optional bank icon bytes.
    pub bank_icon: Option<&'a [u8]>,
    /// Optional payment provider icon bytes.
    pub payment_provider_icon: Option<&'a [u8]>,
    /// Optional opaque callback payload.
    pub metadata: Option<&'a str>,
    /// Target set identifier.
    pub set_id: &'a str,
    /// 0-based slot index within `set_id`.
    pub set_index: i32,
}

/// Borrowed request for `AddPaymentEntryToSetV2` (v3+).
#[derive(Debug, Clone, Copy)]
pub struct PaymentEntryToSetV2Request<'a> {
    /// Identifier returned by the host when selected.
    pub cred_id: &'a str,
    /// Merchant/payee label.
    pub merchant_name: &'a str,
    /// Optional payment method title.
    pub payment_method_name: Option<&'a str>,
    /// Optional payment method subtitle.
    pub payment_method_subtitle: Option<&'a str>,
    /// Optional payment method icon bytes.
    pub payment_method_icon: Option<&'a [u8]>,
    /// Formatted transaction amount shown to the user.
    pub transaction_amount: &'a str,
    /// Optional bank icon bytes.
    pub bank_icon: Option<&'a [u8]>,
    /// Optional payment provider icon bytes.
    pub payment_provider_icon: Option<&'a [u8]>,
    /// Optional host-specific extra context (v3+).
    pub additional_info: Option<&'a str>,
    /// Optional opaque callback payload.
    pub metadata: Option<&'a str>,
    /// Target set identifier.
    pub set_id: &'a str,
    /// 0-based slot index within `set_id`.
    pub set_index: i32,
}

/// Borrowed request for `AddInlineIssuanceEntry`.
#[derive(Debug, Clone, Copy)]
pub struct InlineIssuanceEntryRequest<'a> {
    /// Identifier returned by the host when selected.
    pub cred_id: &'a str,
    /// Optional icon bytes for issuance row.
    pub icon: Option<&'a [u8]>,
    /// Primary text displayed for issuance offer.
    pub title: &'a str,
    /// Optional secondary text for issuance offer.
    pub subtitle: Option<&'a str>,
}

/// Borrowed request for `SetAdditionalDisclaimerAndUrlForVerificationEntry`.
#[derive(Debug, Clone, Copy)]
pub struct VerificationEntryUpdateRequest<'a> {
    /// Identifier of an already-added verification entry.
    pub cred_id: &'a str,
    /// Optional additional disclaimer.
    pub secondary_disclaimer: Option<&'a str>,
    /// Optional display text for URL action.
    pub url_display_text: Option<&'a str>,
    /// Optional URL value.
    pub url_value: Option<&'a str>,
}

/// Borrowed request for `SelfDeclarePackageInfo` (v4+).
#[derive(Debug, Clone, Copy)]
pub struct PackageInfoRequest<'a> {
    /// Human-readable package/app name.
    pub package_display_name: &'a str,
    /// Optional package icon bytes.
    pub package_icon: Option<&'a [u8]>,
}

/// Base Credman host contract.
///
/// # Purpose
/// Provide a single runtime-selected entry-point (`default_credman`) while still
/// allowing version-gated access through extension traits (`CredmanV2+`).
pub trait Credman: Sync {
    /// Host-reported version from `GetWasmVersion`.
    fn wasm_version(&self) -> u32;

    /// Adds a standalone identity-style entry.
    fn add_string_id_entry(&self, req: &StringIdEntryRequest<'_>) {
        abi::add_string_id_entry(req);
    }

    /// Adds a field to a standalone identity-style entry.
    fn add_field_for_string_id_entry(&self, req: &FieldForStringIdEntryRequest<'_>) {
        abi::add_field_for_string_id_entry_opt(req);
    }

    /// Adds a standalone payment entry.
    fn add_payment_entry(&self, req: &PaymentEntryRequest<'_>) {
        abi::add_payment_entry(req);
    }

    /// Adds a standalone inline issuance entry.
    fn add_inline_issuance_entry(&self, req: &InlineIssuanceEntryRequest<'_>) {
        abi::add_inline_issuance_entry(req);
    }

    /// Updates verification-disclaimer metadata for a previously added entry.
    fn set_additional_disclaimer_and_url_for_verification_entry(
        &self,
        req: &VerificationEntryUpdateRequest<'_>,
    ) {
        abi::set_additional_disclaimer_and_url(req);
    }

    /// Returns `Some` when set APIs are supported (`credman_v2`).
    fn as_v2(&self) -> Option<&dyn CredmanV2> {
        None
    }

    /// Returns `Some` when extended payment set APIs are supported (`v3`).
    fn as_v3(&self) -> Option<&dyn CredmanV3> {
        None
    }

    /// Returns `Some` when system-only package declaration APIs are supported (`v4`).
    fn as_v4(&self) -> Option<&dyn CredmanV4> {
        None
    }
}

/// Version 2 host extension (`credman_v2`).
pub trait CredmanV2: Credman {
    /// Creates a set container.
    fn add_entry_set(&self, req: &EntrySetRequest<'_>) {
        abi::add_entry_set(req);
    }

    /// Adds an identity-style entry into a set slot.
    fn add_entry_to_set(&self, req: &EntryToSetRequest<'_>) {
        abi::add_entry_to_set(req);
    }

    /// Adds a field to an entry inside a set slot.
    fn add_field_to_entry_set(&self, req: &FieldToEntrySetRequest<'_>) {
        abi::add_field_to_entry_set_opt(req);
    }

    /// Adds a payment entry into a set slot (v2 payload shape).
    fn add_payment_entry_to_set(&self, req: &PaymentEntryToSetRequest<'_>) {
        abi::add_payment_entry_to_set(req);
    }
}

/// Version 3 host extension (`AddPaymentEntryToSetV2`).
pub trait CredmanV3: CredmanV2 {
    /// Adds a payment entry into a set slot (v3 payload with `additional_info`).
    fn add_payment_entry_to_set_v2(&self, req: &PaymentEntryToSetV2Request<'_>) {
        abi::add_payment_entry_to_set_v2(req);
    }
}

/// Version 4 host extension (`credman_v4`).
pub trait CredmanV4: CredmanV3 {
    /// Declares package info for privileged/system hosts.
    fn self_declare_package_info(&self, req: &PackageInfoRequest<'_>) {
        abi::self_declare_package_info(req);
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct HostCredmanV1;

#[derive(Debug, Clone, Copy, Default)]
pub struct HostCredmanV2;

#[derive(Debug, Clone, Copy, Default)]
pub struct HostCredmanV3;

#[derive(Debug, Clone, Copy, Default)]
pub struct HostCredmanV4;

static HOST_V1: HostCredmanV1 = HostCredmanV1;
static HOST_V2: HostCredmanV2 = HostCredmanV2;
static HOST_V3: HostCredmanV3 = HostCredmanV3;
static HOST_V4: HostCredmanV4 = HostCredmanV4;

/// Returns the process-wide host facade selected by `GetWasmVersion`.
///
/// # Usage
/// 1. Call `default_credman()` once.
/// 2. Use base methods for v1-safe APIs.
/// 3. Ask for `as_v2` / `as_v3` / `as_v4` before calling newer APIs.
///
/// The returned trait object is backed by a zero-sized singleton implementation.
pub fn default_credman() -> &'static dyn Credman {
    match abi::get_wasm_version() {
        0 | 1 => &HOST_V1,
        2 => &HOST_V2,
        3 => &HOST_V3,
        _ => &HOST_V4,
    }
}

/// Convenience probe for set-capable hosts.
pub fn default_credman_v2() -> Option<&'static dyn CredmanV2> {
    default_credman().as_v2()
}

/// Convenience probe for v3 payment-set API.
pub fn default_credman_v3() -> Option<&'static dyn CredmanV3> {
    default_credman().as_v3()
}

/// Convenience probe for v4 system APIs.
pub fn default_credman_v4() -> Option<&'static dyn CredmanV4> {
    default_credman().as_v4()
}

impl Credman for HostCredmanV1 {
    fn wasm_version(&self) -> u32 {
        abi::get_wasm_version()
    }
}

impl Credman for HostCredmanV2 {
    fn wasm_version(&self) -> u32 {
        abi::get_wasm_version()
    }

    fn as_v2(&self) -> Option<&dyn CredmanV2> {
        Some(self)
    }
}

impl CredmanV2 for HostCredmanV2 {}

impl Credman for HostCredmanV3 {
    fn wasm_version(&self) -> u32 {
        abi::get_wasm_version()
    }

    fn as_v2(&self) -> Option<&dyn CredmanV2> {
        Some(self)
    }

    fn as_v3(&self) -> Option<&dyn CredmanV3> {
        Some(self)
    }
}

impl CredmanV2 for HostCredmanV3 {}
impl CredmanV3 for HostCredmanV3 {}

impl Credman for HostCredmanV4 {
    fn wasm_version(&self) -> u32 {
        abi::get_wasm_version()
    }

    fn as_v2(&self) -> Option<&dyn CredmanV2> {
        Some(self)
    }

    fn as_v3(&self) -> Option<&dyn CredmanV3> {
        Some(self)
    }

    fn as_v4(&self) -> Option<&dyn CredmanV4> {
        Some(self)
    }
}

impl CredmanV2 for HostCredmanV4 {}
impl CredmanV3 for HostCredmanV4 {}
impl CredmanV4 for HostCredmanV4 {}

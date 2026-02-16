use android_credman::{
    CredentialEntry, CredentialSet, CredentialSlot, Credman, CredmanV2, CredmanApplyExt,
    EntrySetRequest, EntryToSetRequest, FieldForStringIdEntryRequest, FieldToEntrySetRequest,
    MatcherResponse, MatcherResult, PaymentEntry, PaymentEntryRequest, PaymentEntryToSetRequest,
    PaymentEntryToSetV2Request, StringIdEntry, default_credman,
};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

/// Owned matcher response that can be converted to Credman output.
#[derive(Debug, Clone, Default)]
pub struct ResolvedMatcherResponse {
    /// Ordered top-level result list.
    pub results: Vec<ResolvedMatcherResult>,
}

impl ResolvedMatcherResponse {
    /// Creates an empty response.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a top-level result.
    pub fn add_result(mut self, result: ResolvedMatcherResult) -> Self {
        self.results.push(result);
        self
    }

    /// Adds a single credential entry.
    pub fn add_single(self, entry: ResolvedCredentialEntry) -> Self {
        self.add_result(ResolvedMatcherResult::Single(Box::new(entry)))
    }

    /// Adds a credential set.
    pub fn add_set(self, set: ResolvedCredentialSet) -> Self {
        self.add_result(ResolvedMatcherResult::Set(Box::new(set)))
    }

    /// Builds a borrowed Credman response view.
    pub fn as_credman_response(&self) -> MatcherResponse<'_> {
        let mut out = MatcherResponse::new();
        for result in &self.results {
            out = out.add_result(result.as_credman_result());
        }
        out
    }

    /// Emits response entries to host Credman ABI.
    pub fn apply(&self) {
        let host = default_credman();
        if let Some(v2) = host.as_v2() {
            for result in &self.results {
                match result {
                    ResolvedMatcherResult::Single(entry) => {
                        apply_single_entry(host, entry);
                    }
                    ResolvedMatcherResult::Set(set) => {
                        apply_set_with_fields(host, v2, set);
                    }
                }
            }
            return;
        }

        for result in &self.results {
            match result {
                ResolvedMatcherResult::Single(entry) => apply_single_entry(host, entry),
                ResolvedMatcherResult::Set(set) => {
                    for slot in &set.slots {
                        for entry in &slot.alternatives {
                            apply_single_entry(host, entry);
                        }
                    }
                }
            }
        }
    }
}

/// One top-level resolved result.
#[derive(Debug, Clone)]
pub enum ResolvedMatcherResult {
    /// Standalone entry.
    Single(Box<ResolvedCredentialEntry>),
    /// Grouped credential set.
    Set(Box<ResolvedCredentialSet>),
}

impl ResolvedMatcherResult {
    fn as_credman_result(&self) -> MatcherResult<'_> {
        match self {
            Self::Single(entry) => MatcherResult::Single(entry.as_credman_entry()),
            Self::Set(set) => MatcherResult::Group(set.as_credman_set()),
        }
    }
}

/// One resolved credential set.
#[derive(Debug, Clone)]
pub struct ResolvedCredentialSet {
    /// Credman set identifier.
    pub set_id: String,
    /// Slots in display order.
    pub slots: Vec<ResolvedCredentialSlot>,
}

impl ResolvedCredentialSet {
    /// Creates an empty set.
    pub fn new(set_id: impl Into<String>) -> Self {
        Self {
            set_id: set_id.into(),
            slots: Vec::new(),
        }
    }

    /// Appends one slot.
    pub fn add_slot(mut self, slot: ResolvedCredentialSlot) -> Self {
        self.slots.push(slot);
        self
    }

    fn as_credman_set(&self) -> CredentialSet<'_> {
        let mut set = CredentialSet::new(self.set_id.as_str());
        for slot in &self.slots {
            let mut alternatives = slot.alternatives.iter();
            let Some(first) = alternatives.next() else {
                continue;
            };
            let mut cred_slot = CredentialSlot::new(first.as_credman_entry());
            for alt in alternatives {
                cred_slot = cred_slot.add_alternative(alt.as_credman_entry());
            }
            set = set.add_slot(cred_slot);
        }
        set
    }
}

fn apply_single_entry(host: &dyn Credman, entry: &ResolvedCredentialEntry) {
    if let Some(payment) = &entry.payment {
        host.add_payment_entry(&PaymentEntryRequest {
            cred_id: entry.credential_id.as_str(),
            merchant_name: payment.merchant_name.as_str(),
            payment_method_name: payment.payment_method_name.as_deref(),
            payment_method_subtitle: payment.payment_method_subtitle.as_deref(),
            payment_method_icon: payment.payment_method_icon.as_deref(),
            transaction_amount: payment.transaction_amount.as_str(),
            bank_icon: payment.bank_icon.as_deref(),
            payment_provider_icon: payment.payment_provider_icon.as_deref(),
        });
        for field in entry
            .transaction_fields
            .iter()
            .chain(entry.fields.iter())
        {
            host.add_field_for_string_id_entry(&FieldForStringIdEntryRequest {
                cred_id: entry.credential_id.as_str(),
                field_display_name: field.display_name.as_str(),
                field_display_value: Some(field.display_value.as_str()),
            });
        }
        return;
    }

    let mut string_entry = StringIdEntry::new(entry.credential_id.as_str(), entry.title.as_str());
    if let Some(icon) = &entry.icon {
        string_entry = string_entry.icon(icon.as_slice());
    }
    if let Some(subtitle) = &entry.subtitle {
        string_entry = string_entry.subtitle(subtitle.as_str());
    }
    if let Some(disclaimer) = &entry.disclaimer {
        string_entry = string_entry.disclaimer(disclaimer.as_str());
    }
    if let Some(warning) = &entry.warning {
        string_entry = string_entry.warning(warning.as_str());
    }
    for field in entry
        .transaction_fields
        .iter()
        .chain(entry.fields.iter())
    {
        string_entry = string_entry.add_field(field.display_name.as_str(), field.display_value.as_str());
    }
    string_entry.apply();
}

fn apply_set_with_fields(
    host: &dyn Credman,
    v2: &dyn CredmanV2,
    set: &ResolvedCredentialSet,
) {
    if set.slots.is_empty() {
        return;
    }
    v2.add_entry_set(&EntrySetRequest {
        set_id: set.set_id.as_str(),
        set_length: set.slots.len() as i32,
    });
    let v3 = host.as_v3();
    for (slot_index, slot) in set.slots.iter().enumerate() {
        for entry in &slot.alternatives {
            if let Some(payment) = &entry.payment {
                if let Some(v3) = v3 {
                    v3.add_payment_entry_to_set_v2(&PaymentEntryToSetV2Request {
                        cred_id: entry.credential_id.as_str(),
                        merchant_name: payment.merchant_name.as_str(),
                        payment_method_name: payment.payment_method_name.as_deref(),
                        payment_method_subtitle: payment.payment_method_subtitle.as_deref(),
                        payment_method_icon: payment.payment_method_icon.as_deref(),
                        transaction_amount: payment.transaction_amount.as_str(),
                        bank_icon: payment.bank_icon.as_deref(),
                        payment_provider_icon: payment.payment_provider_icon.as_deref(),
                        additional_info: payment.additional_info.as_deref(),
                        metadata: entry.metadata_json.as_deref(),
                        set_id: set.set_id.as_str(),
                        set_index: slot_index as i32,
                    });
                } else {
                    v2.add_payment_entry_to_set(&PaymentEntryToSetRequest {
                        cred_id: entry.credential_id.as_str(),
                        merchant_name: payment.merchant_name.as_str(),
                        payment_method_name: payment.payment_method_name.as_deref(),
                        payment_method_subtitle: payment.payment_method_subtitle.as_deref(),
                        payment_method_icon: payment.payment_method_icon.as_deref(),
                        transaction_amount: payment.transaction_amount.as_str(),
                        bank_icon: payment.bank_icon.as_deref(),
                        payment_provider_icon: payment.payment_provider_icon.as_deref(),
                        metadata: entry.metadata_json.as_deref(),
                        set_id: set.set_id.as_str(),
                        set_index: slot_index as i32,
                    });
                }
            } else {
                v2.add_entry_to_set(&EntryToSetRequest {
                    cred_id: entry.credential_id.as_str(),
                    icon: entry.icon.as_deref(),
                    title: entry.title.as_str(),
                    subtitle: entry.subtitle.as_deref(),
                    disclaimer: entry.disclaimer.as_deref(),
                    warning: entry.warning.as_deref(),
                    metadata: entry.metadata_json.as_deref(),
                    set_id: set.set_id.as_str(),
                    set_index: slot_index as i32,
                });
            }

            for field in entry
                .transaction_fields
                .iter()
                .chain(entry.fields.iter())
            {
                v2.add_field_to_entry_set(&FieldToEntrySetRequest {
                    cred_id: entry.credential_id.as_str(),
                    field_display_name: field.display_name.as_str(),
                    field_display_value: Some(field.display_value.as_str()),
                    set_id: set.set_id.as_str(),
                    set_index: slot_index as i32,
                });
            }
        }
    }
}

/// One resolved credential slot with alternative entries.
#[derive(Debug, Clone, Default)]
pub struct ResolvedCredentialSlot {
    /// Optional logical identifier (for example, DCQL credential id).
    pub id: Option<String>,
    /// Whether this slot is required by request semantics.
    pub required: bool,
    /// Candidate credential entries for this slot.
    pub alternatives: Vec<ResolvedCredentialEntry>,
}

impl ResolvedCredentialSlot {
    /// Creates an empty slot.
    pub fn new(id: Option<String>, required: bool) -> Self {
        Self {
            id,
            required,
            alternatives: Vec::new(),
        }
    }

    /// Appends one alternative.
    pub fn add_alternative(mut self, entry: ResolvedCredentialEntry) -> Self {
        self.alternatives.push(entry);
        self
    }
}

/// One resolved credential entry.
#[derive(Debug, Clone)]
pub struct ResolvedCredentialEntry {
    /// Unique credential id returned to host when selected.
    pub credential_id: String,
    /// UI title.
    pub title: String,
    /// Optional icon bytes.
    pub icon: Option<Vec<u8>>,
    /// Optional subtitle.
    pub subtitle: Option<String>,
    /// Optional disclaimer.
    pub disclaimer: Option<String>,
    /// Optional warning.
    pub warning: Option<String>,
    /// Optional set-entry metadata JSON string.
    pub metadata_json: Option<String>,
    /// Optional transaction-data-first payment rendering configuration.
    ///
    /// When set, the credential is rendered as Credman `PaymentEntry`.
    /// In this mode claim fields are intentionally not rendered in the same entry,
    /// so claim and transaction-data display remain clearly separated.
    pub payment: Option<ResolvedPaymentPresentation>,
    /// Transaction-data display fields in order.
    pub transaction_fields: Vec<ResolvedField>,
    /// Display fields in order.
    pub fields: Vec<ResolvedField>,
}

impl ResolvedCredentialEntry {
    /// Creates a new entry with required fields.
    pub fn new(credential_id: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            credential_id: credential_id.into(),
            title: title.into(),
            icon: None,
            subtitle: None,
            disclaimer: None,
            warning: None,
            metadata_json: None,
            payment: None,
            transaction_fields: Vec::new(),
            fields: Vec::new(),
        }
    }

    fn as_credman_entry(&self) -> CredentialEntry<'_> {
        if let Some(payment) = &self.payment {
            let mut entry = PaymentEntry::new(
                self.credential_id.as_str(),
                payment.merchant_name.as_str(),
                payment.transaction_amount.as_str(),
            );
            if let Some(name) = &payment.payment_method_name {
                entry = entry.payment_method_name(name.as_str());
            }
            if let Some(subtitle) = &payment.payment_method_subtitle {
                entry = entry.payment_method_subtitle(subtitle.as_str());
            }
            if let Some(icon) = &payment.payment_method_icon {
                entry = entry.payment_method_icon(icon.as_slice());
            }
            if let Some(bank_icon) = &payment.bank_icon {
                entry = entry.bank_icon(bank_icon.as_slice());
            }
            if let Some(provider_icon) = &payment.payment_provider_icon {
                entry = entry.payment_provider_icon(provider_icon.as_slice());
            }
            if let Some(metadata) = &self.metadata_json {
                entry = entry.metadata(metadata.as_str());
            }
            if let Some(additional_info) = &payment.additional_info {
                entry = entry.additional_info(additional_info.as_str());
            }
            return CredentialEntry::Payment(entry);
        }

        let mut entry = StringIdEntry::new(self.credential_id.as_str(), self.title.as_str());
        if let Some(icon) = &self.icon {
            entry = entry.icon(icon.as_slice());
        }
        if let Some(subtitle) = &self.subtitle {
            entry = entry.subtitle(subtitle.as_str());
        }
        if let Some(disclaimer) = &self.disclaimer {
            entry = entry.disclaimer(disclaimer.as_str());
        }
        if let Some(warning) = &self.warning {
            entry = entry.warning(warning.as_str());
        }
        if let Some(metadata) = &self.metadata_json {
            entry = entry.metadata(metadata.as_str());
        }
        for field in &self.transaction_fields {
            entry = entry.add_field(field.display_name.as_str(), field.display_value.as_str());
        }
        for field in &self.fields {
            entry = entry.add_field(field.display_name.as_str(), field.display_value.as_str());
        }
        CredentialEntry::StringId(entry)
    }
}

/// Display field for one credential entry.
#[derive(Debug, Clone)]
pub struct ResolvedField {
    /// Field label.
    pub display_name: String,
    /// Field value.
    pub display_value: String,
}

/// Payment/SCA-focused rendering data for one credential entry.
#[derive(Debug, Clone)]
pub struct ResolvedPaymentPresentation {
    /// Merchant/payee label shown in payment UI.
    pub merchant_name: String,
    /// Transaction amount string shown in payment UI.
    pub transaction_amount: String,
    /// Optional payment method title (typically credential title).
    pub payment_method_name: Option<String>,
    /// Optional payment method subtitle (typically credential subtitle).
    pub payment_method_subtitle: Option<String>,
    /// Optional payment method icon.
    pub payment_method_icon: Option<Vec<u8>>,
    /// Optional bank icon.
    pub bank_icon: Option<Vec<u8>>,
    /// Optional payment provider icon.
    pub payment_provider_icon: Option<Vec<u8>>,
    /// Optional extra payment context for modern hosts.
    pub additional_info: Option<String>,
}

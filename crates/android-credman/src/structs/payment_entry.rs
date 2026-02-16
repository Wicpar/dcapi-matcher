use crate::*;

/// High-fidelity Payment/SCA entry emphasizing merchant and amount.
///
/// Required:
/// - `cred_id` must not be empty
/// - `merchant_name` must not be empty
/// - `transaction_amount` must not be empty and should match the verifier request
///
/// Optional:
/// - `metadata` is forwarded for entries emitted in sets.
/// - `additional_info` is used only with the v3 set API (`AddPaymentEntryToSetV2`).
#[derive(Debug, Clone)]
pub struct PaymentEntry<'a> {
    pub cred_id: &'a str,
    pub merchant_name: &'a str,
    pub transaction_amount: &'a str,
    pub payment_method_name: Option<&'a str>,
    pub payment_method_subtitle: Option<&'a str>,
    pub payment_method_icon: Option<&'a [u8]>,
    pub bank_icon: Option<&'a [u8]>,
    pub payment_provider_icon: Option<&'a [u8]>,
    pub metadata: Option<&'a str>,
    pub additional_info: Option<&'a str>,
}

impl<'a> PaymentEntry<'a> {
    pub fn new(cred_id: &'a str, merchant_name: &'a str, transaction_amount: &'a str) -> Self {
        let cred_id = if cred_id.is_empty() { " " } else { cred_id };
        let merchant_name = if merchant_name.is_empty() {
            " "
        } else {
            merchant_name
        };
        let transaction_amount = if transaction_amount.is_empty() {
            " "
        } else {
            transaction_amount
        };
        Self {
            cred_id,
            merchant_name,
            transaction_amount,
            payment_method_name: None,
            payment_method_subtitle: None,
            payment_method_icon: None,
            bank_icon: None,
            payment_provider_icon: None,
            metadata: None,
            additional_info: None,
        }
    }

    pub fn payment_method_name(mut self, name: &'a str) -> Self {
        self.payment_method_name = Some(name);
        self
    }

    pub fn payment_method_subtitle(mut self, subtitle: &'a str) -> Self {
        self.payment_method_subtitle = Some(subtitle);
        self
    }

    pub fn payment_method_icon(mut self, icon: &'a [u8]) -> Self {
        self.payment_method_icon = Some(icon);
        self
    }

    pub fn bank_icon(mut self, icon: &'a [u8]) -> Self {
        self.bank_icon = Some(icon);
        self
    }

    pub fn payment_provider_icon(mut self, icon: &'a [u8]) -> Self {
        self.payment_provider_icon = Some(icon);
        self
    }

    /// Attaches host callback metadata for set rendering (`credman_v2+`).
    pub fn metadata(mut self, metadata: &'a str) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Adds v3+ payment context shown by modern hosts (`AddPaymentEntryToSetV2`).
    pub fn additional_info(mut self, additional_info: &'a str) -> Self {
        self.additional_info = Some(additional_info);
        self
    }
}

impl<'a> CredmanApply<()> for PaymentEntry<'a> {
    fn apply(&self, _: ()) {
        let host = default_credman();
        host.add_payment_entry(&PaymentEntryRequest {
            cred_id: self.cred_id,
            merchant_name: self.merchant_name,
            payment_method_name: self.payment_method_name,
            payment_method_subtitle: self.payment_method_subtitle,
            payment_method_icon: self.payment_method_icon,
            transaction_amount: self.transaction_amount,
            bank_icon: self.bank_icon,
            payment_provider_icon: self.payment_provider_icon,
        });
    }
}

impl<'a> CredmanApply<(&'a str, i32)> for PaymentEntry<'a> {
    fn apply(&self, (set_id, set_index): (&'a str, i32)) {
        let host = default_credman();
        if let Some(v3) = host.as_v3() {
            v3.add_payment_entry_to_set_v2(&PaymentEntryToSetV2Request {
                cred_id: self.cred_id,
                merchant_name: self.merchant_name,
                payment_method_name: self.payment_method_name,
                payment_method_subtitle: self.payment_method_subtitle,
                payment_method_icon: self.payment_method_icon,
                transaction_amount: self.transaction_amount,
                bank_icon: self.bank_icon,
                payment_provider_icon: self.payment_provider_icon,
                additional_info: self.additional_info,
                metadata: self.metadata,
                set_id,
                set_index,
            });
            return;
        }

        if let Some(v2) = host.as_v2() {
            v2.add_payment_entry_to_set(&PaymentEntryToSetRequest {
                cred_id: self.cred_id,
                merchant_name: self.merchant_name,
                payment_method_name: self.payment_method_name,
                payment_method_subtitle: self.payment_method_subtitle,
                payment_method_icon: self.payment_method_icon,
                transaction_amount: self.transaction_amount,
                bank_icon: self.bank_icon,
                payment_provider_icon: self.payment_provider_icon,
                metadata: self.metadata,
                set_id,
                set_index,
            });
            return;
        }

        host.add_payment_entry(&PaymentEntryRequest {
            cred_id: self.cred_id,
            merchant_name: self.merchant_name,
            payment_method_name: self.payment_method_name,
            payment_method_subtitle: self.payment_method_subtitle,
            payment_method_icon: self.payment_method_icon,
            transaction_amount: self.transaction_amount,
            bank_icon: self.bank_icon,
            payment_provider_icon: self.payment_provider_icon,
        });
    }
}

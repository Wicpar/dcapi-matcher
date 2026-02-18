use crate::*;
use std::borrow::Cow;

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
    pub cred_id: Cow<'a, str>,
    pub merchant_name: Cow<'a, str>,
    pub transaction_amount: Cow<'a, str>,
    pub payment_method_name: Option<Cow<'a, str>>,
    pub payment_method_subtitle: Option<Cow<'a, str>>,
    pub payment_method_icon: Option<Cow<'a, [u8]>>,
    pub bank_icon: Option<Cow<'a, [u8]>>,
    pub payment_provider_icon: Option<Cow<'a, [u8]>>,
    pub metadata: Option<Cow<'a, str>>,
    pub additional_info: Option<Cow<'a, str>>,
    pub fields: Vec<Field<'a>>,
}

impl<'a> PaymentEntry<'a> {
    pub fn new(
        cred_id: impl Into<Cow<'a, str>>,
        merchant_name: impl Into<Cow<'a, str>>,
        transaction_amount: impl Into<Cow<'a, str>>,
    ) -> Self {
        let cred_id = normalize(cred_id.into());
        let merchant_name = normalize(merchant_name.into());
        let transaction_amount = normalize(transaction_amount.into());
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
            fields: Vec::new(),
        }
    }

    pub fn payment_method_name(mut self, name: impl Into<Cow<'a, str>>) -> Self {
        self.payment_method_name = Some(name.into());
        self
    }

    pub fn payment_method_subtitle(mut self, subtitle: impl Into<Cow<'a, str>>) -> Self {
        self.payment_method_subtitle = Some(subtitle.into());
        self
    }

    pub fn payment_method_icon(mut self, icon: impl Into<Cow<'a, [u8]>>) -> Self {
        self.payment_method_icon = Some(icon.into());
        self
    }

    pub fn bank_icon(mut self, icon: impl Into<Cow<'a, [u8]>>) -> Self {
        self.bank_icon = Some(icon.into());
        self
    }

    pub fn payment_provider_icon(mut self, icon: impl Into<Cow<'a, [u8]>>) -> Self {
        self.payment_provider_icon = Some(icon.into());
        self
    }

    /// Attaches host callback metadata for set rendering (`credman_v2+`).
    pub fn metadata(mut self, metadata: impl Into<Cow<'a, str>>) -> Self {
        self.metadata = Some(metadata.into());
        self
    }

    /// Adds v3+ payment context shown by modern hosts (`AddPaymentEntryToSetV2`).
    pub fn additional_info(mut self, additional_info: impl Into<Cow<'a, str>>) -> Self {
        self.additional_info = Some(additional_info.into());
        self
    }

    pub fn add_field(
        mut self,
        display_name: impl Into<Cow<'a, str>>,
        display_value: impl Into<Cow<'a, str>>,
    ) -> Self {
        self.fields
            .push(Field::new(display_name, Some(display_value)));
        self
    }
}

fn normalize<'a>(value: Cow<'a, str>) -> Cow<'a, str> {
    if value.is_empty() {
        Cow::Borrowed("_")
    } else {
        value
    }
}

impl<'a> CredmanApply<()> for PaymentEntry<'a> {
    fn apply(&self, _: ()) {
        let host = credman();
        host.add_payment_entry(&PaymentEntryRequest {
            cred_id: self.cred_id.as_ref(),
            merchant_name: self.merchant_name.as_ref(),
            payment_method_name: self.payment_method_name.as_ref().map(|value| value.as_ref()),
            payment_method_subtitle: self
                .payment_method_subtitle
                .as_ref()
                .map(|value| value.as_ref()),
            payment_method_icon: self
                .payment_method_icon
                .as_ref()
                .map(|icon| icon.as_ref()),
            transaction_amount: self.transaction_amount.as_ref(),
            bank_icon: self.bank_icon.as_ref().map(|icon| icon.as_ref()),
            payment_provider_icon: self
                .payment_provider_icon
                .as_ref()
                .map(|icon| icon.as_ref()),
        });
        apply_payment_fields(self, None);
    }
}

impl<'a> CredmanApply<(&'a str, i32)> for PaymentEntry<'a> {
    fn apply(&self, (set_id, set_index): (&'a str, i32)) {
        let host = credman();
        if let Some(v3) = host.as_v3() {
            v3.add_payment_entry_to_set_v2(&PaymentEntryToSetV2Request {
                cred_id: self.cred_id.as_ref(),
                merchant_name: self.merchant_name.as_ref(),
                payment_method_name: self.payment_method_name.as_ref().map(|value| value.as_ref()),
                payment_method_subtitle: self
                    .payment_method_subtitle
                    .as_ref()
                    .map(|value| value.as_ref()),
                payment_method_icon: self
                    .payment_method_icon
                    .as_ref()
                    .map(|icon| icon.as_ref()),
                transaction_amount: self.transaction_amount.as_ref(),
                bank_icon: self.bank_icon.as_ref().map(|icon| icon.as_ref()),
                payment_provider_icon: self
                    .payment_provider_icon
                    .as_ref()
                    .map(|icon| icon.as_ref()),
                additional_info: self.additional_info.as_ref().map(|value| value.as_ref()),
                metadata: self.metadata.as_ref().map(|value| value.as_ref()),
                set_id,
                set_index,
            });
            apply_payment_fields(self, Some((set_id, set_index)));
            return;
        }

        if let Some(v2) = host.as_v2() {
            v2.add_payment_entry_to_set(&PaymentEntryToSetRequest {
                cred_id: self.cred_id.as_ref(),
                merchant_name: self.merchant_name.as_ref(),
                payment_method_name: self.payment_method_name.as_ref().map(|value| value.as_ref()),
                payment_method_subtitle: self
                    .payment_method_subtitle
                    .as_ref()
                    .map(|value| value.as_ref()),
                payment_method_icon: self
                    .payment_method_icon
                    .as_ref()
                    .map(|icon| icon.as_ref()),
                transaction_amount: self.transaction_amount.as_ref(),
                bank_icon: self.bank_icon.as_ref().map(|icon| icon.as_ref()),
                payment_provider_icon: self
                    .payment_provider_icon
                    .as_ref()
                    .map(|icon| icon.as_ref()),
                metadata: self.metadata.as_ref().map(|value| value.as_ref()),
                set_id,
                set_index,
            });
            apply_payment_fields(self, Some((set_id, set_index)));
            return;
        }

        host.add_payment_entry(&PaymentEntryRequest {
            cred_id: self.cred_id.as_ref(),
            merchant_name: self.merchant_name.as_ref(),
            payment_method_name: self.payment_method_name.as_ref().map(|value| value.as_ref()),
            payment_method_subtitle: self
                .payment_method_subtitle
                .as_ref()
                .map(|value| value.as_ref()),
            payment_method_icon: self
                .payment_method_icon
                .as_ref()
                .map(|icon| icon.as_ref()),
            transaction_amount: self.transaction_amount.as_ref(),
            bank_icon: self.bank_icon.as_ref().map(|icon| icon.as_ref()),
            payment_provider_icon: self
                .payment_provider_icon
                .as_ref()
                .map(|icon| icon.as_ref()),
        });
        apply_payment_fields(self, None);
    }
}

fn apply_payment_fields(entry: &PaymentEntry<'_>, ctx: Option<(&str, i32)>) {
    if entry.fields.is_empty() {
        let field = Field::new("_", Some("_"));
        match ctx {
            Some((set_id, set_index)) => {
                field.apply((entry.cred_id.as_ref(), set_id, set_index));
            }
            None => field.apply(entry.cred_id.as_ref()),
        }
        return;
    }

    for field in &entry.fields {
        match ctx {
            Some((set_id, set_index)) => {
                field.apply((entry.cred_id.as_ref(), set_id, set_index));
            }
            None => field.apply(entry.cred_id.as_ref()),
        }
    }
}

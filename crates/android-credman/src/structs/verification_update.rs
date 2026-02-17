use crate::*;
use std::borrow::Cow;

#[derive(Debug, Clone)]
pub struct VerificationEntryUpdate<'a> {
    pub cred_id: Cow<'a, str>,
    pub secondary_disclaimer: Option<Cow<'a, str>>,
    pub url_display_text: Option<Cow<'a, str>>,
    pub url_value: Option<Cow<'a, str>>,
}

impl<'a> VerificationEntryUpdate<'a> {
    pub fn new(cred_id: impl Into<Cow<'a, str>>) -> Self {
        Self {
            cred_id: cred_id.into(),
            secondary_disclaimer: None,
            url_display_text: None,
            url_value: None,
        }
    }

    pub fn secondary_disclaimer(mut self, disclaimer: impl Into<Cow<'a, str>>) -> Self {
        self.secondary_disclaimer = Some(disclaimer.into());
        self
    }

    pub fn url_display_text(mut self, text: impl Into<Cow<'a, str>>) -> Self {
        self.url_display_text = Some(text.into());
        self
    }

    pub fn url_value(mut self, value: impl Into<Cow<'a, str>>) -> Self {
        self.url_value = Some(value.into());
        self
    }
}

impl<'a> CredmanApply<()> for VerificationEntryUpdate<'a> {
    fn apply(&self, _: ()) {
        let host = default_credman();
        host.set_additional_disclaimer_and_url_for_verification_entry(
            &VerificationEntryUpdateRequest {
                cred_id: self.cred_id.as_ref(),
                secondary_disclaimer: self.secondary_disclaimer.as_ref().map(|value| value.as_ref()),
                url_display_text: self.url_display_text.as_ref().map(|value| value.as_ref()),
                url_value: self.url_value.as_ref().map(|value| value.as_ref()),
            },
        );
    }
}

use crate::*;

#[derive(Debug, Clone)]
pub struct VerificationEntryUpdate<'a> {
    pub cred_id: &'a str,
    pub secondary_disclaimer: Option<&'a str>,
    pub url_display_text: Option<&'a str>,
    pub url_value: Option<&'a str>,
}

impl<'a> VerificationEntryUpdate<'a> {
    pub fn new(cred_id: &'a str) -> Self {
        Self {
            cred_id,
            secondary_disclaimer: None,
            url_display_text: None,
            url_value: None,
        }
    }

    pub fn secondary_disclaimer(mut self, disclaimer: &'a str) -> Self {
        self.secondary_disclaimer = Some(disclaimer);
        self
    }

    pub fn url_display_text(mut self, text: &'a str) -> Self {
        self.url_display_text = Some(text);
        self
    }

    pub fn url_value(mut self, value: &'a str) -> Self {
        self.url_value = Some(value);
        self
    }
}

impl<'a> CredmanApply<()> for VerificationEntryUpdate<'a> {
    fn apply(&self, _: ()) {
        let host = default_credman();
        host.set_additional_disclaimer_and_url_for_verification_entry(
            &VerificationEntryUpdateRequest {
                cred_id: self.cred_id,
                secondary_disclaimer: self.secondary_disclaimer,
                url_display_text: self.url_display_text,
                url_value: self.url_value,
            },
        );
    }
}

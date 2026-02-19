use crate::{CredmanApply, CredmanContext};
use core::ffi::CStr;

#[derive(Debug, Clone)]
pub struct VerificationEntryUpdate<'a> {
    pub cred_id: &'a CStr,
    pub secondary_disclaimer: Option<&'a CStr>,
    pub url_display_text: Option<&'a CStr>,
    pub url_value: Option<&'a CStr>,
}

impl<'a> VerificationEntryUpdate<'a> {
    pub fn new(cred_id: &'a CStr) -> Self {
        Self {
            cred_id,
            secondary_disclaimer: None,
            url_display_text: None,
            url_value: None,
        }
    }

}

impl<'a, 'b> CredmanApply<CredmanContext<'b>> for VerificationEntryUpdate<'a> {
    fn apply(&self, ctx: CredmanContext<'b>) {
        ctx.host
            .set_additional_disclaimer_and_url_for_verification_entry(self);
    }
}

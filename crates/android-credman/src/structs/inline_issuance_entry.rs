use crate::*;

/// Entry that triggers an Inline Issuance flow when the requested credential is missing.
///
/// Required:
/// - `cred_id` must not be empty
/// - `title` must not be empty
#[derive(Debug, Clone)]
pub struct InlineIssuanceEntry<'a> {
    pub cred_id: &'a str,
    pub title: &'a str,
    pub icon: Option<&'a [u8]>,
    pub subtitle: Option<&'a str>,
}

impl<'a> InlineIssuanceEntry<'a> {
    pub fn new(cred_id: &'a str, title: &'a str) -> Self {
        let cred_id = if cred_id.is_empty() { " " } else { cred_id };
        let title = if title.is_empty() { " " } else { title };
        Self {
            cred_id,
            title,
            icon: None,
            subtitle: None,
        }
    }

    pub fn icon(mut self, icon: &'a [u8]) -> Self {
        self.icon = Some(icon);
        self
    }

    pub fn subtitle(mut self, subtitle: &'a str) -> Self {
        self.subtitle = Some(subtitle);
        self
    }
}

impl<'a> CredmanApply<()> for InlineIssuanceEntry<'a> {
    fn apply(&self, _: ()) {
        let host = default_credman();
        host.add_inline_issuance_entry(&InlineIssuanceEntryRequest {
            cred_id: self.cred_id,
            icon: self.icon,
            title: self.title,
            subtitle: self.subtitle,
        });
    }
}

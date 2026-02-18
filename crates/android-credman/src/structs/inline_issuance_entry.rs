use crate::*;
use std::borrow::Cow;

/// Entry that triggers an Inline Issuance flow when the requested credential is missing.
///
/// Required:
/// - `cred_id` must not be empty
/// - `title` must not be empty
#[derive(Debug, Clone)]
pub struct InlineIssuanceEntry<'a> {
    pub cred_id: Cow<'a, str>,
    pub title: Cow<'a, str>,
    pub icon: Option<Cow<'a, [u8]>>,
    pub subtitle: Option<Cow<'a, str>>,
}

impl<'a> InlineIssuanceEntry<'a> {
    pub fn new(cred_id: impl Into<Cow<'a, str>>, title: impl Into<Cow<'a, str>>) -> Self {
        let cred_id = normalize(cred_id.into());
        let title = normalize(title.into());
        Self {
            cred_id,
            title,
            icon: None,
            subtitle: None,
        }
    }

    pub fn icon(mut self, icon: impl Into<Cow<'a, [u8]>>) -> Self {
        self.icon = Some(icon.into());
        self
    }

    pub fn subtitle(mut self, subtitle: impl Into<Cow<'a, str>>) -> Self {
        self.subtitle = Some(subtitle.into());
        self
    }
}

fn normalize(value: Cow<str>) -> Cow<str> {
    if value.is_empty() {
        Cow::Borrowed("_")
    } else {
        value
    }
}

impl<'a> CredmanApply<()> for InlineIssuanceEntry<'a> {
    fn apply(&self, _: ()) {
        let host = credman();
        host.add_inline_issuance_entry(&InlineIssuanceEntryRequest {
            cred_id: self.cred_id.as_ref(),
            icon: self.icon.as_ref().map(|icon| icon.as_ref()),
            title: self.title.as_ref(),
            subtitle: self.subtitle.as_ref().map(|value| value.as_ref()),
        });
    }
}

use crate::*;
use std::borrow::Cow;
use std::vec::Vec;

/// Standard entry rendered by Credential Manager with a string `cred_id`.
///
/// Required:
/// - `cred_id` must not be empty
/// - `title` must not be empty
///
/// Optional:
/// - `metadata` is forwarded only when rendered inside a set (`credman_v2+`).
#[derive(Debug, Clone)]
pub struct StringIdEntry<'a> {
    pub cred_id: Cow<'a, str>,
    pub title: Cow<'a, str>,
    pub icon: Option<Cow<'a, [u8]>>,
    pub subtitle: Option<Cow<'a, str>>,
    pub disclaimer: Option<Cow<'a, str>>,
    pub warning: Option<Cow<'a, str>>,
    pub metadata: Option<Cow<'a, str>>,
    pub fields: Vec<Field<'a>>,
}

impl<'a> StringIdEntry<'a> {
    pub fn new(
        cred_id: impl Into<Cow<'a, str>>,
        title: impl Into<Cow<'a, str>>,
    ) -> Self {
        let cred_id = cred_id.into();
        let title = title.into();
        Self {
            cred_id,
            title,
            icon: None,
            subtitle: None,
            disclaimer: None,
            warning: None,
            metadata: None,
            fields: Vec::new(),
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

    pub fn disclaimer(mut self, disclaimer: impl Into<Cow<'a, str>>) -> Self {
        self.disclaimer = Some(disclaimer.into());
        self
    }

    pub fn warning(mut self, warning: impl Into<Cow<'a, str>>) -> Self {
        self.warning = Some(warning.into());
        self
    }

    /// Attaches opaque metadata for host-side callbacks when this entry is emitted in a set.
    pub fn metadata(mut self, metadata: impl Into<Cow<'a, str>>) -> Self {
        self.metadata = Some(metadata.into());
        self
    }
}

impl<'a> CredmanApply<()> for StringIdEntry<'a> {
    fn apply(&self, _: ()) {
        let host = credman();
        host.add_string_id_entry(&StringIdEntryRequest {
            cred_id: self.cred_id.as_ref(),
            icon: self.icon.as_ref().map(|icon| icon.as_ref()),
            title: self.title.as_ref(),
            subtitle: self.subtitle.as_ref().map(|value| value.as_ref()),
            disclaimer: self.disclaimer.as_ref().map(|value| value.as_ref()),
            warning: self.warning.as_ref().map(|value| value.as_ref()),
        });
        if self.fields.is_empty() {
            host.add_field_for_string_id_entry(&FieldForStringIdEntryRequest {
                cred_id: self.cred_id.as_ref(),
                field_display_name: "_",
                field_display_value: None,
            });
            return;
        }
        for field in &self.fields {
            field.apply(self.cred_id.as_ref());
        }
    }
}

impl<'a> CredmanApply<(&'a str, i32)> for StringIdEntry<'a> {
    fn apply(&self, (set_id, set_index): (&'a str, i32)) {
        let host = credman();
        if let Some(v2) = host.as_v2() {
            v2.add_entry_to_set(&EntryToSetRequest {
                cred_id: self.cred_id.as_ref(),
                icon: self.icon.as_ref().map(|icon| icon.as_ref()),
                title: self.title.as_ref(),
                subtitle: self.subtitle.as_ref().map(|value| value.as_ref()),
                disclaimer: self.disclaimer.as_ref().map(|value| value.as_ref()),
                warning: self.warning.as_ref().map(|value| value.as_ref()),
                metadata: self.metadata.as_ref().map(|value| value.as_ref()),
                set_id,
                set_index,
            });
        } else {
            host.add_string_id_entry(&StringIdEntryRequest {
                cred_id: self.cred_id.as_ref(),
                icon: self.icon.as_ref().map(|icon| icon.as_ref()),
                title: self.title.as_ref(),
                subtitle: self.subtitle.as_ref().map(|value| value.as_ref()),
                disclaimer: self.disclaimer.as_ref().map(|value| value.as_ref()),
                warning: self.warning.as_ref().map(|value| value.as_ref()),
            });
        }
        if self.fields.is_empty() {
            if let Some(v2) = host.as_v2() {
                v2.add_field_to_entry_set(&FieldToEntrySetRequest {
                    cred_id: self.cred_id.as_ref(),
                    field_display_name: "_",
                    field_display_value: Some("_"),
                    set_id,
                    set_index,
                });
                return;
            }
            host.add_field_for_string_id_entry(&FieldForStringIdEntryRequest {
                cred_id: self.cred_id.as_ref(),
                field_display_name: "_",
                field_display_value: Some("_"),
            });
            return;
        }
        for field in &self.fields {
            field.apply((self.cred_id.as_ref(), set_id, set_index));
        }
    }
}

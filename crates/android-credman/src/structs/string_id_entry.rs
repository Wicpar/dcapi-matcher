use crate::*;
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
    pub cred_id: &'a str,
    pub title: &'a str,
    pub icon: Option<&'a [u8]>,
    pub subtitle: Option<&'a str>,
    pub disclaimer: Option<&'a str>,
    pub warning: Option<&'a str>,
    pub metadata: Option<&'a str>,
    pub fields: Vec<Field<'a>>,
}

impl<'a> StringIdEntry<'a> {
    pub fn new(cred_id: &'a str, title: &'a str) -> Self {
        let cred_id = if cred_id.is_empty() { " " } else { cred_id };
        let title = if title.is_empty() { " " } else { title };
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

    pub fn icon(mut self, icon: &'a [u8]) -> Self {
        self.icon = Some(icon);
        self
    }

    pub fn subtitle(mut self, subtitle: &'a str) -> Self {
        self.subtitle = Some(subtitle);
        self
    }

    pub fn disclaimer(mut self, disclaimer: &'a str) -> Self {
        self.disclaimer = Some(disclaimer);
        self
    }

    pub fn warning(mut self, warning: &'a str) -> Self {
        self.warning = Some(warning);
        self
    }

    /// Attaches opaque metadata for host-side callbacks when this entry is emitted in a set.
    pub fn metadata(mut self, metadata: &'a str) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub fn add_field(mut self, display_name: &'a str, display_value: &'a str) -> Self {
        self.fields.push(Field::new(display_name, display_value));
        self
    }
}

impl<'a> CredmanApply<()> for StringIdEntry<'a> {
    fn apply(&self, _: ()) {
        let host = default_credman();
        host.add_string_id_entry(&StringIdEntryRequest {
            cred_id: self.cred_id,
            icon: self.icon,
            title: self.title,
            subtitle: self.subtitle,
            disclaimer: self.disclaimer,
            warning: self.warning,
        });
        for field in &self.fields {
            field.apply(self.cred_id);
        }
    }
}

impl<'a> CredmanApply<(&'a str, i32)> for StringIdEntry<'a> {
    fn apply(&self, (set_id, set_index): (&'a str, i32)) {
        let host = default_credman();
        if let Some(v2) = host.as_v2() {
            v2.add_entry_to_set(&EntryToSetRequest {
                cred_id: self.cred_id,
                icon: self.icon,
                title: self.title,
                subtitle: self.subtitle,
                disclaimer: self.disclaimer,
                warning: self.warning,
                metadata: self.metadata,
                set_id,
                set_index,
            });
        } else {
            host.add_string_id_entry(&StringIdEntryRequest {
                cred_id: self.cred_id,
                icon: self.icon,
                title: self.title,
                subtitle: self.subtitle,
                disclaimer: self.disclaimer,
                warning: self.warning,
            });
        }
        for field in &self.fields {
            field.apply((self.cred_id, set_id, set_index));
        }
    }
}

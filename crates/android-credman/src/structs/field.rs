use crate::*;
use std::borrow::Cow;

/// A key-value detail field displayed in an entry's detail section.
///
/// Constraints:
/// - `display_name` must not be empty
/// - `display_value` must not be empty when provided
#[derive(Debug, Clone)]
pub struct Field<'a> {
    pub display_name: Cow<'a, str>,
    pub display_value: Option<Cow<'a, str>>,
}

impl<'a> Field<'a> {
    pub fn new<D>(display_name: impl Into<Cow<'a, str>>, display_value: Option<D>) -> Self
    where
        D: Into<Cow<'a, str>>,
    {
        let display_name = normalize(display_name.into());
        let display_value = display_value.map(Into::into);
        Self {
            display_name,
            display_value,
        }
    }
}

fn normalize(value: Cow<str>) -> Cow<str> {
    if value.is_empty() {
        Cow::Borrowed("_")
    } else {
        value
    }
}

impl<'a> CredmanApply<&'a str> for Field<'a> {
    fn apply(&self, cred_id: &'a str) {
        let host = credman();
        host.add_field_for_string_id_entry(&FieldForStringIdEntryRequest {
            cred_id,
            field_display_name: self.display_name.as_ref(),
            field_display_value: self.display_value.as_deref(),
        });
    }
}

impl<'a> CredmanApply<(&'a str, &'a str, i32)> for Field<'a> {
    fn apply(&self, (cred_id, set_id, set_index): (&'a str, &'a str, i32)) {
        let host = credman();
        if let Some(v2) = host.as_v2() {
            v2.add_field_to_entry_set(&FieldToEntrySetRequest {
                cred_id,
                field_display_name: self.display_name.as_ref(),
                field_display_value: self.display_value.as_deref(),
                set_id,
                set_index,
            });
            return;
        }

        host.add_field_for_string_id_entry(&FieldForStringIdEntryRequest {
            cred_id,
            field_display_name: self.display_name.as_ref(),
            field_display_value: self.display_value.as_deref(),
        });
    }
}

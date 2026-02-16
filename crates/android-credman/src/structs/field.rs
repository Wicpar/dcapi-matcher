use crate::*;

/// A key-value detail field displayed in an entry's detail section.
///
/// Constraints:
/// - `display_name` must not be empty
/// - `display_value` must not be empty
#[derive(Debug, Clone)]
pub struct Field<'a> {
    pub display_name: &'a str,
    pub display_value: &'a str,
}

impl<'a> Field<'a> {
    pub fn new(display_name: &'a str, display_value: &'a str) -> Self {
        let display_name = if display_name.is_empty() {
            " "
        } else {
            display_name
        };
        Self {
            display_name,
            display_value: if display_value.is_empty() {
                " "
            } else {
                display_value
            },
        }
    }
}

impl<'a> CredmanApply<&'a str> for Field<'a> {
    fn apply(&self, cred_id: &'a str) {
        let host = default_credman();
        host.add_field_for_string_id_entry(&FieldForStringIdEntryRequest {
            cred_id,
            field_display_name: self.display_name,
            field_display_value: Some(self.display_value),
        });
    }
}

impl<'a> CredmanApply<(&'a str, &'a str, i32)> for Field<'a> {
    fn apply(&self, (cred_id, set_id, set_index): (&'a str, &'a str, i32)) {
        let host = default_credman();
        if let Some(v2) = host.as_v2() {
            v2.add_field_to_entry_set(&FieldToEntrySetRequest {
                cred_id,
                field_display_name: self.display_name,
                field_display_value: Some(self.display_value),
                set_id,
                set_index,
            });
            return;
        }

        host.add_field_for_string_id_entry(&FieldForStringIdEntryRequest {
            cred_id,
            field_display_name: self.display_name,
            field_display_value: Some(self.display_value),
        });
    }
}

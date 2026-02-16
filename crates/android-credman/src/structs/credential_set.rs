use crate::*;

/// A visual group (Set) of credentials.
///
/// In Android Credential Manager, a Set is a top-level item that expands.
/// Each item in the set (a "slot") can contain multiple alternatives.
///
/// # Semantics
/// - `CredentialSet` is an OR-select across its slots.
/// - Each slot is an OR-select across its alternatives.
/// - On hosts without set support (v1), entries are emitted as standalone rows.
#[derive(Debug, Clone)]
pub struct CredentialSet<'a> {
    pub set_id: &'a str,
    pub slots: Vec<CredentialSlot<'a>>,
}

impl<'a> CredentialSet<'a> {
    pub fn new(set_id: &'a str) -> Self {
        let set_id = if set_id.is_empty() { " " } else { set_id };
        Self {
            set_id,
            slots: Vec::new(),
        }
    }

    /// Adds a slot to the set.
    pub fn add_slot<S: Into<CredentialSlot<'a>>>(mut self, slot: S) -> Self {
        self.slots.push(slot.into());
        self
    }

    /// Shortcut to add a single entry to the set as its own slot.
    pub fn add_entry(self, entry: CredentialEntry<'a>) -> Self {
        self.add_slot(entry)
    }
}

impl<'a> CredmanApply<()> for CredentialSet<'a> {
    fn apply(&self, _: ()) {
        if self.slots.is_empty() {
            return;
        }
        let host = default_credman();
        if let Some(v2) = host.as_v2() {
            v2.add_entry_set(&EntrySetRequest {
                set_id: self.set_id,
                set_length: self.slots.len() as i32,
            });
            for (i, slot) in self.slots.iter().enumerate() {
                for entry in &slot.alternatives {
                    CredmanApply::apply(entry, (self.set_id, i as i32));
                }
            }
            return;
        }

        // Host does not support sets (v1): degrade to standalone entries.
        for slot in &self.slots {
            for entry in &slot.alternatives {
                CredmanApply::apply(entry, ());
            }
        }
    }
}

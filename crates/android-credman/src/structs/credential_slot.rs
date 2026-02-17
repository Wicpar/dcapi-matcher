use crate::*;

/// A slot in a `CredentialSet` that contains one or more alternatives.
///
/// Credential Manager treats multiple entries for the same `set_index` as
/// alternatives that the user can pick between (OR-selection).
#[derive(Debug, Clone)]
pub struct CredentialSlot<'a> {
    pub alternatives: Vec<CredentialEntry<'a>>,
}

impl<'a> CredentialSlot<'a> {
    /// Creates a new slot with one or more initial entries.
    pub fn new<I>(entries: I) -> Self
    where
        I: IntoIterator<Item = CredentialEntry<'a>>,
    {
        Self {
            alternatives: entries.into_iter().collect(),
        }
    }

    /// Adds an alternative to this slot.
    pub fn add_alternative(mut self, entry: CredentialEntry<'a>) -> Self {
        self.alternatives.push(entry);
        self
    }
}

impl<'a> From<CredentialEntry<'a>> for CredentialSlot<'a> {
    fn from(entry: CredentialEntry<'a>) -> Self {
        CredentialSlot::new(core::iter::once(entry))
    }
}

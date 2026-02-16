use crate::*;

/// A single credential choice that can be rendered standalone or inside a Set.
#[derive(Debug, Clone)]
pub enum CredentialEntry<'a> {
    StringId(StringIdEntry<'a>),
    Payment(PaymentEntry<'a>),
}

impl<'a> CredmanApply<()> for CredentialEntry<'a> {
    fn apply(&self, _: ()) {
        match self {
            CredentialEntry::StringId(e) => CredmanApply::apply(e, ()),
            CredentialEntry::Payment(e) => CredmanApply::apply(e, ()),
        }
    }
}

impl<'a> CredmanApply<(&'a str, i32)> for CredentialEntry<'a> {
    fn apply(&self, ctx: (&'a str, i32)) {
        match self {
            CredentialEntry::StringId(e) => CredmanApply::apply(e, ctx),
            CredentialEntry::Payment(e) => CredmanApply::apply(e, ctx),
        }
    }
}

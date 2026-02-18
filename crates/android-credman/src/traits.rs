/// Emits a value to the host using the Credential Manager output ABI.
///
/// # Purpose
/// Types like `StringIdEntry`, `PaymentEntry`, and `CredentialSet` implement this trait
/// so they can be applied uniformly from matcher code.
///
/// # `options`
/// Implementations may use `options` as additional context (for example, set id/index).
pub trait CredmanApply<T = ()> {
    fn apply(&self, options: T);
}

/// Convenience extension for `CredmanApply<()>`.
///
/// This allows calling `x.apply()` instead of `CredmanApply::apply(&x, ())`.
pub trait CredmanRender {
    fn render(&self);
}

impl<S> CredmanRender for S
where
    S: CredmanApply<()>,
{
    fn render(&self) {
        CredmanApply::apply(self, ());
    }
}

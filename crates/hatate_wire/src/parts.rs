//! Failures that come from one part of a list of parts.
use crate::error_code::ErrorCodeOf;
use core::{error::Error, fmt};
use frunk_core::coproduct::{CNil, Coproduct};

/// A failure that one part of a list reported, held as a `Coproduct` of
/// the failures of the parts, in the order of the list, ending in `CNil`.
///
/// A `Coproduct` does not implement [`Error`]; this wrapper does, and
/// gives the failure of the part as its source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartsError<C>(C);

impl<C> PartsError<C> {
    /// The failure of `part`.
    pub const fn new(part: C) -> Self {
        Self(part)
    }

    /// The sum of the failures of the parts.
    pub const fn get(&self) -> &C {
        &self.0
    }

    /// Takes the sum of the failures of the parts.
    pub fn into_inner(self) -> C {
        self.0
    }
}

impl<C: ErrorSum> fmt::Display for PartsError<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.0.error(), f)
    }
}

impl<C: ErrorSum> Error for PartsError<C> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.error().source()
    }
}

/// The code of the part's failure.
impl<X, C: ErrorCodeOf<X>> ErrorCodeOf<X> for PartsError<C> {
    fn error_code(&self) -> Option<X> {
        self.0.error_code()
    }
}

/// A `Coproduct` of failures, each an [`Error`].
pub trait ErrorSum: fmt::Debug {
    /// The failure this sum holds.
    fn error(&self) -> &(dyn Error + 'static);
}

impl ErrorSum for CNil {
    fn error(&self) -> &(dyn Error + 'static) {
        match *self {}
    }
}

impl<H: Error + 'static, T: ErrorSum> ErrorSum for Coproduct<H, T> {
    fn error(&self) -> &(dyn Error + 'static) {
        match self {
            Coproduct::Inl(error) => error,
            Coproduct::Inr(rest) => rest.error(),
        }
    }
}

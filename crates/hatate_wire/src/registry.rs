//! The values a part claims in one of the extensible HTTP/3 registries.
//!
//! HTTP/3 has four extension points ([RFC 9114 §9]): frame types, settings,
//! error codes and unidirectional stream types. A part claims values in the
//! first, second and fourth; [`ClaimedValues`] lists them so that a list of
//! parts can be checked at compile time to claim each value at most once.
//! Error codes need no such check, as no part reads them differently.
//!
//! [RFC 9114 §9]: https://www.rfc-editor.org/rfc/rfc9114.html#section-9
use core::ops::RangeInclusive;
use frunk_core::coproduct::{CNil, Coproduct};
use sakuya_var_int::VarInt;
use snafu::Snafu;

/// A value of a registry as the type that claims it reads it, such as a
/// frame type or a stream type of a part: the type converts it to and from
/// the integer on the wire.
///
/// The value types of the parts implement it, and so do their sums, a
/// `Coproduct` of value types ending in `CNil`, so that the conversion of a
/// value of a list of parts is that of the part it belongs to.
pub trait ClaimedValue: Copy {
    /// The integer on the wire.
    fn value(self) -> VarInt;

    /// The value that `value` is, or `None` if this type does not claim it.
    fn of(value: VarInt) -> Option<Self>;
}

impl ClaimedValue for CNil {
    fn value(self) -> VarInt {
        match self {}
    }

    fn of(_value: VarInt) -> Option<Self> {
        None
    }
}

impl<H: ClaimedValue, T: ClaimedValue> ClaimedValue for Coproduct<H, T> {
    fn value(self) -> VarInt {
        match self {
            Coproduct::Inl(value) => value.value(),
            Coproduct::Inr(value) => value.value(),
        }
    }

    fn of(value: VarInt) -> Option<Self> {
        H::of(value)
            .map(Coproduct::Inl)
            .or_else(|| T::of(value).map(Coproduct::Inr))
    }
}

/// An integer is not a value the type claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("{value} is not a value this type claims"))]
pub struct UnclaimedValueError {
    value: VarInt,
}

impl UnclaimedValueError {
    /// The error for `value`.
    pub const fn new(value: VarInt) -> Self {
        Self { value }
    }

    /// The integer.
    pub const fn value(&self) -> VarInt {
        self.value
    }
}

/// The values a part claims in one registry: ranges of values, or for a
/// list of parts those of the parts it holds.
#[derive(Debug)]
pub struct ClaimedValues(Values);

#[derive(Debug)]
enum Values {
    Ranges(&'static [RangeInclusive<VarInt>]),
    Join(&'static ClaimedValues, &'static ClaimedValues),
}

impl ClaimedValues {
    /// The values in `ranges`; an empty range claims no value.
    pub const fn new(ranges: &'static [RangeInclusive<VarInt>]) -> Self {
        Self(Values::Ranges(ranges))
    }

    /// No value.
    pub const NONE: Self = Self::new(&[]);

    /// The values of `first` and those of `rest`.
    pub(crate) const fn join(first: &'static Self, rest: &'static Self) -> Self {
        Self(Values::Join(first, rest))
    }

    /// Whether no value is in both `self` and `other`.
    pub const fn is_disjoint(&self, other: &Self) -> bool {
        match self.0 {
            Values::Ranges(ranges) => {
                let mut index = 0;
                while index < ranges.len() {
                    if !other.excludes(&ranges[index]) {
                        return false;
                    }
                    index += 1;
                }
                true
            }
            Values::Join(first, rest) => first.is_disjoint(other) && rest.is_disjoint(other),
        }
    }

    /// Whether `value` is in `self`.
    pub const fn contains(&self, value: VarInt) -> bool {
        !self.excludes(&RangeInclusive::new(value, value))
    }

    /// Whether no value of `self` is reserved ([`is_reserved`]).
    pub const fn avoids_reserved(&self) -> bool {
        match self.0 {
            Values::Ranges(ranges) => {
                let mut index = 0;
                while index < ranges.len() {
                    let (start, end) = (ranges[index].start().get(), ranges[index].end().get());
                    if start <= end && first_reserved_from(start) <= end {
                        return false;
                    }
                    index += 1;
                }
                true
            }
            Values::Join(first, rest) => first.avoids_reserved() && rest.avoids_reserved(),
        }
    }

    /// Whether no value of `range` is in `self`.
    const fn excludes(&self, range: &RangeInclusive<VarInt>) -> bool {
        match self.0 {
            Values::Ranges(ranges) => {
                let (start, end) = (range.start().get(), range.end().get());
                let mut index = 0;
                while index < ranges.len() {
                    let (other_start, other_end) =
                        (ranges[index].start().get(), ranges[index].end().get());
                    if start <= end
                        && other_start <= other_end
                        && start <= other_end
                        && other_start <= end
                    {
                        return false;
                    }
                    index += 1;
                }
                true
            }
            Values::Join(first, rest) => first.excludes(range) && rest.excludes(range),
        }
    }
}

/// Whether `value` has the form 0x1f × N + 0x21, which each of the frame
/// type, setting, error code and stream type registries reserves to
/// exercise the requirement that unknown values be ignored ([RFC 9114 §7.2.8,
/// §7.2.4.1, §8.1, §6.2.3]). Such a value has no meaning, and no part
/// claims it.
///
/// [RFC 9114 §7.2.8, §7.2.4.1, §8.1, §6.2.3]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.8
pub const fn is_reserved(value: VarInt) -> bool {
    let value = value.get();
    value >= RESERVED_BASE && (value - RESERVED_BASE).is_multiple_of(RESERVED_STEP)
}

/// The reserved value 0x1f × `n` + 0x21, or `None` if it exceeds
/// [`VarInt::MAX`].
pub const fn reserved(n: u64) -> Option<VarInt> {
    let Some(scaled) = n.checked_mul(RESERVED_STEP) else {
        return None;
    };
    let Some(value) = scaled.checked_add(RESERVED_BASE) else {
        return None;
    };
    match VarInt::new(value) {
        Ok(value) => Some(value),
        Err(_) => None,
    }
}

const RESERVED_BASE: u64 = 0x21;
const RESERVED_STEP: u64 = 0x1f;

/// The smallest reserved value at or above `start`, saturating at
/// `u64::MAX`.
const fn first_reserved_from(start: u64) -> u64 {
    if start <= RESERVED_BASE {
        return RESERVED_BASE;
    }
    let offset = (start - RESERVED_BASE) % RESERVED_STEP;
    if offset == 0 {
        start
    } else {
        start.saturating_add(RESERVED_STEP - offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn v(value: u32) -> VarInt {
        VarInt::from_u32(value)
    }

    #[test]
    fn reserved_values_follow_the_formula() {
        assert!(is_reserved(v(0x21)));
        assert!(is_reserved(v(0x40)));
        assert!(!is_reserved(v(0x20)));
        assert!(!is_reserved(v(0x22)));
        assert!(!is_reserved(v(0)));
        assert_eq!(reserved(0), Some(v(0x21)));
        assert_eq!(reserved(1), Some(v(0x40)));
        let last = reserved((VarInt::MAX.get() - 0x21) / 0x1f).unwrap();
        assert!(is_reserved(last));
        assert_eq!(last.get(), 0x3fff_ffff_ffff_fffe);
        assert_eq!(reserved((VarInt::MAX.get() - 0x21) / 0x1f + 1), None);
        assert_eq!(reserved(u64::MAX), None);
    }

    #[test]
    fn ranges_are_checked_against_reserved_values() {
        static LOW: [RangeInclusive<VarInt>; 1] = [v(0x00)..=v(0x0d)];
        static ACROSS: [RangeInclusive<VarInt>; 1] = [v(0x22)..=v(0x40)];
        static BETWEEN: [RangeInclusive<VarInt>; 1] = [v(0x22)..=v(0x3f)];
        static EMPTY: [RangeInclusive<VarInt>; 1] = [v(0x40)..=v(0x21)];
        assert!(ClaimedValues::new(&LOW).avoids_reserved());
        assert!(!ClaimedValues::new(&ACROSS).avoids_reserved());
        assert!(ClaimedValues::new(&BETWEEN).avoids_reserved());
        assert!(ClaimedValues::new(&EMPTY).avoids_reserved());
    }

    #[test]
    fn joined_values_are_disjoint_only_if_every_part_is() {
        static A: [RangeInclusive<VarInt>; 2] = [v(0x00)..=v(0x01), v(0x07)..=v(0x07)];
        static B: [RangeInclusive<VarInt>; 1] = [v(0x02)..=v(0x06)];
        static C: [RangeInclusive<VarInt>; 1] = [v(0x06)..=v(0x08)];
        static AV: ClaimedValues = ClaimedValues::new(&A);
        static BV: ClaimedValues = ClaimedValues::new(&B);
        static CV: ClaimedValues = ClaimedValues::new(&C);
        assert!(AV.is_disjoint(&BV));
        assert!(!AV.is_disjoint(&CV));
        let joined = ClaimedValues::join(&AV, &BV);
        assert!(!joined.is_disjoint(&CV));
        assert!(!CV.is_disjoint(&joined));
        assert!(joined.contains(v(0x05)));
        assert!(!joined.contains(v(0x08)));
        assert!(ClaimedValues::NONE.is_disjoint(&joined));
    }
}

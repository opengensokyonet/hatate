//! Encoded field section prefix (RFC 9204 §4.5.1), read with zero maximum
//! dynamic table capacity.

use crate::integer::{self, PaddingError, PrefixedField};
use bytes::Buf;
use core::num::NonZeroU64;
use snafu::{ResultExt, Snafu};

/// A field section prefix with the details of its encoding: Encoded Insert
/// Count, the sign bit and Delta Base, each integer with its padding.
///
/// The default is the zero prefix `00 00`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SectionPrefix {
    encoded_insert_count: PrefixedField,
    negative: bool,
    delta_base: PrefixedField,
}

impl SectionPrefix {
    /// A prefix of an Encoded Insert Count in an 8-bit prefix, the sign bit
    /// and a Delta Base in a 7-bit prefix.
    ///
    /// # Errors
    ///
    /// [`PaddingError`] if either integer's padding has no encoding at its
    /// prefix width.
    pub fn new(
        encoded_insert_count: PrefixedField,
        negative: bool,
        delta_base: PrefixedField,
    ) -> Result<Self, PaddingError> {
        encoded_insert_count.check::<8>()?;
        delta_base.check::<7>()?;
        Ok(Self {
            encoded_insert_count,
            negative,
            delta_base,
        })
    }

    /// The Encoded Insert Count.
    pub const fn encoded_insert_count(&self) -> PrefixedField {
        self.encoded_insert_count
    }

    /// The sign bit: whether Base lies below the Required Insert Count.
    pub const fn is_negative(&self) -> bool {
        self.negative
    }

    /// The Delta Base.
    pub const fn delta_base(&self) -> PrefixedField {
        self.delta_base
    }
}

/// An invalid static-mode field section prefix.
#[derive(Debug, Snafu)]
pub enum PrefixError {
    /// No Encoded Insert Count octet.
    #[snafu(display("missing encoded insert count"))]
    MissingInsertCount,
    /// Invalid continuation of the Encoded Insert Count.
    #[snafu(display("invalid encoded insert count"))]
    InsertCount {
        /// The integer decoding failure.
        source: integer::ReadError,
    },
    /// The nonzero encoded count cannot occur with a zero-capacity table.
    #[snafu(display("encoded insert count {count} exceeds the zero-capacity table range"))]
    NonzeroInsertCount {
        /// The received nonzero count.
        count: NonZeroU64,
    },
    /// No Delta Base octet.
    #[snafu(display("missing delta base"))]
    MissingDeltaBase,
    /// Invalid continuation of Delta Base.
    #[snafu(display("invalid delta base"))]
    DeltaBase {
        /// The integer decoding failure.
        source: integer::ReadError,
    },
    /// The sign bit denotes a negative Base.
    #[snafu(display("negative base for a zero required insert count"))]
    NegativeBase,
}

pub(super) fn read(src: &mut impl Buf) -> Result<SectionPrefix, PrefixError> {
    let first = src
        .try_get_u8()
        .map_err(|_| PrefixError::MissingInsertCount)?;
    let encoded_insert_count = integer::read::<8>(first, src).context(InsertCountSnafu)?;
    if let Some(count) = NonZeroU64::new(encoded_insert_count.value().get()) {
        return Err(PrefixError::NonzeroInsertCount { count });
    }
    let first = src
        .try_get_u8()
        .map_err(|_| PrefixError::MissingDeltaBase)?;
    let delta_base = integer::read::<7>(first, src).context(DeltaBaseSnafu)?;
    // Required Insert Count is zero. A clear sign bit permits every
    // representable Delta Base; a set sign bit would yield -DeltaBase - 1.
    if first & 0x80 != 0 {
        return Err(PrefixError::NegativeBase);
    }
    Ok(SectionPrefix {
        encoded_insert_count,
        negative: false,
        delta_base,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integer::PrefixedInt;
    use alloc::vec::Vec;

    #[test]
    fn accepts_nonnegative_base_and_stops_before_the_first_line() {
        for delta in [0, 1, 126, 127, (1 << 62) - 1, u64::MAX] {
            let delta = PrefixedField::shortest(PrefixedInt::from(delta));
            let mut wire = Vec::from([0]);
            integer::write::<7, _>(&mut wire, 0, delta).unwrap();
            wire.push(0xd1);
            let mut rest = wire.as_slice();
            let prefix = read(&mut rest).unwrap();
            assert_eq!(prefix.delta_base(), delta);
            assert!(!prefix.is_negative());
            assert_eq!(rest, [0xd1]);
        }
        // Delta Base 127 with a redundant zero continuation.
        let mut rest = &[0x00, 0x7f, 0x80, 0x00, 0xd1][..];
        let prefix = read(&mut rest).unwrap();
        assert_eq!(
            prefix.delta_base(),
            PrefixedField::new::<7>(PrefixedInt::from(127u8), 1).unwrap()
        );
        assert_eq!(rest, [0xd1]);
    }

    #[test]
    fn rejects_nonzero_insert_count_and_negative_base() {
        for (wire, expected) in [(&[1][..], 1), (&[0xff, 0][..], 255)] {
            assert!(
                matches!(read(&mut &*wire), Err(PrefixError::NonzeroInsertCount { count }) if count.get() == expected)
            );
        }
        for wire in [&[0, 0x80][..], &[0, 0xff, 0][..]] {
            assert!(matches!(read(&mut &*wire), Err(PrefixError::NegativeBase)));
        }
    }

    #[test]
    fn identifies_truncation_and_integer_limits_at_the_correct_prefix_field() {
        assert!(matches!(
            read(&mut &[][..]),
            Err(PrefixError::MissingInsertCount)
        ));
        assert!(matches!(
            read(&mut &[0xff][..]),
            Err(PrefixError::InsertCount {
                source: integer::ReadError::Incomplete
            })
        ));
        assert!(matches!(
            read(&mut &[0][..]),
            Err(PrefixError::MissingDeltaBase)
        ));
        assert!(matches!(
            read(&mut &[0, 0x7f][..]),
            Err(PrefixError::DeltaBase {
                source: integer::ReadError::Incomplete
            })
        ));
        let mut wire = Vec::from([0, 0x7f]);
        wire.extend_from_slice(&[0x80; 10]);
        wire.push(0);
        let mut rest = wire.as_slice();
        assert!(matches!(
            read(&mut rest),
            Err(PrefixError::DeltaBase {
                source: integer::ReadError::TooLong
            })
        ));
        assert_eq!(rest, [0]);
    }

    #[test]
    fn construction_checks_each_integer_at_its_prefix_width() {
        let zero = PrefixedField::shortest(PrefixedInt::ZERO);
        assert_eq!(
            SectionPrefix::new(zero, false, zero),
            Ok(SectionPrefix::default())
        );
        // 200 fits in the eight-bit prefix but needs a continuation in seven bits.
        let padded = PrefixedField::new::<7>(PrefixedInt::from(200u8), 1).unwrap();
        assert!(SectionPrefix::new(zero, true, padded).is_ok());
        let error = SectionPrefix::new(padded, false, zero).unwrap_err();
        assert_eq!(error.prefix_bits(), 8);
    }
}

//! Encoded field section prefix with zero maximum dynamic table capacity
//! (RFC 9204 §4.5.1).

use crate::{InsufficientCapacityError, integer};
use bytes::{Buf, BufMut};
use core::num::NonZeroU64;
use snafu::{ResultExt, Snafu};

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

pub(super) fn read(src: &mut impl Buf) -> Result<(), PrefixError> {
    let first = src
        .try_get_u8()
        .map_err(|_| PrefixError::MissingInsertCount)?;
    let encoded = integer::read::<8>(first, src).context(InsertCountSnafu)?;
    if let Some(count) = NonZeroU64::new(encoded) {
        return Err(PrefixError::NonzeroInsertCount { count });
    }
    let first = src
        .try_get_u8()
        .map_err(|_| PrefixError::MissingDeltaBase)?;
    integer::read::<7>(first, src).context(DeltaBaseSnafu)?;
    // Required Insert Count is zero. A clear sign bit permits every
    // representable Delta Base; a set sign bit would yield -DeltaBase - 1.
    if first & 0x80 != 0 {
        return Err(PrefixError::NegativeBase);
    }
    Ok(())
}

pub(super) const ENCODED: [u8; 2] = [0, 0];

pub(super) fn write(dst: &mut impl BufMut) -> Result<(), InsufficientCapacityError> {
    InsufficientCapacityError::check(ENCODED.len() as u128, dst.remaining_mut())?;
    dst.put_slice(&ENCODED);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn accepts_nonnegative_base_and_stops_before_the_first_line() {
        for delta in [0, 1, 126, 127, (1 << 62) - 1, u64::MAX] {
            let mut wire = Vec::from([0]);
            integer::write::<7>(&mut wire, 0, delta).unwrap();
            wire.push(0xd1);
            let mut rest = wire.as_slice();
            read(&mut rest).unwrap();
            assert_eq!(rest, [0xd1]);
        }
        // Delta Base 127 with a redundant zero continuation.
        let mut rest = &[0x00, 0x7f, 0x80, 0x00, 0xd1][..];
        read(&mut rest).unwrap();
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
    fn writes_the_canonical_prefix_as_a_unit() {
        for capacity in 0..=2 {
            let mut storage = [0xa5; 2];
            let mut dst = &mut storage[..capacity];
            if capacity == 2 {
                write(&mut dst).unwrap();
                assert!(dst.is_empty());
                assert_eq!(storage, [0, 0]);
            } else {
                let err = write(&mut dst).unwrap_err();
                assert_eq!((err.required(), err.available()), (2, capacity));
                assert_eq!(dst.len(), capacity);
                assert_eq!(storage, [0xa5; 2]);
            }
        }
    }
}

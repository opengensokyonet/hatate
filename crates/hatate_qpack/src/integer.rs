//! Prefixed integers (RFC 9204 §4.1.1 and RFC 7541 §5.1).

use crate::InsufficientCapacityError;
use bytes::{Buf, BufMut};
use snafu::Snafu;

/// Failure to read a QPACK prefixed integer after its first octet.
#[derive(Debug, PartialEq, Eq, Snafu)]
pub enum ReadError {
    /// The encoding ends before its terminating octet.
    #[snafu(display("missing continuation octet of prefixed integer"))]
    Incomplete,
    /// The numeric value exceeds u64::MAX.
    #[snafu(display("prefixed integer exceeds 64 bits"))]
    Overflow,
    /// The encoding needs more than ten continuation octets.
    #[snafu(display("prefixed integer exceeds ten continuation octets"))]
    TooLong,
}

const fn prefix_mask<const N: u8>() -> u8 {
    const { assert!(N >= 1 && N <= 8) };
    u8::MAX >> (8 - N)
}

/// Read a prefixed integer given the already-consumed first octet. Its low
/// `N` bits belong to the integer (`1..=8`, checked at compile time).
/// The implementation accepts values through `u64::MAX` and at most ten
/// continuation octets in addition to `first`. Non-minimal encodings within
/// both limits are accepted. A digit that would exceed the numeric range is
/// [`ReadError::Overflow`]. If the tenth continuation octet still requests a
/// further octet, the encoding is [`ReadError::TooLong`] unless that digit
/// already overflowed the value. Only continuation octets are consumed from
/// `src`, including on error; an eleventh continuation octet is never read.
pub fn read<const N: u8>(first: u8, src: &mut impl Buf) -> Result<u64, ReadError> {
    use core::ops::ControlFlow;
    let mut continuation = match Continuation::start::<N>(first) {
        ControlFlow::Break(value) => return Ok(value),
        ControlFlow::Continue(state) => state,
    };
    loop {
        let byte = src.try_get_u8().map_err(|_| ReadError::Incomplete)?;
        if let Some(value) = continuation.push(byte)? {
            return Ok(value);
        }
    }
}

/// The digits of one prefixed integer, shared with instruction streams where
/// a read may suspend between any two octets.
pub(crate) struct Continuation {
    value: u64,
    shift: u32,
}

impl Continuation {
    pub(crate) fn start<const N: u8>(first: u8) -> core::ops::ControlFlow<u64, Self> {
        use core::ops::ControlFlow;
        let mask = prefix_mask::<N>();
        let value = u64::from(first & mask);
        if value < u64::from(mask) {
            ControlFlow::Break(value)
        } else {
            ControlFlow::Continue(Self { value, shift: 0 })
        }
    }

    /// Stop feeding octets at either a result or an error.
    pub(crate) fn push(&mut self, byte: u8) -> Result<Option<u64>, ReadError> {
        let digit = u64::from(byte & 0x7f);
        if digit > (u64::MAX - self.value) >> self.shift {
            return Err(ReadError::Overflow);
        }
        self.value += digit << self.shift;
        if byte & 0x80 == 0 {
            return Ok(Some(self.value));
        }
        if self.shift == 63 {
            return Err(ReadError::TooLong);
        }
        self.shift += 7;
        Ok(None)
    }
}

/// One prefix octet and at most ten base-128 digits for a u64.
pub(crate) const MAX_ENCODED_LEN: usize = 11;

/// Write the shortest encoding, keeping the high `8 - N` bits of `first`
/// and replacing its low `N` bits. The width is in `1..=8` (checked at
/// compile time). If the complete integer cannot fit, leave `dst` unchanged.
pub fn write<const N: u8>(
    dst: &mut impl BufMut,
    first: u8,
    value: u64,
) -> Result<(), InsufficientCapacityError> {
    let mask = prefix_mask::<N>();
    let flags = first & !mask;
    if value < u64::from(mask) {
        InsufficientCapacityError::check(1, dst.remaining_mut())?;
        dst.put_u8(flags | value as u8);
        return Ok(());
    }
    let mut remaining = value - u64::from(mask);
    // Zero after a full prefix still occupies one continuation octet.
    let digits = (u64::BITS - remaining.leading_zeros()).max(1).div_ceil(7);
    InsufficientCapacityError::check(1 + u128::from(digits), dst.remaining_mut())?;
    dst.put_u8(flags | mask);
    while remaining >= 128 {
        dst.put_u8((remaining as u8 & 0x7f) | 0x80);
        remaining >>= 7;
    }
    dst.put_u8(remaining as u8);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn appendix_c_examples() {
        fn check<const N: u8>(value: u64, bytes: &[u8]) {
            let mut output = BytesMut::new();
            write::<N>(&mut output, 0, value).unwrap();
            assert_eq!(&output[..], bytes);
            let mut rest = &bytes[1..];
            assert_eq!(read::<N>(bytes[0], &mut rest), Ok(value));
            assert!(rest.is_empty());
        }
        check::<5>(10, &[10]);
        check::<5>(1337, &[0x1f, 0x9a, 0x0a]);
        check::<8>(42, &[42]);
    }

    #[test]
    fn boundary_keeps_flags_and_next_octet() {
        let mut output = BytesMut::new();
        write::<3>(&mut output, 0x50, 7).unwrap();
        assert_eq!(&output[..], &[0x57, 0]);
        let mut rest = &[0x80, 0, 0xa5][..];
        assert_eq!(read::<3>(0x57, &mut rest), Ok(7));
        assert_eq!(rest, &[0xa5]);
    }

    #[test]
    fn largest_supported_values_and_all_prefix_widths() {
        fn check<const N: u8>() {
            for value in [0, 1, 127, 255, (1 << 62) - 1, u64::MAX] {
                let mut encoded = BytesMut::new();
                write::<N>(&mut encoded, 0, value).unwrap();
                let mut rest = &encoded[1..];
                assert_eq!(read::<N>(encoded[0], &mut rest), Ok(value));
                assert!(rest.is_empty());
            }
        }
        check::<1>();
        check::<2>();
        check::<3>();
        check::<4>();
        check::<5>();
        check::<6>();
        check::<7>();
        check::<8>();
    }

    #[test]
    fn distinguishes_incomplete_overflow_and_length_limit() {
        assert_eq!(read::<8>(255, &mut &[][..]), Err(ReadError::Incomplete));
        let mut too_large = [0xff; 10];
        too_large[9] = 1;
        assert_eq!(
            read::<8>(255, &mut &too_large[..]),
            Err(ReadError::Overflow)
        );
        let mut overlong = &[0x80; 11][..];
        assert_eq!(read::<1>(1, &mut overlong), Err(ReadError::TooLong));
        assert_eq!(overlong.len(), 1);
    }
}

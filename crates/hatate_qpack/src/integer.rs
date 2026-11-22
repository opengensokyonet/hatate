//! Prefixed integers (RFC 9204 §4.1.1 and RFC 7541 §5.1).

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

/// The caller has already consumed the first octet to dispatch on its flags.
pub(crate) fn read<const N: u8>(first: u8, src: &mut impl Buf) -> Result<u64, ReadError> {
    let mask = prefix_mask::<N>();
    let mut value = u64::from(first & mask);
    if value < u64::from(mask) {
        return Ok(value);
    }
    for shift in (0..64).step_by(7) {
        let byte = src.try_get_u8().map_err(|_| ReadError::Incomplete)?;
        let digit = u64::from(byte & 0x7f);
        if digit > (u64::MAX - value) >> shift {
            return Err(ReadError::Overflow);
        }
        value += digit << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(ReadError::TooLong)
}

/// Write the prefix into the low N bits; the enclosing format supplies the
/// flags in the other bits and space in the destination.
pub(crate) fn write<const N: u8>(dst: &mut impl BufMut, flags: u8, value: u64) {
    let mask = prefix_mask::<N>();
    debug_assert_eq!(flags & mask, 0);
    if value < u64::from(mask) {
        dst.put_u8(flags | value as u8);
        return;
    }
    dst.put_u8(flags | mask);
    let mut remaining = value - u64::from(mask);
    while remaining >= 128 {
        dst.put_u8((remaining as u8 & 0x7f) | 0x80);
        remaining >>= 7;
    }
    dst.put_u8(remaining as u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn appendix_c_examples() {
        fn check<const N: u8>(value: u64, bytes: &[u8]) {
            let mut output = BytesMut::new();
            write::<N>(&mut output, 0, value);
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
        write::<3>(&mut output, 0x50, 7);
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
                write::<N>(&mut encoded, 0, value);
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

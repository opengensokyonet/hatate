use super::*;
use bytes::BytesMut;

fn int(value: u64) -> PrefixedField {
    PrefixedField::shortest(PrefixedInt::from(value))
}

#[test]
fn appendix_c_examples() {
    fn check<const N: u8>(value: u64, bytes: &[u8]) {
        let mut output = BytesMut::new();
        write::<N, _>(&mut output, 0, int(value)).unwrap();
        assert_eq!(&output[..], bytes);
        let mut rest = &bytes[1..];
        assert_eq!(read::<N>(bytes[0], &mut rest), Ok(int(value)));
        assert!(rest.is_empty());
    }
    check::<5>(10, &[10]);
    check::<5>(1337, &[0x1f, 0x9a, 0x0a]);
    check::<8>(42, &[42]);
}

#[test]
fn boundary_keeps_flags_and_next_octet() {
    let mut output = BytesMut::new();
    write::<3, _>(&mut output, 0x50, int(7)).unwrap();
    assert_eq!(&output[..], &[0x57, 0]);
    let mut rest = &[0x80, 0, 0xa5][..];
    let field = read::<3>(0x57, &mut rest).unwrap();
    assert_eq!((field.value().get(), field.padding()), (7, 1));
    assert_eq!(rest, &[0xa5]);
}

#[test]
fn largest_supported_values_and_all_prefix_widths() {
    fn check<const N: u8>() {
        for value in [0, 1, 127, 255, (1 << 62) - 1, u64::MAX] {
            let mut encoded = BytesMut::new();
            write::<N, _>(&mut encoded, 0, int(value)).unwrap();
            assert_eq!(encoded.len(), int(value).encoded_len::<N>());
            let mut rest = &encoded[1..];
            assert_eq!(read::<N>(encoded[0], &mut rest), Ok(int(value)));
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

#[test]
fn padded_encodings_read_back_and_write_their_original_octets() {
    // 1337 in a five-bit prefix, then one and then seven extra zero groups.
    for (wire, padding) in [
        (&[0xbf, 0x9a, 0x8a, 0x00][..], 1),
        (
            &[0xbf, 0x9a, 0x8a, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00],
            7,
        ),
    ] {
        let mut rest = &wire[1..];
        let field = read::<5>(wire[0], &mut rest).unwrap();
        assert!(rest.is_empty());
        assert_eq!((field.value().get(), field.padding()), (1337, padding));
        assert_eq!(field.encoded_len::<5>(), wire.len());
        assert_eq!(
            field,
            PrefixedField::new::<5>(PrefixedInt::from(1337u16), padding).unwrap()
        );
        let mut output = BytesMut::new();
        write::<5, _>(&mut output, 0xa0, field).unwrap();
        assert_eq!(&output[..], wire);
    }
}

#[test]
fn padding_is_rejected_where_the_value_fits_the_prefix_or_the_encoding_is_too_long() {
    let small = PrefixedInt::from(62u8);
    let error = PrefixedField::new::<6>(small, 1).unwrap_err();
    assert_eq!(
        (error.value(), error.padding(), error.prefix_bits()),
        (small, 1, 6)
    );
    assert!(PrefixedField::new::<6>(PrefixedInt::from(63u8), 9).is_ok());
    assert!(PrefixedField::new::<6>(PrefixedInt::from(63u8), 10).is_err());
    assert!(PrefixedField::new::<1>(PrefixedInt::MAX, 0).is_ok());
    assert!(PrefixedField::new::<1>(PrefixedInt::MAX, 1).is_err());
    assert!(PrefixedField::new::<1>(PrefixedInt::from(1u8), u8::MAX).is_err());
    // Valid with a four-bit prefix, but 20 fits in six bits.
    let moved = PrefixedField::new::<4>(PrefixedInt::from(20u8), 1).unwrap();
    let mut output = [0x55; 3];
    let mut dst = &mut output[..];
    assert!(matches!(
        write::<6, _>(&mut dst, 0, moved),
        Err(WriteError::Padding { source }) if source.prefix_bits() == 6
    ));
    assert_eq!(output, [0x55; 3]);
}

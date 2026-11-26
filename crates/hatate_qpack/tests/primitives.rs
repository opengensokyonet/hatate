use bytes::{Buf, BytesMut};
use hatate_qpack::{
    huffman,
    integer::{self, PrefixedField, PrefixedInt},
};

fn int(value: u64) -> PrefixedField {
    PrefixedField::shortest(PrefixedInt::from(value))
}

#[test]
fn prefixed_integer_after_dispatch() {
    // RFC 7541 Appendix C.1.2, with an enclosing format in the top three bits.
    let mut dst = [0; 3];
    integer::write::<5, _>(&mut &mut dst[..], 0xa2, int(1337)).unwrap();
    assert_eq!(dst, [0xbf, 0x9a, 0x0a]);
    let mut rest = &[0x9a, 0x0a, 0xe1][..];
    assert_eq!(integer::read::<5>(0xbf, &mut rest), Ok(int(1337)));
    assert_eq!(rest, [0xe1]);
}

#[test]
fn integer_capacity_failures_leave_the_destination_untouched() {
    for (field, len) in [
        (int(0), 1),
        (int(255), 2),
        (int(255 + 127), 2),
        (int(255 + 128), 3),
        (int(u64::MAX), 11),
        (
            PrefixedField::new::<8>(PrefixedInt::from(255u8), 3).unwrap(),
            5,
        ),
    ] {
        assert_eq!(field.encoded_len::<8>(), len);
        for capacity in 0..len {
            let mut storage = [0xcc; 11];
            let mut dst = &mut storage[..capacity];
            let integer::WriteError::InsufficientCapacity { source } =
                integer::write::<8, _>(&mut dst, 0xff, field).unwrap_err()
            else {
                panic!("expected a capacity error")
            };
            assert_eq!(source.required(), len as u128);
            assert_eq!(source.available(), capacity);
            assert_eq!(dst.len(), capacity);
            assert_eq!(storage, [0xcc; 11]);
        }
        let mut storage = [0; 11];
        let mut exact = &mut storage[..len];
        integer::write::<8, _>(&mut exact, 0xff, field).unwrap();
        assert!(exact.is_empty());
        assert_eq!(
            integer::read::<8>(storage[0], &mut &storage[1..len]),
            Ok(field)
        );
    }
}

#[test]
fn standalone_huffman_respects_both_bounds_and_decodes_segmented_input() {
    // Eight '0' symbols use exactly forty bits.
    let input = &b"00000000"[..];
    let mut short = [0x55; 4];
    let mut dst = &mut short[..];
    let error = huffman::encode(&mut dst, input).unwrap_err();
    assert_eq!((error.required(), error.available()), (5, 4));
    assert_eq!(dst.len(), 4);
    assert_eq!(short, [0x55; 4]);

    // Five octets are below the 30-bit bound of eight symbols, so this
    // takes the measured path.
    let mut wire = [0xff; 5];
    huffman::encode(&mut &mut wire[..], input).unwrap();
    assert_eq!(wire, [0; 5]);
    let decoded: Vec<u8> = huffman::decode(wire[..2].chain(&wire[2..]), 8).unwrap();
    assert_eq!(decoded, input);
    let decoded: BytesMut = huffman::decode(&wire[..], 8).unwrap();
    assert_eq!(&decoded[..], input);
    assert_eq!(
        huffman::decode::<Vec<u8>>(&wire[..], 7),
        Err(huffman::DecodeError::OutputTooLong { limit: 7 })
    );
    assert_eq!(
        huffman::decode::<Vec<u8>>(&[0xff; 4][..], 8),
        Err(huffman::DecodeError::EndOfString)
    );
    huffman::encode(&mut &mut [0u8; 0][..], &b""[..]).unwrap();
    assert!(huffman::decode::<Vec<u8>>(&[][..], 0).unwrap().is_empty());
    // Segmented input to the encoder.
    let mut segmented = Vec::new();
    huffman::encode(&mut segmented, input[..3].chain(&input[3..])).unwrap();
    assert_eq!(segmented, [0; 5]);
}

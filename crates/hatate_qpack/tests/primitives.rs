use bytes::Buf;
use hatate_qpack::{huffman, integer};

#[test]
fn prefixed_integer_after_dispatch() {
    // RFC 7541 Appendix C.1.2, with an enclosing format in the top three bits.
    let mut dst = [0; 3];
    integer::write::<5>(&mut &mut dst[..], 0xa2, 1337).unwrap();
    assert_eq!(dst, [0xbf, 0x9a, 0x0a]);
    let mut rest = &[0x9a, 0x0a, 0xe1][..];
    assert_eq!(integer::read::<5>(0xbf, &mut rest), Ok(1337));
    assert_eq!(rest, [0xe1]);
}

#[test]
fn integer_capacity_failures_leave_the_destination_untouched() {
    for (value, len) in [
        (0, 1),
        (255, 2),
        (255 + 127, 2),
        (255 + 128, 3),
        (u64::MAX, 11),
    ] {
        for capacity in 0..len {
            let mut storage = [0xcc; 11];
            let mut dst = &mut storage[..capacity];
            let error = integer::write::<8>(&mut dst, 0xff, value).unwrap_err();
            assert_eq!(error.required(), len as u128);
            assert_eq!(error.available(), capacity);
            assert_eq!(dst.len(), capacity);
            assert_eq!(storage, [0xcc; 11]);
        }
        let mut storage = [0; 11];
        let mut exact = &mut storage[..len];
        integer::write::<8>(&mut exact, 0xff, value).unwrap();
        assert!(exact.is_empty());
        assert_eq!(
            integer::read::<8>(storage[0], &mut &storage[1..len]),
            Ok(value)
        );
    }
}

#[test]
fn standalone_huffman_respects_both_bounds_and_decodes_segmented_input() {
    // Eight '0' symbols use exactly forty bits.
    let input = b"00000000";
    let mut short = [0x55; 4];
    let mut dst = &mut short[..];
    let error = huffman::encode(&mut dst, input).unwrap_err();
    assert_eq!((error.required(), error.available()), (5, 4));
    assert_eq!(dst.len(), 4);
    assert_eq!(short, [0x55; 4]);

    let mut wire = [0xff; 5];
    huffman::encode(&mut &mut wire[..], input).unwrap();
    assert_eq!(wire, [0; 5]);
    assert_eq!(
        huffman::decode(wire[..2].chain(&wire[2..]), 8)
            .unwrap()
            .as_ref(),
        input
    );
    assert_eq!(
        huffman::decode(&wire[..], 7),
        Err(huffman::DecodeError::OutputTooLong { limit: 7 })
    );
    assert_eq!(
        huffman::decode(&[0xff; 4][..], 8),
        Err(huffman::DecodeError::EndOfString)
    );
    huffman::encode(&mut &mut [0u8; 0][..], b"").unwrap();
    assert!(huffman::decode(&[][..], 0).unwrap().is_empty());
}

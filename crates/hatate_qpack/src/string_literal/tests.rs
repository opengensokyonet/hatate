use super::*;
use crate::test_support::{huffman as coded, now, raw};
use alloc::vec::Vec;

#[test]
fn constructors_record_the_shortest_length_and_the_decoded_length() {
    let plain: StringLiteral<&[u8], Vec<u8>> = raw(&b"custom-key"[..]);
    assert!(!plain.is_huffman());
    assert_eq!(
        plain.length(),
        PrefixedField::shortest(PrefixedInt::from(10u8))
    );
    assert_eq!(plain.decoded_len(), 10);
    assert_eq!(plain.wire_len::<7>(), 11);
    assert_eq!(plain.bytes(), LiteralBytes::Raw(&&b"custom-key"[..]));

    // RFC 7541 C.4.1: the hostname encodes to twelve octets.
    let coded: StringLiteral<Bytes, &[u8]> = coded(&b"www.example.com"[..]);
    assert!(coded.is_huffman());
    assert_eq!(coded.length().value().get(), 12);
    assert_eq!(coded.decoded_len(), 15);
    // Twelve does not fit a three-bit prefix: one continuation octet.
    assert_eq!(coded.wire_len::<3>(), 14);
    assert_eq!(coded.as_ref(), b"www.example.com");
}

#[test]
fn length_padding_is_checked_at_the_given_width() {
    let literal: StringLiteral<&[u8], Vec<u8>> = raw(&[b'x'; 7][..]);
    assert!(literal.clone().with_length_padding::<7>(1).is_err());
    let padded = literal.with_length_padding::<3>(2).unwrap();
    assert_eq!(padded.length().padding(), 2);
    assert_eq!(padded.wire_len::<3>(), 4 + 7);
}

#[test]
fn a_failing_encoded_len_is_reported() {
    struct Unknown;
    impl EncodedLen for Unknown {
        type LengthError = &'static str;
        async fn encoded_len(&mut self) -> Result<u64, &'static str> {
            Err("reset")
        }
    }
    assert!(matches!(
        now(StringLiteral::<Unknown, Vec<u8>>::raw(Unknown)),
        Err(LiteralLengthError::Length { source: "reset" })
    ));
}

#[test]
fn joined_bytes_keep_a_single_chunk_and_copy_from_the_second() {
    let first = Bytes::from_static(b"abc");
    let mut joined = JoinedBytes::default();
    joined.extend([Bytes::new(), first.clone(), Bytes::new()]);
    assert_eq!(joined.as_ref().as_ptr(), first.as_ptr());
    assert_eq!(now(joined.encoded_len()), Ok(3));
    joined.extend([Bytes::from_static(b"de")]);
    assert_eq!(joined.as_ref(), b"abcde");
    assert_ne!(joined.as_ref().as_ptr(), first.as_ptr());
    let whole = Bytes::from_static(b"abcde");
    let mut single = JoinedBytes::default();
    single.extend([whole.clone()]);
    assert_eq!(single, joined);
    assert_eq!(single.into_bytes().as_ptr(), whole.as_ptr());
    joined.advance(1);
    assert_eq!((joined.remaining(), joined.chunk()), (4, &b"bcde"[..]));
    assert_eq!(joined.into_bytes(), &b"bcde"[..]);
}

#[test]
fn copied_bytes_collect_borrowed_chunks() {
    let mut copied = CopiedBytes::default();
    copied.extend([&b"ab"[..], &b""[..], &b"c"[..]]);
    assert_eq!(copied.as_ref(), b"abc");
    assert_eq!(now(copied.encoded_len()), Ok(3));
    copied.advance(2);
    assert_eq!((copied.remaining(), copied.chunk()), (1, &b"c"[..]));
    assert_eq!(copied.into_bytes(), &b"c"[..]);
}

#[test]
fn a_payload_that_changed_since_construction_is_rejected() {
    let mut literal: StringLiteral<&[u8], &[u8]> = raw(&b"abc"[..]);
    if let Repr::Raw { bytes, .. } = &mut literal.0 {
        *bytes = &b"ab"[..];
    }
    assert_eq!(
        literal.into_wire::<7>().unwrap_err(),
        WriteError::PayloadLength {
            expected: 3,
            actual: 2
        }
    );
}

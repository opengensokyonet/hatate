use super::*;
use crate::huffman;
use crate::integer::PrefixedInt;
use crate::string_literal::LiteralBytes;
use crate::test_support::{huffman as coded, raw};
use alloc::{vec, vec::Vec};
use bytes::BytesMut;

type Line<'a> = FieldLine<&'a [u8], BytesMut>;

fn read<'a>(src: &mut &'a [u8], limit: usize) -> Result<Line<'a>, ReadError> {
    read_field_line(src, limit)
}

fn write(line: Line<'_>) -> BytesMut {
    let mut output = BytesMut::new();
    write_field_line(&mut output, line).unwrap();
    output
}

fn int(value: u64) -> PrefixedField {
    PrefixedField::shortest(PrefixedInt::from(value))
}

fn static_index(number: u64) -> TableIndex {
    TableIndex::Static {
        index: PrefixedField::shortest(Index::try_from(number).unwrap()),
    }
}

#[test]
fn published_field_lines_leave_the_next_line() {
    // RFC 9204 Appendix B.1 and B.2, after their field section prefixes.
    let input = &b"\x51\x0b/index.html\x10\x11"[..];
    let mut rest = input;
    let line = read(&mut rest, 11).unwrap();
    let FieldLine::LiteralWithNameReference {
        never_index: false,
        name: TableIndex::Static { index },
        value,
    } = &line
    else {
        panic!("expected an uncompressed static-name literal")
    };
    assert_eq!(index.value().entry().0, b":path");
    let LiteralBytes::Raw(bytes) = value.bytes() else {
        panic!("expected a raw literal")
    };
    assert_eq!(*bytes, b"/index.html");
    assert_eq!(bytes.as_ptr(), input[2..].as_ptr());
    let mut written = write(line);
    for index in [0, 1] {
        let next = read(&mut rest, 0).unwrap();
        assert_eq!(
            next,
            FieldLine::Indexed {
                index: TableIndex::PostBase { index: int(index) }
            }
        );
        written.extend_from_slice(&write(next));
    }
    assert!(rest.is_empty());
    assert_eq!(&written[..], input);
}

#[test]
fn static_relative_and_post_base_indices() {
    for (index, wire) in [
        (static_index(17), &[0xd1][..]),
        (static_index(98), &[0xff, 35]),
        (TableIndex::Relative { index: int(63) }, &[0xbf, 0]),
        (TableIndex::PostBase { index: int(16) }, &[0x1f, 1]),
    ] {
        let line = Line::Indexed { index };
        let output = write(line.clone());
        assert_eq!(&output[..], wire);
        assert_eq!(read(&mut &output[..], 0).unwrap(), line);
    }
}

#[test]
fn literal_name_references_keep_the_n_and_h_bits_independent() {
    for (prefix, index) in [
        (0x51, static_index(1)),
        (0x41, TableIndex::Relative { index: int(1) }),
        (0x01, TableIndex::PostBase { index: int(1) }),
    ] {
        for never_index in [false, true] {
            for huffman in [false, true] {
                let n_mask = if prefix == 1 { 8 } else { 32 };
                let wire = [
                    prefix | if never_index { n_mask } else { 0 },
                    if huffman { 0x81 } else { 1 },
                    if huffman { 0x1f } else { b'a' },
                ];
                let line = read(&mut &wire[..], 1).unwrap();
                let FieldLine::LiteralWithNameReference {
                    name,
                    value,
                    never_index: bit,
                } = &line
                else {
                    panic!()
                };
                assert_eq!(*bit, never_index);
                assert_eq!(*name, index);
                assert_eq!(value.as_ref(), b"a");
                assert_eq!(value.is_huffman(), huffman);
                assert_eq!(&write(line)[..], &wire);
            }
        }
    }
}

#[test]
fn literal_name_and_value_each_choose_their_encoding_and_limit() {
    for name_h in [false, true] {
        for value_h in [false, true] {
            for n in [false, true] {
                let first = 0x21 | u8::from(n) << 4 | u8::from(name_h) << 3;
                let wire = [
                    first,
                    if name_h { 0x1f } else { b'a' },
                    1 | u8::from(value_h) << 7,
                    if value_h { 0x1f } else { b'a' },
                ];
                let mut src = &wire[..];
                let line = read(&mut src, 1).unwrap();
                let FieldLine::LiteralWithLiteralName {
                    never_index,
                    name,
                    value,
                } = &line
                else {
                    panic!()
                };
                assert_eq!(*never_index, n);
                assert_eq!(name.as_ref(), b"a");
                assert_eq!(value.as_ref(), b"a");
                assert_eq!(name.is_huffman(), name_h);
                assert_eq!(value.is_huffman(), value_h);
                assert_eq!(&write(line)[..], &wire);
                assert!(src.is_empty());
            }
        }
    }
    let empty = read(&mut &[0x38, 0x80][..], 0).unwrap();
    assert_eq!(&write(empty)[..], &[0x38, 0x80]);
}

#[test]
fn input_storage_and_octets_are_preserved_for_raw_literals() {
    let input = Bytes::from_static(b"\x21A\x01\xff");
    let mut rest = input.clone();
    let FieldLine::<Bytes, Vec<u8>>::LiteralWithLiteralName { name, value, .. } =
        read_field_line(&mut rest, 1).unwrap()
    else {
        panic!()
    };
    let (LiteralBytes::Raw(name), LiteralBytes::Raw(value)) =
        (name.into_bytes(), value.into_bytes())
    else {
        panic!()
    };
    assert_eq!(name, &b"A"[..]);
    assert_eq!(value, &[0xff][..]);
    assert_eq!(name.as_ptr(), input[1..].as_ptr());
    assert_eq!(value.as_ptr(), input[3..].as_ptr());
}

#[test]
fn invalid_static_indices_differ_from_unresolved_dynamic_references() {
    assert_eq!(Index::try_from(99).unwrap_err().index(), 99);
    assert!(matches!(
        read(&mut &[0xff, 36][..], 0),
        Err(ReadError::StaticField { .. })
    ));
    assert!(matches!(
        read(&mut &[0x5f, 84][..], 0),
        Err(ReadError::StaticName { .. })
    ));
    let expected = Line::Indexed {
        index: TableIndex::Relative {
            index: int((1 << 62) - 1),
        },
    };
    let wire = write(expected.clone());
    assert_eq!(read(&mut &wire[..], 0).unwrap(), expected);
}

#[test]
fn eager_validation_identifies_the_failed_name_or_value() {
    use string_literal::ReadError as LiteralError;
    assert!(matches!(
        read(&mut &[0x29, 0xff][..], 16),
        Err(ReadError::Name {
            source: LiteralError::Huffman {
                source: huffman::DecodeError::ExcessPadding
            }
        })
    ));
    assert!(matches!(
        read(&mut &[0x40, 0x81, 0x18][..], 16),
        Err(ReadError::Value {
            source: LiteralError::Huffman {
                source: huffman::DecodeError::InvalidPadding
            }
        })
    ));
    // Eight '0' symbols of five zero bits each fit into five octets.
    let wire = [0x40, 0x85, 0, 0, 0, 0, 0];
    assert!(matches!(
        read(&mut &wire[..], 7),
        Err(ReadError::Value {
            source: LiteralError::Huffman {
                source: huffman::DecodeError::OutputTooLong { limit: 7 }
            }
        })
    ));
    let line = read(&mut &wire[..], 8).unwrap();
    let FieldLine::LiteralWithNameReference { value, .. } = line else {
        panic!()
    };
    assert_eq!(value.as_ref(), b"00000000");
    assert_eq!(value.decoded_len(), 8);
    assert!(matches!(
        read(&mut &[0x21, b'x', 2, 1, 2][..], 1),
        Err(ReadError::Value {
            source: LiteralError::RawTooLong { source } }) if source.length() == 2 && source.limit() == 1
    ));
}

#[test]
fn truncated_field_lines_return_errors_at_every_cut() {
    for wire in [
        &b"\x51\x0b/index.html"[..],
        &[0xff, 0x20],
        &[0x1f, 0],
        &[0x0f, 0, 1, 1],
        &[0x5f, 0, 0],
        &[0x29, 0x1f, 0x81, 0x1f],
        &[0x27, 0, 1, 2, 3, 4, 5, 6, 7, 0],
    ] {
        assert!(read(&mut &wire[..], 128).is_ok());
        for end in 0..wire.len() {
            assert!(read(&mut &wire[..end], 128).is_err(), "{wire:?} at {end}");
        }
    }
    // A large announced Huffman payload without data is rejected by SplitTo.
    assert!(read(&mut &[0x40, 0xff, 0xff, 0xff, 0xff, 0x7f][..], 16).is_err());
}

#[test]
fn bounded_sink_is_untouched_on_failure_and_exact_fit_succeeds() {
    let line = || FieldLine::<&[u8], &[u8]>::LiteralWithLiteralName {
        never_index: true,
        name: raw(&b"custom-key"[..]),
        value: coded(&b"www.example.com"[..]),
    };
    let mut out = BytesMut::new();
    write_field_line(&mut out, line()).unwrap();
    assert_eq!(out.len(), 2 + 10 + 1 + 12);
    for capacity in 0..out.len() {
        let mut storage = [0x77; 25];
        let mut dst = &mut storage[..capacity];
        let error = write_field_line(&mut dst, line()).unwrap_err();
        assert!(
            matches!(error, WriteError::InsufficientCapacity {source} if source.required() == 25 && source.available() == capacity)
        );
        assert_eq!(dst.len(), capacity);
        assert_eq!(storage, [0x77; 25]);
    }
    let mut exact = [0; 25];
    write_field_line(&mut &mut exact[..], line()).unwrap();
    assert_eq!(&exact, &out[..]);
}

#[test]
fn huffman_name_and_value_use_encoded_lengths_across_prefix_boundaries() {
    // RFC 7541 C.4: the 15-byte hostname encodes to twelve octets.
    let line = FieldLine::<&[u8], &[u8]>::LiteralWithLiteralName {
        never_index: false,
        name: coded(&b"www.example.com"[..]),
        value: raw(&[b'z'; 127][..]),
    };
    let mut wire = BytesMut::new();
    write_field_line(&mut wire, line).unwrap();
    assert_eq!(&wire[..2], &[0x2f, 5]);
    assert_eq!(&wire[14..16], &[127, 0]);
    let mut input = wire.freeze();
    let decoded: FieldLine<Bytes, Vec<u8>> = read_field_line(&mut input, 127).unwrap();
    let FieldLine::LiteralWithLiteralName { name, value, .. } = decoded else {
        panic!()
    };
    assert_eq!(name.as_ref(), b"www.example.com");
    assert_eq!(value.as_ref(), [b'z'; 127]);
    assert!(input.is_empty());
}

#[test]
fn raw_and_huffman_can_hit_the_limit_on_the_name_before_reading_the_value() {
    assert!(matches!(
        read(&mut &b"\x23abc\x00"[..], 2),
        Err(ReadError::Name {
            source: string_literal::ReadError::RawTooLong { source } }) if source.length() == 3 && source.limit() == 2
    ));
    let mut wire = &b"\x29\x1f\x00"[..];
    assert!(matches!(
        read(&mut wire, 0),
        Err(ReadError::Name {
            source: string_literal::ReadError::Huffman {
                source: huffman::DecodeError::OutputTooLong { limit: 0 }
            }
        })
    ));
    assert_eq!(wire, &[0]);
}

#[test]
fn padded_indices_and_lengths_write_back_their_original_octets() {
    let cases: [&[u8]; 6] = [
        // Static index 70 (63 + 7) as a field, with two zero groups.
        &[0xff, 0x87, 0x80, 0x00],
        // Relative index 63 with two zero groups.
        &[0xbf, 0x80, 0x80, 0x00],
        // Post-Base name reference 7 with one zero group, raw value "a"
        // whose length 1 fits in the prefix and so is not padded.
        &[0x07, 0x80, 0x00, 0x01, b'a'],
        // Literal name of seven octets, the 3-bit prefix maximum, with a
        // padded length.
        &[
            0x27, 0x80, 0x00, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x01, b'z',
        ],
        // Static name references 0 and 1 with a raw value of length 127,
        // the 7-bit prefix maximum, padded by one and two zero groups.
        &[0x50, 0x7f, 0x80, 0x00],
        &[0x51, 0x7f, 0x80, 0x80, 0x00],
    ];
    for wire in &cases[..4] {
        let mut src = *wire;
        let line = read(&mut src, 127).unwrap();
        assert!(src.is_empty(), "{wire:02x?}");
        assert_eq!(&write(line)[..], *wire, "{wire:02x?}");
    }
    for prefix in &cases[4..] {
        let mut wire = prefix.to_vec();
        wire.extend_from_slice(&[b'x'; 127]);
        let mut src = &wire[..];
        let line = read(&mut src, 127).unwrap();
        assert!(src.is_empty());
        let FieldLine::LiteralWithNameReference { value, .. } = &line else {
            panic!()
        };
        assert!(value.length().padding() > 0);
        assert_eq!(&write(line)[..], &wire[..]);
    }
}

#[test]
fn huffman_literals_write_back_their_original_octets() {
    // Huffman literal name "www.example.com" (twelve encoded octets) and
    // Huffman value "no-cache" (six).
    let mut wire = vec![0x2f, 5];
    wire.extend_from_slice(&[
        0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
    ]);
    wire.extend_from_slice(&[0x86]);
    wire.extend_from_slice(&[0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf]);
    let mut src = &wire[..];
    let line = read(&mut src, 64).unwrap();
    assert!(src.is_empty());
    let FieldLine::LiteralWithLiteralName { name, value, .. } = &line else {
        panic!()
    };
    assert_eq!((name.decoded_len(), name.wire_len::<3>()), (15, 14));
    assert_eq!((value.decoded_len(), value.wire_len::<7>()), (8, 7));
    assert_eq!(&write(line)[..], &wire[..]);
    // A longer Huffman length prefix: 127 encoded octets of 'a' (5 bits each).
    let plain = [b'a'; 203];
    let literal: StringLiteral<&[u8], &[u8]> = coded(&plain[..]);
    assert_eq!(literal.length().value().get(), 127);
    let literal = literal.with_length_padding::<7>(1).unwrap();
    let mut out = BytesMut::new();
    write_field_line(
        &mut out,
        FieldLine::LiteralWithNameReference {
            never_index: false,
            name: static_index(1),
            value: literal,
        },
    )
    .unwrap();
    assert_eq!(&out[..4], &[0x51, 0xff, 0x80, 0x00]);
    let line = read(&mut &out[..], 203).unwrap();
    assert_eq!(&write(line)[..], &out[..]);
}

#[test]
fn moved_fields_without_an_encoding_at_the_new_width_are_rejected_unwritten() {
    // Index 20 can be padded with a four-bit prefix, but fits in six bits.
    let index = PrefixedField::new::<4>(PrefixedInt::from(20u8), 1).unwrap();
    let line = Line::Indexed {
        index: TableIndex::Relative { index },
    };
    let mut out = Vec::from(*b"unchanged");
    assert!(matches!(
        write_field_line(&mut out, line),
        Err(WriteError::Index { source }) if source.prefix_bits() == 6
    ));
    assert_eq!(out, b"unchanged");
    // A name of length 7 can be padded with a three-bit prefix, but a value
    // of length 7 fits in seven bits.
    let literal = raw::<&[u8], BytesMut>(&b"example"[..])
        .with_length_padding::<3>(1)
        .unwrap();
    let line = Line::LiteralWithNameReference {
        never_index: false,
        name: static_index(0),
        value: literal,
    };
    assert!(matches!(
        write_field_line(&mut out, line),
        Err(WriteError::Value {
            source: string_literal::WriteError::Padding { .. }
        })
    ));
    assert_eq!(out, b"unchanged");
}

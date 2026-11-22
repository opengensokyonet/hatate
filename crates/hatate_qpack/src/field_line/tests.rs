use super::*;
use crate::huffman;
use bytes::BytesMut;

#[test]
fn published_field_lines_leave_the_next_line() {
    // RFC 9204 Appendix B.1 and B.2, after their field section prefixes.
    let input = &b"\x51\x0b/index.html\x10\x11"[..];
    let mut rest = input;
    let line = read_field_line(&mut rest, 11).unwrap();
    let FieldLine::LiteralWithNameReference {
        never_index: false,
        name: TableIndex::Static(index),
        value: StringLiteral::Raw(value),
    } = line
    else {
        panic!("expected an uncompressed static-name literal")
    };
    assert_eq!(index.entry().0, b":path");
    assert_eq!(value, b"/index.html");
    assert_eq!(value.as_ptr(), input[2..].as_ptr());
    let mut written = BytesMut::new();
    write_field_line(&mut written, &line).unwrap();
    for index in [0, 1] {
        let next = read_field_line(&mut rest, 0).unwrap();
        assert_eq!(next, FieldLine::Indexed(TableIndex::PostBase(index)));
        write_field_line(&mut written, &next).unwrap();
    }
    assert!(rest.is_empty());
    assert_eq!(&written[..], input);
}

#[test]
fn static_relative_and_post_base_indices() {
    for (index, wire) in [
        (
            TableIndex::Static(Index::try_from(17).unwrap()),
            &[0xd1][..],
        ),
        (
            TableIndex::Static(Index::try_from(98).unwrap()),
            &[0xff, 35],
        ),
        (TableIndex::Relative(63), &[0xbf, 0]),
        (TableIndex::PostBase(16), &[0x1f, 1]),
    ] {
        let line = FieldLine::<Bytes>::Indexed(index);
        let mut output = BytesMut::new();
        write_field_line(&mut output, &line).unwrap();
        assert_eq!(&output[..], wire);
        assert_eq!(read_field_line(&mut output.freeze(), 0).unwrap(), line);
    }
}

#[test]
fn literal_name_references_keep_the_n_and_h_bits_independent() {
    for (prefix, index) in [
        (0x51, TableIndex::Static(Index::try_from(1).unwrap())),
        (0x41, TableIndex::Relative(1)),
        (0x01, TableIndex::PostBase(1)),
    ] {
        for never_index in [false, true] {
            for coded in [false, true] {
                let n_mask = if prefix == 1 { 8 } else { 32 };
                let wire = [
                    prefix | if never_index { n_mask } else { 0 },
                    if coded { 0x81 } else { 1 },
                    if coded { 0x1f } else { b'a' },
                ];
                let line = read_field_line(&mut &wire[..], 1).unwrap();
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
                assert_eq!(matches!(value, StringLiteral::Huffman(_)), coded);
                let mut out = BytesMut::new();
                write_field_line(&mut out, &line).unwrap();
                assert_eq!(&out[..], &wire);
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
                let line = read_field_line(&mut src, 1).unwrap();
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
                assert_eq!(matches!(name, StringLiteral::Huffman(_)), name_h);
                assert_eq!(matches!(value, StringLiteral::Huffman(_)), value_h);
                let mut out = BytesMut::new();
                write_field_line(&mut out, &line).unwrap();
                assert_eq!(&out[..], &wire);
                assert!(src.is_empty());
            }
        }
    }
    let empty = read_field_line(&mut &[0x38, 0x80][..], 0).unwrap();
    let mut out = BytesMut::new();
    write_field_line(&mut out, &empty).unwrap();
    assert_eq!(&out[..], &[0x38, 0x80]);
}

#[test]
fn input_storage_and_octets_are_preserved_for_raw_literals() {
    let input = Bytes::from_static(b"\x21A\x01\xff");
    let mut rest = input.clone();
    let FieldLine::LiteralWithLiteralName {
        name: StringLiteral::Raw(name),
        value: StringLiteral::Raw(value),
        ..
    } = read_field_line(&mut rest, 1).unwrap()
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
        read_field_line(&mut &[0xff, 36][..], 0),
        Err(ReadError::StaticField { .. })
    ));
    assert!(matches!(
        read_field_line(&mut &[0x5f, 84][..], 0),
        Err(ReadError::StaticName { .. })
    ));
    let expected = FieldLine::<Bytes>::Indexed(TableIndex::Relative((1 << 62) - 1));
    let mut wire = BytesMut::new();
    write_field_line(&mut wire, &expected).unwrap();
    assert_eq!(read_field_line(&mut wire.freeze(), 0).unwrap(), expected);
}

#[test]
fn eager_validation_identifies_the_failed_name_or_value() {
    use string_literal::ReadError as LiteralError;
    assert!(matches!(
        read_field_line(&mut &[0x29, 0xff][..], 16),
        Err(ReadError::Name {
            source: LiteralError::Huffman {
                source: huffman::DecodeError::ExcessPadding
            }
        })
    ));
    assert!(matches!(
        read_field_line(&mut &[0x40, 0x81, 0x18][..], 16),
        Err(ReadError::Value {
            source: LiteralError::Huffman {
                source: huffman::DecodeError::InvalidPadding
            }
        })
    ));
    // Eight '0' symbols of five zero bits each fit into five octets.
    let wire = [0x40, 0x85, 0, 0, 0, 0, 0];
    assert!(matches!(
        read_field_line(&mut &wire[..], 7),
        Err(ReadError::Value {
            source: LiteralError::Huffman {
                source: huffman::DecodeError::OutputTooLong { limit: 7 }
            }
        })
    ));
    let line = read_field_line(&mut &wire[..], 8).unwrap();
    let FieldLine::LiteralWithNameReference { value, .. } = line else {
        panic!()
    };
    assert_eq!(value.as_ref(), b"00000000");
    assert!(matches!(
        read_field_line(&mut &[0x21, b'x', 2, 1, 2][..], 1),
        Err(ReadError::Value {
            source: LiteralError::RawTooLong {
                length: 2,
                limit: 1
            }
        })
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
        assert!(read_field_line(&mut &wire[..], 128).is_ok());
        for end in 0..wire.len() {
            assert!(
                read_field_line(&mut &wire[..end], 128).is_err(),
                "{wire:?} at {end}"
            );
        }
    }
    // A large announced Huffman payload without data is rejected by SplitTo.
    assert!(read_field_line(&mut &[0x40, 0xff, 0xff, 0xff, 0xff, 0x7f][..], 16).is_err());
}

#[test]
fn bounded_sink_is_untouched_on_failure_and_exact_fit_succeeds() {
    let line = FieldLine::<&[u8], &[u8]>::LiteralWithLiteralName {
        never_index: true,
        name: StringLiteral::Raw(b"custom-key"),
        value: StringLiteral::Huffman(b"www.example.com"),
    };
    let mut out = BytesMut::new();
    write_field_line(&mut out, &line).unwrap();
    assert_eq!(out.len(), 2 + 10 + 1 + 12);
    for capacity in 0..out.len() {
        let mut storage = [0x77; 25];
        let mut dst = &mut storage[..capacity];
        let error = write_field_line(&mut dst, &line).unwrap_err();
        assert!(
            matches!(error, WriteError::InsufficientCapacity {source} if source.required() == 25 && source.available() == capacity)
        );
        assert_eq!(dst.len(), capacity);
        assert_eq!(storage, [0x77; 25]);
    }
    let mut exact = [0; 25];
    write_field_line(&mut &mut exact[..], &line).unwrap();
    assert_eq!(&exact, &out[..]);
}

#[test]
fn huffman_name_and_value_use_encoded_lengths_across_prefix_boundaries() {
    // RFC 7541 C.4: the 15-byte hostname encodes to twelve octets.
    let line = FieldLine::<&[u8], &[u8]>::LiteralWithLiteralName {
        never_index: false,
        name: StringLiteral::Huffman(b"www.example.com"),
        value: StringLiteral::Raw(&[b'z'; 127]),
    };
    let mut wire = BytesMut::new();
    write_field_line(&mut wire, &line).unwrap();
    assert_eq!(&wire[..2], &[0x2f, 5]);
    assert_eq!(&wire[14..16], &[127, 0]);
    let mut input = wire.freeze();
    let decoded = read_field_line(&mut input, 127).unwrap();
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
        read_field_line(&mut &b"\x23abc\x00"[..], 2),
        Err(ReadError::Name {
            source: string_literal::ReadError::RawTooLong {
                length: 3,
                limit: 2
            }
        })
    ));
    let mut wire = &b"\x29\x1f\x00"[..];
    assert!(matches!(
        read_field_line(&mut wire, 0),
        Err(ReadError::Name {
            source: string_literal::ReadError::Huffman {
                source: huffman::DecodeError::OutputTooLong { limit: 0 }
            }
        })
    ));
    assert_eq!(wire, &[0]);
}

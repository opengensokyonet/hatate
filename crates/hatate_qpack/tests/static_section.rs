use bytes::{Bytes, BytesMut};
use hatate_qpack::{
    field_line::{FieldLine, TableIndex},
    static_section::{
        DynamicReferenceError, Field, FieldBytes, PrefixError, ReadError, WriteError,
        read_static_section, write_static_section,
    },
    static_table::Index,
    string_literal::StringLiteral,
};

#[test]
fn appendix_b1_reads_and_writes_a_complete_section() {
    let wire = b"\x00\x00\x51\x0b/index.html";
    let mut fields = read_static_section(&wire[..], 11, 48).unwrap();
    let field = fields.next().unwrap().unwrap();
    assert_eq!(field.name, FieldBytes::Static(b":path"));
    let FieldBytes::Input(value) = field.value else {
        panic!()
    };
    assert_eq!(value, b"/index.html");
    assert_eq!(value.as_ptr(), wire[4..].as_ptr());
    assert!(!field.never_index);
    assert!(fields.next().is_none());
    let lines = [FieldLine::<&[u8]>::LiteralWithNameReference {
        never_index: false,
        name: TableIndex::Static(Index::try_from(1).unwrap()),
        value: StringLiteral::Raw(b"/index.html"),
    }];
    let mut out = Vec::new();
    write_static_section(&mut out, &lines).unwrap();
    assert_eq!(out, wire);
}

#[test]
fn prefix_is_eager_and_section_errors_are_terminal() {
    assert!(matches!(
        read_static_section(&[][..], 0, 0),
        Err(PrefixError::MissingInsertCount)
    ));
    assert!(matches!(
        read_static_section(&[1, 0][..], 0, 0),
        Err(PrefixError::NonzeroInsertCount { .. })
    ));
    assert!(matches!(
        read_static_section(&[0, 0x80][..], 0, 0),
        Err(PrefixError::NegativeBase)
    ));
    for wire in [&[0, 0][..], &[0, 1], &[0, 0x7f, 0x80, 0]] {
        let mut empty = read_static_section(wire, 0, 0).unwrap();
        assert!(empty.next().is_none());
        assert!(empty.next().is_none());
    }
    let mut fields = read_static_section(&[0, 0, 0xd1, 0x51][..], 20, 128).unwrap();
    assert_eq!(fields.next().unwrap().unwrap().value.as_ref(), b"GET");
    assert!(matches!(fields.next(), Some(Err(ReadError::Line { .. }))));
    assert!(fields.next().is_none());
    let mut out = Vec::new();
    write_static_section::<Bytes, Bytes>(&mut out, &[]).unwrap();
    assert_eq!(out, [0, 0]);
}

#[test]
fn resolved_sizes_and_per_literal_limits_are_independent() {
    let wire = &[0, 0, 0xd1, 0xd7][..];
    let ok = read_static_section(wire, 0, 86)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(ok[1].value.as_ref(), b"https");
    let mut short = read_static_section(wire, 0, 85).unwrap();
    assert!(short.next().unwrap().is_ok());
    assert!(matches!(
        short.next(),
        Some(Err(ReadError::SectionTooLarge))
    ));
    assert!(short.next().is_none());
    // :path uses five octets from the static table; its raw value uses one.
    for (per_literal, total, section_error) in [(10, 37, true), (0, 38, false), (0, 37, false)] {
        let mut fields =
            read_static_section(&b"\x00\x00\x51\x01z"[..], per_literal, total).unwrap();
        let error = fields.next().unwrap().unwrap_err();
        assert_eq!(matches!(error, ReadError::SectionTooLarge), section_error);
        assert!(fields.next().is_none());
    }
    for (size, ok) in [(31, false), (32, true)] {
        let mut fields = read_static_section(&[0, 0, 0x20, 0][..], 0, size).unwrap();
        assert_eq!(fields.next().unwrap().is_ok(), ok);
    }
    let wire = &b"\x00\x00\x21x\x85\x00\x00\x00\x00\x00"[..];
    let mut over = read_static_section(wire, 8, 40).unwrap();
    assert!(matches!(over.next(), Some(Err(ReadError::SectionTooLarge))));
    let field = read_static_section(wire, 8, 41)
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    assert!(matches!(field.value, FieldBytes::Huffman(ref data) if data.as_ref() == b"00000000"));
}

#[test]
fn repeated_names_keep_their_order_storage_and_never_index_bit() {
    let wire = Bytes::from_static(b"\x00\x00\x71\x01A\x51\x81\x1f\x31x\x01z");
    let fields = read_static_section(wire.clone(), 1, 256)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(fields.len(), 3);
    assert!(
        matches!(&fields[0], Field {name: FieldBytes::Static(b":path"), value: FieldBytes::Input(bytes), never_index:true} if bytes.as_ptr()==wire[4..].as_ptr())
    );
    assert!(
        matches!(&fields[1], Field {name: FieldBytes::Static(b":path"), value: FieldBytes::Huffman(bytes), never_index:false} if bytes.as_ref()==b"a")
    );
    assert_eq!(fields[2].name.as_ref(), b"x");
    assert!(fields[2].never_index);
    assert_eq!(fields[2].value.as_ref(), b"z");
}

#[test]
fn dynamic_references_fail_before_reading_an_associated_value() {
    for (tag, indexed) in [(0x80, true), (0x10, true), (0x40, false), (0x00, false)] {
        let wire = [0, 0, 0xd1, tag, 0xff];
        let mut fields = read_static_section(&wire[..], 0, 128).unwrap();
        assert!(fields.next().unwrap().is_ok());
        let Some(Err(ReadError::DynamicReference { source })) = fields.next() else {
            panic!()
        };
        assert_eq!(
            source,
            if indexed {
                DynamicReferenceError::Field
            } else {
                DynamicReferenceError::Name
            }
        );
        assert!(fields.next().is_none());
        let bad = if indexed {
            FieldLine::Indexed(TableIndex::Relative(0))
        } else {
            FieldLine::LiteralWithNameReference {
                never_index: true,
                name: TableIndex::PostBase(0),
                value: StringLiteral::Raw(&b""[..]),
            }
        };
        let mut out = Vec::from(b"unchanged");
        let lines = [
            FieldLine::<&[u8]>::Indexed(TableIndex::Static(Index::try_from(17).unwrap())),
            bad,
        ];
        assert!(matches!(
            write_static_section(&mut out, &lines),
            Err(WriteError::DynamicReference { index: 1, .. })
        ));
        assert_eq!(out, b"unchanged");
    }
}

#[test]
fn all_short_destinations_are_untouched_and_exact_fit_preserves_choices() {
    let rows: [FieldLine<&[u8], &[u8]>; 2] = [
        FieldLine::Indexed(TableIndex::Static(Index::try_from(17).unwrap())),
        FieldLine::LiteralWithLiteralName {
            never_index: true,
            name: StringLiteral::Raw(b"x"),
            value: StringLiteral::Huffman(b"a"),
        },
    ];
    let expected = [0, 0, 0xd1, 0x31, b'x', 0x81, 0x1f];
    for capacity in 0..expected.len() {
        let mut buf = [0xa5; 7];
        let mut dst = &mut buf[..capacity];
        let error = write_static_section(&mut dst, &rows).unwrap_err();
        assert!(
            matches!(error, WriteError::InsufficientCapacity {source} if source.required()==7 && source.available()==capacity)
        );
        assert_eq!(dst.len(), capacity);
        assert_eq!(buf, [0xa5; 7]);
    }
    let mut buf = BytesMut::new();
    write_static_section(&mut buf, &rows).unwrap();
    assert_eq!(buf.as_ref(), expected);
    let mut exact = [0; 7];
    write_static_section(&mut &mut exact[..], &rows).unwrap();
    assert_eq!(exact, expected);
}

#[test]
fn measurement_and_write_use_the_same_payload_borrow() {
    use core::cell::Cell;
    struct Alternating(Cell<bool>);
    impl AsRef<[u8]> for Alternating {
        fn as_ref(&self) -> &[u8] {
            if self.0.replace(true) {
                b"longer"
            } else {
                b"a"
            }
        }
    }
    let lines = [
        FieldLine::<Alternating, Alternating>::LiteralWithLiteralName {
            never_index: false,
            name: StringLiteral::Raw(Alternating(Cell::new(false))),
            value: StringLiteral::Huffman(Alternating(Cell::new(false))),
        },
    ];
    let mut out = [0; 6];
    write_static_section(&mut &mut out[..], &lines).unwrap();
    assert_eq!(out, [0, 0, 0x21, b'a', 0x81, 0x1f]);
}

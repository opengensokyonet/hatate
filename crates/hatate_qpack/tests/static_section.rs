mod support;

use bytes::{Bytes, BytesMut};
use hatate_qpack::{
    field_line::{FieldLine, TableIndex},
    integer::{PrefixedField, PrefixedInt},
    static_section::{
        DynamicReferenceError, Field, FieldBytes, Fields, PrefixError, ReadError, SectionPrefix,
        WriteError, read_static_section, write_static_section,
    },
    static_table::Index,
};
use support::{huffman, raw};

fn read(
    wire: &[u8],
    max_literal_len: usize,
    max_section_size: usize,
) -> Result<Fields<&[u8], BytesMut>, PrefixError> {
    read_static_section(wire, max_literal_len, max_section_size).map(|(_, fields)| fields)
}

fn static_index(number: u64) -> TableIndex {
    TableIndex::Static {
        index: PrefixedField::shortest(Index::try_from(number).unwrap()),
    }
}

fn never_index(field: &Field<impl Sized, impl Sized>) -> bool {
    match field.line {
        FieldLine::Indexed { .. } => false,
        FieldLine::LiteralWithNameReference { never_index, .. }
        | FieldLine::LiteralWithLiteralName { never_index, .. } => never_index,
    }
}

fn zero() -> SectionPrefix {
    SectionPrefix::default()
}

#[test]
fn appendix_b1_reads_and_writes_a_complete_section() {
    let wire = b"\x00\x00\x51\x0b/index.html";
    let (prefix, mut fields) = read_static_section::<_, BytesMut>(&wire[..], 11, 48).unwrap();
    assert_eq!(prefix, SectionPrefix::default());
    let field = fields.next().unwrap().unwrap();
    assert_eq!(field.name, FieldBytes::Static(b":path"));
    let FieldBytes::Input(value) = field.value else {
        panic!()
    };
    assert_eq!(value, b"/index.html");
    assert_eq!(value.as_ptr(), wire[4..].as_ptr());
    assert!(!never_index(&field));
    assert!(fields.next().is_none());
    let lines = [FieldLine::<&[u8], &[u8]>::LiteralWithNameReference {
        never_index: false,
        name: static_index(1),
        value: raw(&b"/index.html"[..]),
    }];
    let mut out = Vec::new();
    write_static_section(&mut out, &prefix, &lines).unwrap();
    assert_eq!(out, wire);
    // The line that was read writes back the same octets.
    let mut again = Vec::new();
    write_static_section(&mut again, &prefix, [&field.line]).unwrap();
    assert_eq!(again, wire);
}

#[test]
fn prefix_is_eager_and_section_errors_are_terminal() {
    assert!(matches!(
        read(&[][..], 0, 0),
        Err(PrefixError::MissingInsertCount)
    ));
    assert!(matches!(
        read(&[1, 0][..], 0, 0),
        Err(PrefixError::NonzeroInsertCount { .. })
    ));
    assert!(matches!(
        read(&[0, 0x80][..], 0, 0),
        Err(PrefixError::NegativeBase)
    ));
    for wire in [&[0, 0][..], &[0, 1], &[0, 0x7f, 0x80, 0]] {
        let mut empty = read(wire, 0, 0).unwrap();
        assert!(empty.next().is_none());
        assert!(empty.next().is_none());
    }
    let mut fields = read(&[0, 0, 0xd1, 0x51][..], 20, 128).unwrap();
    assert_eq!(fields.next().unwrap().unwrap().value.as_ref(), b"GET");
    assert!(matches!(fields.next(), Some(Err(ReadError::Line { .. }))));
    assert!(fields.next().is_none());
    let mut out = Vec::new();
    write_static_section(&mut out, &zero(), &Vec::<FieldLine<Bytes, Bytes>>::new()).unwrap();
    assert_eq!(out, [0, 0]);
}

#[test]
fn padded_prefixes_read_back_and_write_their_original_octets() {
    for wire in [
        &[0x00, 0x05][..],
        &[0x00, 0x7f, 0x80, 0x00],
        &[0x00, 0x7f, 0x81, 0x80, 0x80, 0x00],
    ] {
        let (prefix, mut fields) = read_static_section::<_, BytesMut>(wire, 0, 0).unwrap();
        assert!(fields.next().is_none());
        assert!(!prefix.is_negative());
        assert_eq!(prefix.encoded_insert_count().value(), PrefixedInt::ZERO);
        let mut out = Vec::new();
        write_static_section(&mut out, &prefix, &Vec::<FieldLine<Bytes, Bytes>>::new()).unwrap();
        assert_eq!(out, wire);
    }
    let padded = SectionPrefix::new(
        PrefixedField::shortest(PrefixedInt::ZERO),
        false,
        PrefixedField::new::<7>(PrefixedInt::from(128u8), 3).unwrap(),
    )
    .unwrap();
    let mut out = Vec::new();
    write_static_section(&mut out, &padded, &Vec::<FieldLine<Bytes, Bytes>>::new()).unwrap();
    assert_eq!(out, [0x00, 0x7f, 0x81, 0x80, 0x80, 0x00]);
}

#[test]
fn prefixes_that_need_a_dynamic_table_are_not_written() {
    let zero = PrefixedField::shortest(PrefixedInt::ZERO);
    for prefix in [
        SectionPrefix::new(PrefixedField::shortest(PrefixedInt::from(1u8)), false, zero),
        SectionPrefix::new(zero, true, zero),
    ] {
        let mut out = Vec::from(*b"unchanged");
        assert!(matches!(
            write_static_section(
                &mut out,
                &prefix.unwrap(),
                &Vec::<FieldLine<Bytes, Bytes>>::new()
            ),
            Err(WriteError::DynamicPrefix)
        ));
        assert_eq!(out, b"unchanged");
    }
}

#[test]
fn resolved_sizes_and_per_literal_limits_are_independent() {
    let wire = &[0, 0, 0xd1, 0xd7][..];
    let ok = read(wire, 0, 86)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(ok[1].value.as_ref(), b"https");
    let mut short = read(wire, 0, 85).unwrap();
    assert!(short.next().unwrap().is_ok());
    assert!(matches!(
        short.next(),
        Some(Err(ReadError::SectionTooLarge))
    ));
    assert!(short.next().is_none());
    // :path uses five octets from the static table; its raw value uses one.
    for (per_literal, total, section_error) in [(10, 37, true), (0, 38, false), (0, 37, false)] {
        let mut fields = read(&b"\x00\x00\x51\x01z"[..], per_literal, total).unwrap();
        let error = fields.next().unwrap().unwrap_err();
        assert_eq!(matches!(error, ReadError::SectionTooLarge), section_error);
        assert!(fields.next().is_none());
    }
    for (size, ok) in [(31, false), (32, true)] {
        let mut fields = read(&[0, 0, 0x20, 0][..], 0, size).unwrap();
        assert_eq!(fields.next().unwrap().is_ok(), ok);
    }
    let wire = &b"\x00\x00\x21x\x85\x00\x00\x00\x00\x00"[..];
    let mut over = read(wire, 8, 40).unwrap();
    assert!(matches!(over.next(), Some(Err(ReadError::SectionTooLarge))));
    let field = read(wire, 8, 41).unwrap().next().unwrap().unwrap();
    assert!(matches!(field.value, FieldBytes::Huffman(ref data) if data.as_ref() == b"00000000"));
}

#[test]
fn repeated_names_keep_their_order_storage_and_never_index_bit() {
    let wire = Bytes::from_static(b"\x00\x00\x71\x01A\x51\x81\x1f\x31x\x01z");
    let (prefix, fields) = read_static_section::<_, BytesMut>(wire.clone(), 1, 256).unwrap();
    let fields = fields.collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(fields.len(), 3);
    assert!(
        matches!(&fields[0], Field {name: FieldBytes::Static(b":path"), value: FieldBytes::Input(bytes), ..} if bytes.as_ptr()==wire[4..].as_ptr())
    );
    assert!(never_index(&fields[0]));
    assert!(
        matches!(&fields[1], Field {name: FieldBytes::Static(b":path"), value: FieldBytes::Huffman(bytes), ..} if bytes.as_ref()==b"a")
    );
    assert!(!never_index(&fields[1]));
    assert_eq!(fields[2].name.as_ref(), b"x");
    assert!(never_index(&fields[2]));
    assert_eq!(fields[2].value.as_ref(), b"z");
    let mut out = Vec::new();
    write_static_section(&mut out, &prefix, fields.iter().map(|field| &field.line)).unwrap();
    assert_eq!(out, wire);
}

#[test]
fn dynamic_references_fail_before_reading_an_associated_value() {
    for (tag, indexed) in [(0x80, true), (0x10, true), (0x40, false), (0x00, false)] {
        let wire = [0, 0, 0xd1, tag, 0xff];
        let mut fields = read(&wire[..], 0, 128).unwrap();
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
        let index = PrefixedField::shortest(PrefixedInt::ZERO);
        let reference = match tag {
            0x80 | 0x40 => TableIndex::Relative { index },
            _ => TableIndex::PostBase { index },
        };
        let bad = if indexed {
            FieldLine::Indexed { index: reference }
        } else {
            FieldLine::LiteralWithNameReference {
                never_index: true,
                name: reference,
                value: raw(&b""[..]),
            }
        };
        let mut out = Vec::from(b"unchanged");
        let lines = [
            FieldLine::<&[u8], &[u8]>::Indexed {
                index: static_index(17),
            },
            bad,
        ];
        assert!(matches!(
            write_static_section(&mut out, &zero(), &lines),
            Err(WriteError::DynamicReference { index: 1, source: error }) if error == source
        ));
        assert_eq!(out, b"unchanged");
    }
}

fn rows() -> [FieldLine<&'static [u8], &'static [u8]>; 2] {
    [
        FieldLine::Indexed {
            index: static_index(17),
        },
        FieldLine::LiteralWithLiteralName {
            never_index: true,
            name: raw(&b"x"[..]),
            value: huffman(&b"a"[..]),
        },
    ]
}

#[test]
fn all_short_destinations_are_untouched_and_exact_fit_preserves_choices() {
    let expected = [0, 0, 0xd1, 0x31, b'x', 0x81, 0x1f];
    for capacity in 0..expected.len() {
        let mut buf = [0xa5; 7];
        let mut dst = &mut buf[..capacity];
        let error = write_static_section(&mut dst, &zero(), &rows()).unwrap_err();
        assert!(
            matches!(error, WriteError::InsufficientCapacity {source} if source.required()==7 && source.available()==capacity)
        );
        assert_eq!(dst.len(), capacity);
        assert_eq!(buf, [0xa5; 7]);
    }
    let mut buf = BytesMut::new();
    write_static_section(&mut buf, &zero(), &rows()).unwrap();
    assert_eq!(buf.as_ref(), expected);
    let mut exact = [0; 7];
    write_static_section(&mut &mut exact[..], &zero(), &rows()).unwrap();
    assert_eq!(exact, expected);
}

// After advancing once, report just one writable byte at a time. The
// physical storage still has all the space advertised on entry.
struct ConservativeSink<'a> {
    rest: &'a mut [u8],
    advanced: bool,
}

// SAFETY: all writable chunks borrow initialized storage exclusively; the
// inner slice maintains the cursor, and chunks never exceed remaining_mut.
unsafe impl bytes::BufMut for ConservativeSink<'_> {
    fn remaining_mut(&self) -> usize {
        if self.advanced {
            self.rest.len().min(1)
        } else {
            self.rest.len()
        }
    }
    fn chunk_mut(&mut self) -> &mut bytes::buf::UninitSlice {
        let size = self.rest.len().min(1);
        bytes::buf::UninitSlice::new(&mut self.rest[..size])
    }
    unsafe fn advance_mut(&mut self, count: usize) {
        assert!(count <= self.rest.len().min(1));
        let (_, tail) = core::mem::take(&mut self.rest).split_at_mut(count);
        self.rest = tail;
        self.advanced |= count != 0;
    }
}

#[test]
fn capacity_can_be_reported_conservatively_after_the_first_write() {
    use hatate_qpack::field_line::write_field_line;
    let line = || FieldLine::<&[u8], &[u8]>::LiteralWithNameReference {
        never_index: false,
        name: static_index(1),
        value: huffman(&b"aa"[..]),
    };
    let expected = [0x51, 0x82, 0x18, 0xff];
    let mut one = [0; 4];
    write_field_line(
        &mut ConservativeSink {
            rest: &mut one,
            advanced: false,
        },
        line(),
    )
    .unwrap();
    assert_eq!(one, expected);
    let mut section = [0xa5; 8];
    write_static_section(
        &mut ConservativeSink {
            rest: &mut section,
            advanced: false,
        },
        &zero(),
        &[line()],
    )
    .unwrap();
    assert_eq!(&section[..6], &[0, 0, 0x51, 0x82, 0x18, 0xff]);
    assert_eq!(&section[6..], &[0xa5; 2]);
}

#[test]
fn segmented_destination_can_cross_several_encoded_chunks() {
    let octets = [b'x'; 670];
    let line = FieldLine::<&[u8], &[u8]>::LiteralWithLiteralName {
        never_index: true,
        name: raw(&octets[..]),
        value: huffman(&octets[..]),
    };
    let mut storage = [0; 1500];
    let mut dst = ConservativeSink {
        rest: &mut storage,
        advanced: false,
    };
    write_static_section(&mut dst, &zero(), [&line]).unwrap();
    let length = 1500 - dst.rest.len();
    let mut fields = read(&storage[..length], 670, 1372).unwrap();
    let field = fields.next().unwrap().unwrap();
    assert_eq!(field.name.as_ref(), &octets);
    assert_eq!(field.value.as_ref(), &octets);
    assert!(fields.next().is_none());
}

type Line = FieldLine<&'static [u8], &'static [u8]>;

fn indexed(number: u64) -> Line {
    FieldLine::Indexed {
        index: static_index(number),
    }
}

fn literal(value: &'static [u8]) -> Line {
    FieldLine::LiteralWithNameReference {
        never_index: false,
        name: static_index(1),
        value: raw(value),
    }
}

/// The octets of a section of these lines, written as they stand.
fn written(lines: &[Line]) -> Vec<u8> {
    let mut out = Vec::new();
    write_static_section(&mut out, &zero(), lines.iter()).unwrap();
    out
}

/// Lines that give `normal` the first time they are walked and `changed`
/// the second time, whichever of the iterator and its clone is walked first.
#[derive(Clone)]
struct Rewalked<'a> {
    normal: &'a [Line],
    changed: &'a [Line],
    walks: std::rc::Rc<std::cell::Cell<usize>>,
    chosen: Option<&'a [Line]>,
    position: usize,
}

impl<'a> Rewalked<'a> {
    fn new(normal: &'a [Line], changed: &'a [Line]) -> Self {
        Self {
            normal,
            changed,
            walks: Default::default(),
            chosen: None,
            position: 0,
        }
    }
}

impl<'a> Iterator for Rewalked<'a> {
    type Item = &'a Line;

    fn next(&mut self) -> Option<&'a Line> {
        let chosen = *self.chosen.get_or_insert_with(|| {
            let walk = self.walks.get();
            self.walks.set(walk + 1);
            if walk == 0 { self.normal } else { self.changed }
        });
        let line = chosen.get(self.position)?;
        self.position += 1;
        Some(line)
    }
}

/// What writing `normal` as walked once more as `changed` came to: the
/// result and the octets left in the destination.
fn rewalk(normal: &[Line], changed: &[Line]) -> (Result<(), WriteError>, Vec<u8>) {
    let mut out = Vec::new();
    let result = write_static_section(&mut out, &zero(), Rewalked::new(normal, changed));
    (result, out)
}

#[test]
fn lines_that_change_between_the_walks_report_where() {
    let normal = [indexed(17), indexed(18), indexed(19)];
    // The second line grows beyond what was measured.
    let (result, out) = rewalk(&normal, &[indexed(17), literal(b"abcdefgh"), indexed(19)]);
    assert!(
        matches!(result, Err(WriteError::LineChanged { index: 1 })),
        "{result:?}"
    );
    assert_eq!(out, written(&normal[..1]));
    // The last line is missing.
    let (result, out) = rewalk(&normal, &[indexed(17), indexed(18)]);
    assert!(
        matches!(result, Err(WriteError::LineChanged { index: 2 })),
        "{result:?}"
    );
    assert_eq!(out, written(&normal[..2]));
    // A line too many.
    let (result, out) = rewalk(
        &normal,
        &[indexed(17), indexed(18), indexed(19), indexed(20)],
    );
    assert!(
        matches!(result, Err(WriteError::LineChanged { index: 3 })),
        "{result:?}"
    );
    assert_eq!(out, written(&normal));
    // No lines at all where there were some.
    let (result, out) = rewalk(&normal, &[]);
    assert!(
        matches!(result, Err(WriteError::LineChanged { index: 0 })),
        "{result:?}"
    );
    assert_eq!(out, written(&[]));
    // The same lines in the second walk write the section.
    let (result, out) = rewalk(&normal, &normal);
    result.unwrap();
    assert_eq!(out, written(&normal));
}

#[test]
fn a_vec_of_lines_or_of_things_that_hold_lines_is_written_by_borrowing() {
    struct Entry {
        line: Line,
    }
    let lines = vec![indexed(17), literal(b"value"), indexed(25)];
    let mut by_iter = Vec::new();
    write_static_section(&mut by_iter, &zero(), lines.iter()).unwrap();
    let entries: Vec<Entry> = lines.iter().cloned().map(|line| Entry { line }).collect();
    let mut by_field = Vec::new();
    write_static_section(
        &mut by_field,
        &zero(),
        entries.iter().map(|entry| &entry.line),
    )
    .unwrap();
    assert_eq!(by_iter, by_field);
    assert_eq!(by_iter[..2], [0, 0]);
    // Walking the lines to write them leaves them to be written again.
    let mut again = Vec::new();
    write_static_section(&mut again, &zero(), &lines).unwrap();
    assert_eq!(again, by_iter);
}

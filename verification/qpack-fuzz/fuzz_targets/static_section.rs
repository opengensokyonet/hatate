//! Compare static-mode section parsing with unrestricted single-line
//! decoding plus independent resolution and decoded-size accounting. An
//! accepted section writes back to the octets it was read from.
#![no_main]

use bytes::BytesMut;
use hatate_qpack::{
    field_line::{FieldLine, TableIndex, read_field_line},
    static_section::{SectionPrefix, read_static_section, write_static_section},
};
use libfuzzer_sys::fuzz_target;

type Line<'a> = FieldLine<&'a [u8], BytesMut>;

struct Expected<'a> {
    name: &'a [u8],
    value: &'a [u8],
    longest_literal: usize,
}

fn resolve<'a>(line: &'a Line<'_>) -> Option<Expected<'a>> {
    match line {
        FieldLine::Indexed {
            index: TableIndex::Static { index },
        } => {
            let (name, value) = index.value().entry();
            Some(Expected {
                name,
                value,
                longest_literal: 0,
            })
        }
        FieldLine::LiteralWithNameReference {
            name: TableIndex::Static { index },
            value,
            ..
        } => Some(Expected {
            name: index.value().entry().0,
            value: value.as_ref(),
            longest_literal: value.as_ref().len(),
        }),
        FieldLine::LiteralWithLiteralName { name, value, .. } => Some(Expected {
            name: name.as_ref(),
            value: value.as_ref(),
            longest_literal: name.as_ref().len().max(value.as_ref().len()),
        }),
        _ => None,
    }
}

fuzz_target!(|data: &[u8]| {
    let [literal, high, low, body @ ..] = data else {
        return;
    };
    let literal = usize::from(*literal);
    let total = usize::from(u16::from_be_bytes([*high, *low]));
    // Also exercise arbitrary section prefixes and fused termination. A
    // section read completely writes back to its octets.
    if let Ok((prefix, mut fields)) = read_static_section::<_, BytesMut>(body, literal, total) {
        let mut lines = Vec::new();
        let mut complete = true;
        for field in fields.by_ref() {
            match field {
                Ok(field) => lines.push(field.line),
                Err(_) => {
                    complete = false;
                    break;
                }
            }
        }
        assert!(fields.next().is_none());
        if complete {
            let mut written = Vec::new();
            write_static_section(&mut written, &prefix, lines).unwrap();
            assert_eq!(written, body);
        }
    }

    let mut wire = vec![0, 0];
    wire.extend_from_slice(body);
    let (prefix, mut fields) =
        read_static_section::<_, BytesMut>(wire.as_slice(), literal, total).unwrap();
    assert_eq!(prefix, SectionPrefix::default());
    let mut rest = body;
    let mut consumed = 0;
    let mut rows = Vec::new();
    let mut accepted = 0;
    while !rest.is_empty() {
        let Ok(line) = read_field_line::<_, BytesMut>(&mut rest, usize::MAX) else {
            assert!(fields.next().unwrap().is_err());
            break;
        };
        let Some(expected) = resolve(&line) else {
            rows.push(line);
            let mut dst = vec![0x77];
            assert!(write_static_section(&mut dst, &prefix, rows.clone()).is_err());
            assert_eq!(dst, [0x77]);
            assert!(fields.next().unwrap().is_err());
            break;
        };
        consumed += expected.name.len() + expected.value.len() + 32;
        if consumed > total || expected.longest_literal > literal {
            assert!(fields.next().unwrap().is_err());
            break;
        }
        let actual = fields.next().unwrap().unwrap();
        assert_eq!(actual.name.as_ref(), expected.name);
        assert_eq!(actual.value.as_ref(), expected.value);
        assert_eq!(actual.line, line);
        rows.push(line);
        accepted = body.len() - rest.len();
    }
    assert!(fields.next().is_none());
    if rows.iter().any(|line| resolve(line).is_none()) {
        return;
    }
    // The accepted rows came from the start of `body`.
    let reference = &wire[..2 + accepted];
    let mut dst = vec![0xaa; reference.len() - 1];
    assert!(write_static_section(&mut dst.as_mut_slice(), &prefix, rows.clone()).is_err());
    assert!(dst.iter().all(|b| *b == 0xaa));
    let mut exact = vec![0; reference.len()];
    write_static_section(&mut exact.as_mut_slice(), &prefix, rows).unwrap();
    assert_eq!(exact, reference);
});

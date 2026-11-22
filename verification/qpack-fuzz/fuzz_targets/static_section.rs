//! Compare static-mode section parsing with unrestricted single-line
//! decoding plus independent resolution and decoded-size accounting.
#![no_main]

use hatate_qpack::{
    field_line::{FieldLine, TableIndex, read_field_line, write_field_line},
    static_section::{read_static_section, write_static_section},
};
use libfuzzer_sys::fuzz_target;

struct Expected<'a> {
    name: &'a [u8],
    value: &'a [u8],
    never_index: bool,
    longest_literal: usize,
}

fn resolve<'a>(line: &'a FieldLine<&[u8]>) -> Option<Expected<'a>> {
    match line {
        FieldLine::Indexed(TableIndex::Static(index)) => {
            let (name, value) = index.entry();
            Some(Expected {
                name,
                value,
                never_index: false,
                longest_literal: 0,
            })
        }
        FieldLine::LiteralWithNameReference {
            never_index,
            name: TableIndex::Static(index),
            value,
        } => Some(Expected {
            name: index.entry().0,
            value: value.as_ref(),
            never_index: *never_index,
            longest_literal: value.as_ref().len(),
        }),
        FieldLine::LiteralWithLiteralName {
            never_index,
            name,
            value,
        } => Some(Expected {
            name: name.as_ref(),
            value: value.as_ref(),
            never_index: *never_index,
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
    // Also exercise arbitrary section prefixes and fused termination.
    if let Ok(mut fields) = read_static_section(body, literal, total) {
        for field in fields.by_ref() {
            if field.is_err() {
                break;
            }
        }
        assert!(fields.next().is_none());
    }

    let mut wire = vec![0, 0];
    wire.extend_from_slice(body);
    let mut fields = read_static_section(wire.as_slice(), literal, total).unwrap();
    let mut rest = body;
    let mut consumed = 0;
    let mut rows = Vec::new();
    while !rest.is_empty() {
        let Ok(line) = read_field_line(&mut rest, usize::MAX) else {
            assert!(fields.next().unwrap().is_err());
            break;
        };
        let Some(expected) = resolve(&line) else {
            rows.push(line);
            let mut dst = vec![0x77];
            assert!(write_static_section(&mut dst, &rows).is_err());
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
        assert_eq!(actual.never_index, expected.never_index);
        rows.push(line);
    }
    assert!(fields.next().is_none());
    if rows.iter().any(|line| resolve(line).is_none()) {
        return;
    }
    let mut reference = vec![0, 0];
    for line in &rows {
        write_field_line(&mut reference, line).unwrap();
    }
    let mut dst = vec![0xaa; reference.len() - 1];
    assert!(write_static_section(&mut dst.as_mut_slice(), &rows).is_err());
    assert!(dst.iter().all(|b| *b == 0xaa));
    let mut exact = vec![0; reference.len()];
    write_static_section(&mut exact.as_mut_slice(), &rows).unwrap();
    assert_eq!(exact, reference);
});

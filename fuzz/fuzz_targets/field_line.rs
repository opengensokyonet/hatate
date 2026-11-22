//! Check arbitrary wire sequences and construct valid lines directly.
#![no_main]
use bytes::Bytes;
use hatate_qpack::{
    field_line::{FieldLine, TableIndex, read_field_line, write_field_line},
    static_table::Index,
    string_literal::StringLiteral,
};
use libfuzzer_sys::fuzz_target;

fn literal(bytes: &[u8], huffman: bool) -> StringLiteral<&[u8]> {
    if huffman {
        StringLiteral::Huffman(Bytes::copy_from_slice(bytes))
    } else {
        StringLiteral::Raw(bytes)
    }
}

fn generated(control: u8, selector: u8, payload: &[u8]) {
    let mut index_bytes = [0; 8];
    let n = payload.len().min(8);
    index_bytes[..n].copy_from_slice(&payload[..n]);
    let numeric = u64::from_le_bytes(index_bytes);
    let table = match selector % 3 {
        0 => TableIndex::Static(Index::try_from(numeric % 99).unwrap()),
        1 => TableIndex::Relative(numeric),
        _ => TableIndex::PostBase(numeric),
    };
    let split = usize::from(selector).min(payload.len());
    let never_index = control & 4 != 0;
    let line = match control % 4 {
        0 => FieldLine::Indexed(table),
        1 => FieldLine::LiteralWithNameReference {
            never_index,
            name: table,
            value: literal(payload, control & 8 != 0),
        },
        _ => FieldLine::LiteralWithLiteralName {
            never_index,
            name: literal(&payload[..split], control & 16 != 0),
            value: literal(&payload[split..], control & 8 != 0),
        },
    };
    let mut encoded = Vec::new();
    write_field_line(&mut encoded, &line).unwrap();
    let mut exact = vec![0; encoded.len()];
    write_field_line(&mut exact.as_mut_slice(), &line).unwrap();
    assert_eq!(exact, encoded);
    let mut short = vec![0x77; encoded.len() - 1];
    let mut dst = short.as_mut_slice();
    assert!(write_field_line(&mut dst, &line).is_err());
    assert_eq!(dst.len(), encoded.len() - 1);
    assert!(short.iter().all(|&octet| octet == 0x77));

    encoded.push(0xd1);
    let mut cursor = encoded.as_slice();
    assert_eq!(read_field_line(&mut cursor, payload.len()).unwrap(), line);
    assert_eq!(cursor, [0xd1]);
}

fuzz_target!(|data: &[u8]| {
    let [control, selector, wire @ ..] = data else {
        return;
    };
    generated(*control, *selector, wire);
    let limit = usize::from(*control);
    let mut cursor = wire;
    let mut owned = Bytes::copy_from_slice(wire);
    while !cursor.is_empty() {
        let before = cursor.len();
        let raw = read_field_line(&mut cursor, limit);
        let shared = read_field_line(&mut owned, limit);
        assert_eq!(cursor.len(), owned.len());
        match (raw, shared) {
            (Ok(line), Ok(other)) => {
                assert!(cursor.len() < before);
                let mut canonical = Vec::new();
                let mut from_owned = Vec::new();
                write_field_line(&mut canonical, &line).unwrap();
                write_field_line(&mut from_owned, &other).unwrap();
                assert_eq!(canonical, from_owned);
                let mut rest = canonical.as_slice();
                assert_eq!(read_field_line(&mut rest, limit).unwrap(), line);
                assert!(rest.is_empty());
            }
            (Err(a), Err(b)) => {
                assert_eq!(core::mem::discriminant(&a), core::mem::discriminant(&b));
                break;
            }
            _ => panic!("field line acceptance differs by input storage"),
        }
    }
});

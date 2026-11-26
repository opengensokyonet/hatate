//! Check arbitrary wire sequences and construct valid lines directly. Every
//! accepted line writes back to the octets it was read from.
#![no_main]
use bytes::{Bytes, BytesMut};
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use hatate_qpack::{
    field_line::{FieldLine, TableIndex, read_field_line, write_field_line},
    integer::{PrefixedField, PrefixedInt},
    static_table::Index,
    string_literal::StringLiteral,
};
use libfuzzer_sys::fuzz_target;

type Line<'a> = FieldLine<&'a [u8], &'a [u8]>;

fn now<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the future waited"),
    }
}

// A literal of `bytes`, padded by `padding` where the length prefix of `N`
// bits allows it.
fn literal<const N: u8>(bytes: &[u8], huffman: bool, padding: u8) -> StringLiteral<&[u8], &[u8]> {
    let literal = if huffman {
        StringLiteral::huffman(bytes).unwrap()
    } else {
        now(StringLiteral::raw(bytes)).unwrap()
    };
    literal
        .clone()
        .with_length_padding::<N>(padding)
        .unwrap_or(literal)
}

fn padded<const N: u8, T: Copy + Into<PrefixedInt>>(value: T, padding: u8) -> PrefixedField<T> {
    PrefixedField::new::<N>(value, padding).unwrap_or(PrefixedField::shortest(value))
}

// A reference whose static and relative index use `STATIC` prefix bits
// and whose post-Base index uses `POST_BASE`, padded where allowed.
fn table<const STATIC: u8, const POST_BASE: u8>(
    selector: u8,
    numeric: u64,
    padding: u8,
) -> TableIndex {
    let value = PrefixedInt::from(numeric);
    match selector % 3 {
        0 => TableIndex::Static {
            index: padded::<STATIC, _>(Index::try_from(numeric % 99).unwrap(), padding),
        },
        1 => TableIndex::Relative {
            index: padded::<STATIC, _>(value, padding),
        },
        _ => TableIndex::PostBase {
            index: padded::<POST_BASE, _>(value, padding),
        },
    }
}

fn generated(control: u8, selector: u8, payload: &[u8]) {
    let mut index_bytes = [0; 8];
    let n = payload.len().min(8);
    index_bytes[..n].copy_from_slice(&payload[..n]);
    let numeric = u64::from_le_bytes(index_bytes);
    let padding = selector >> 4;
    let split = usize::from(selector).min(payload.len());
    let never_index = control & 4 != 0;
    let line = || -> Line<'_> {
        match control % 4 {
            0 => FieldLine::Indexed {
                index: table::<6, 4>(selector, numeric, padding),
            },
            1 => FieldLine::LiteralWithNameReference {
                never_index,
                name: table::<4, 3>(selector, numeric, padding),
                value: literal::<7>(payload, control & 8 != 0, padding),
            },
            _ => FieldLine::LiteralWithLiteralName {
                never_index,
                name: literal::<3>(&payload[..split], control & 16 != 0, padding),
                value: literal::<7>(&payload[split..], control & 8 != 0, padding),
            },
        }
    };
    let mut encoded = Vec::new();
    write_field_line(&mut encoded, line()).unwrap();
    let mut exact = vec![0; encoded.len()];
    write_field_line(&mut exact.as_mut_slice(), line()).unwrap();
    assert_eq!(exact, encoded);
    let mut short = vec![0x77; encoded.len() - 1];
    let mut dst = short.as_mut_slice();
    assert!(write_field_line(&mut dst, line()).is_err());
    assert_eq!(dst.len(), encoded.len() - 1);
    assert!(short.iter().all(|&octet| octet == 0x77));

    encoded.push(0xd1);
    let mut cursor = encoded.as_slice();
    let read: FieldLine<&[u8], BytesMut> = read_field_line(&mut cursor, payload.len()).unwrap();
    assert_eq!(cursor, [0xd1]);
    let mut again = Vec::new();
    write_field_line(&mut again, read).unwrap();
    assert_eq!(again, encoded[..encoded.len() - 1]);
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
        let before = cursor;
        let raw: Result<FieldLine<&[u8], BytesMut>, _> = read_field_line(&mut cursor, limit);
        let shared: Result<FieldLine<Bytes, BytesMut>, _> = read_field_line(&mut owned, limit);
        assert_eq!(cursor.len(), owned.len());
        match (raw, shared) {
            (Ok(line), Ok(other)) => {
                let original = &before[..before.len() - cursor.len()];
                assert!(!original.is_empty());
                let mut written = Vec::new();
                write_field_line(&mut written, line).unwrap();
                assert_eq!(written, original);
                let mut from_owned = Vec::new();
                write_field_line(&mut from_owned, other).unwrap();
                assert_eq!(from_owned, original);
            }
            (Err(a), Err(b)) => {
                assert_eq!(core::mem::discriminant(&a), core::mem::discriminant(&b));
                break;
            }
            _ => panic!("field line acceptance differs by input storage"),
        }
    }
});

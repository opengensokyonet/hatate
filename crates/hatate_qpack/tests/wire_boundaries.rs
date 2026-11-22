use hatate_qpack::{
    field_line::{FieldLine, TableIndex, read_field_line, write_field_line},
    integer::{self, ReadError},
    static_table::Index,
    string_literal::StringLiteral,
};

// Mathematical base-128 decomposition, also usable one past u64::MAX.
fn octets(width: u8, flags: u8, value: u128) -> Vec<u8> {
    let mask = (1u128 << width) - 1;
    let mut wire = vec![flags | value.min(mask) as u8];
    if value >= mask {
        let mut rest = value - mask;
        loop {
            let digit = (rest % 128) as u8;
            rest /= 128;
            wire.push(if rest == 0 { digit } else { digit + 128 });
            if rest == 0 {
                break;
            }
        }
    }
    wire
}

#[test]
fn every_prefix_width_at_each_digit_transition_and_u64_overflow() {
    fn check<const N: u8>() {
        let prefix = (1u128 << N) - 1;
        let flags = 0xff ^ prefix as u8;
        let mut values = vec![prefix - 1, prefix, prefix + 1, u128::from(u64::MAX)];
        for digit in 1..=9 {
            let transition = prefix + 128u128.pow(digit);
            values.extend([transition - 1, transition, transition + 1]);
        }
        for value in values {
            let expected = octets(N, flags, value);
            let mut wire = Vec::new();
            integer::write::<N>(&mut wire, flags, value as u64).unwrap();
            assert_eq!(wire, expected);
            let mut rest = &expected[1..];
            assert_eq!(integer::read::<N>(expected[0], &mut rest), Ok(value as u64));
            assert!(rest.is_empty());
            for end in 1..expected.len() {
                assert_eq!(
                    integer::read::<N>(expected[0], &mut &expected[1..end]),
                    Err(ReadError::Incomplete)
                );
            }
        }
        let overflow = octets(N, flags, u128::from(u64::MAX) + 1);
        assert_eq!(
            integer::read::<N>(overflow[0], &mut &overflow[1..]),
            Err(ReadError::Overflow)
        );
    }
    check::<1>();
    check::<2>();
    check::<3>();
    check::<4>();
    check::<5>();
    check::<6>();
    check::<7>();
    check::<8>();
}

#[test]
fn every_static_index_as_a_field_and_a_name_leaves_the_following_line() {
    for number in 0..99 {
        let index = TableIndex::Static(Index::try_from(number).unwrap());
        let mut name_wire = octets(4, 0x70, u128::from(number));
        name_wire.extend_from_slice(b"\x01x");
        for (expected, mut wire) in [
            (
                FieldLine::Indexed(index),
                octets(6, 0xc0, u128::from(number)),
            ),
            (
                FieldLine::LiteralWithNameReference {
                    never_index: true,
                    name: index,
                    value: StringLiteral::Raw(&b"x"[..]),
                },
                name_wire,
            ),
        ] {
            let mut encoded = Vec::new();
            write_field_line(&mut encoded, &expected).unwrap();
            assert_eq!(encoded, wire);
            wire.push(0x10);
            let mut cursor = &wire[..];
            assert_eq!(read_field_line(&mut cursor, 1).unwrap(), expected);
            assert_eq!(cursor, [0x10]);
        }
    }
}

#[test]
fn nonminimal_encodings_are_normalized_without_changing_the_line() {
    // Each input length or index at the prefix maximum uses an extra zero digit.
    let mut wire = vec![0x37, 0x80, 0];
    wire.extend_from_slice(b"example");
    wire.extend_from_slice(&[0x7f, 0x80, 0]);
    wire.extend_from_slice(&[b'x'; 127]);
    wire.push(0xd1);
    let mut cursor = &wire[..];
    let line = read_field_line(&mut cursor, 127).unwrap();
    assert_eq!(cursor, [0xd1]);
    let mut encoded = Vec::new();
    write_field_line(&mut encoded, &line).unwrap();
    let mut canonical = vec![0x37, 0];
    canonical.extend_from_slice(b"example\x7f\x00");
    canonical.extend_from_slice(&[b'x'; 127]);
    assert_eq!(encoded, canonical);
}

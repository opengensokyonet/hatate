//! Compare wire decoding and cursor movement with wider arithmetic, and
//! check that every accepted encoding writes back to its original octets.
#![no_main]
use hatate_qpack::integer::{self, PrefixedField, PrefixedInt, ReadError};
use libfuzzer_sys::fuzz_target;

// The value and the number of continuation octets, or the error and the
// octets consumed.
fn reference<const N: u8>(first: u8, rest: &[u8]) -> (Result<(u64, usize), ReadError>, usize) {
    let mask = (1u128 << N) - 1;
    let prefix = u128::from(first) & mask;
    if prefix < mask {
        return (Ok((prefix as u64, 0)), 0);
    }
    let mut value = prefix;
    let mut place = 1u128;
    for (i, &octet) in rest.iter().take(10).enumerate() {
        value += u128::from(octet % 128) * place;
        let Ok(result) = u64::try_from(value) else {
            return (Err(ReadError::Overflow), i + 1);
        };
        if octet < 128 {
            return (Ok((result, i + 1)), i + 1);
        }
        place *= 128;
    }
    if rest.len() >= 10 {
        (Err(ReadError::TooLong), 10)
    } else {
        (Err(ReadError::Incomplete), rest.len())
    }
}

// Continuation octets of the shortest encoding, by wide arithmetic.
fn shortest<const N: u8>(value: u64) -> usize {
    let mask = (1u128 << N) - 1;
    let value = u128::from(value);
    if value < mask {
        return 0;
    }
    let mut rest = value - mask;
    let mut digits = 1;
    while rest >= 128 {
        rest /= 128;
        digits += 1;
    }
    digits
}

fn check<const N: u8>(first: u8, rest: &[u8], padding: u8) {
    let (expected, consumed) = reference::<N>(first, rest);
    let mut cursor = rest;
    let read = integer::read::<N>(first, &mut cursor);
    assert_eq!(cursor.len(), rest.len() - consumed);
    match (read, expected) {
        (Ok(field), Ok((value, continuations))) => {
            assert_eq!(field.value().get(), value);
            assert_eq!(
                usize::from(field.padding()),
                continuations - shortest::<N>(value)
            );
            assert_eq!(field.encoded_len::<N>(), 1 + consumed);
            let mut written = Vec::new();
            integer::write::<N, _>(&mut written, first, field).unwrap();
            assert_eq!(written[0], first);
            assert_eq!(written[1..], rest[..consumed]);
        }
        (Err(error), Err(expected)) => assert_eq!(error, expected),
        (read, expected) => panic!("{read:?} differs from {expected:?}"),
    }

    let mut octets = [0; 8];
    let count = rest.len().min(8);
    octets[..count].copy_from_slice(&rest[..count]);
    let value = u64::from_le_bytes(octets);
    let field = PrefixedField::shortest(PrefixedInt::from(value));
    let mut encoded = Vec::new();
    integer::write::<N, _>(&mut encoded, first, field).unwrap();
    assert_eq!(
        reference::<N>(encoded[0], &encoded[1..])
            .0
            .map(|(value, _)| value),
        Ok(value)
    );
    let mask = u8::MAX >> (8 - N);
    assert_eq!(first & !mask, encoded[0] & !mask);
    if encoded.len() > 2 {
        assert_ne!(encoded.last(), Some(&0), "redundant top base-128 digit");
    }

    // A padded field is constructible exactly when it has an encoding, and
    // then writes the octets that read back to it.
    let padding = padding % 12;
    let valid = padding == 0
        || (shortest::<N>(value) > 0 && shortest::<N>(value) + usize::from(padding) <= 10);
    match PrefixedField::new::<N>(PrefixedInt::from(value), padding) {
        Ok(field) => {
            assert!(valid);
            let mut padded = Vec::new();
            integer::write::<N, _>(&mut padded, first, field).unwrap();
            assert_eq!(padded.len(), field.encoded_len::<N>());
            assert_eq!(padded.len(), encoded.len() + usize::from(padding));
            let mut tail = &padded[1..];
            assert_eq!(integer::read::<N>(padded[0], &mut tail), Ok(field));
            assert!(tail.is_empty());
        }
        Err(error) => {
            assert!(!valid);
            assert_eq!((error.padding(), error.prefix_bits()), (padding, N));
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let [width, first, rest @ ..] = data else {
        return;
    };
    let padding = width / 8;
    match width % 8 {
        0 => check::<1>(*first, rest, padding),
        1 => check::<2>(*first, rest, padding),
        2 => check::<3>(*first, rest, padding),
        3 => check::<4>(*first, rest, padding),
        4 => check::<5>(*first, rest, padding),
        5 => check::<6>(*first, rest, padding),
        6 => check::<7>(*first, rest, padding),
        _ => check::<8>(*first, rest, padding),
    }
});

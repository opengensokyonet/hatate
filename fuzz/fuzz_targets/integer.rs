//! Compare wire decoding and cursor movement with wider arithmetic.
#![no_main]
use hatate_qpack::integer::{self, ReadError};
use libfuzzer_sys::fuzz_target;

fn reference<const N: u8>(first: u8, rest: &[u8]) -> (Result<u64, ReadError>, usize) {
    let mask = (1u128 << N) - 1;
    let prefix = u128::from(first) & mask;
    if prefix < mask {
        return (Ok(prefix as u64), 0);
    }
    let mut value = prefix;
    let mut place = 1u128;
    for (i, &octet) in rest.iter().take(10).enumerate() {
        value += u128::from(octet % 128) * place;
        let Ok(result) = u64::try_from(value) else {
            return (Err(ReadError::Overflow), i + 1);
        };
        if octet < 128 {
            return (Ok(result), i + 1);
        }
        place *= 128;
    }
    if rest.len() >= 10 {
        (Err(ReadError::TooLong), 10)
    } else {
        (Err(ReadError::Incomplete), rest.len())
    }
}

fn check<const N: u8>(first: u8, rest: &[u8]) {
    let (expected, consumed) = reference::<N>(first, rest);
    let mut cursor = rest;
    assert_eq!(integer::read::<N>(first, &mut cursor), expected);
    assert_eq!(cursor.len(), rest.len() - consumed);

    let mut octets = [0; 8];
    let count = rest.len().min(8);
    octets[..count].copy_from_slice(&rest[..count]);
    let value = u64::from_le_bytes(octets);
    let mut encoded = Vec::new();
    integer::write::<N>(&mut encoded, first, value).unwrap();
    assert_eq!(
        reference::<N>(encoded[0], &encoded[1..]),
        (Ok(value), encoded.len() - 1)
    );
    let mask = u8::MAX >> (8 - N);
    assert_eq!(first & !mask, encoded[0] & !mask);
    if encoded.len() > 2 {
        assert_ne!(encoded.last(), Some(&0), "redundant top base-128 digit");
    }
}

fuzz_target!(|data: &[u8]| {
    let [width, first, rest @ ..] = data else {
        return;
    };
    match width % 8 {
        0 => check::<1>(*first, rest),
        1 => check::<2>(*first, rest),
        2 => check::<3>(*first, rest),
        3 => check::<4>(*first, rest),
        4 => check::<5>(*first, rest),
        5 => check::<6>(*first, rest),
        6 => check::<7>(*first, rest),
        _ => check::<8>(*first, rest),
    }
});

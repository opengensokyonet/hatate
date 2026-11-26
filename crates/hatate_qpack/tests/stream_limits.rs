//! The limits of the instruction streams: the defaults of RFC 9204, the
//! limits that follow from a table capacity, and limits set between
//! instructions.
mod common;
mod support;

use common::{Read as Instruction, octets};
use hatate_qpack::{
    decoder_instruction::{
        DecodeDecoderInstructionError, DecoderInstruction, DecoderStream, DecoderStreamLimits,
        StreamId,
    },
    encoder_instruction::{
        DecodeEncoderInstructionError as StartError, DecodeLiteralError,
        EncodeEncoderInstructionError, EncoderInstruction, EncoderStream, EncoderStreamLimits,
        NameReference,
    },
    integer::{PrefixedField, PrefixedInt},
};
use nitori_call::{ConstructedAccess, ReceiverAccess};
use nitori_codec::{DecodeFrom, EncodeInto};
use nitori_io::{Read, ReadChunk, calls::ReadValue};

fn run<T>(future: impl core::future::Future<Output = T>) -> T {
    nitori_call::__private::run_sync(future)
}

/// Two prefixed integers of at most 11 octets each, with nothing else.
const TWO_INTEGERS: usize = 22;

#[test]
fn a_table_capacity_gives_the_decoded_and_wire_limits_of_one_insertion() {
    // (capacity, max_decoded_len, max_wire_len). The entry overhead of RFC
    // 9204 Section 3.2.1 is 32 octets, so nothing is left of a capacity
    // below 33. The wire limit is the two integers, the decoded octets at 30
    // bits each rounded up to octets, and one more octet for the second
    // literal's rounding.
    for (capacity, decoded, wire) in [
        (0, 0, TWO_INTEGERS),
        (31, 0, TWO_INTEGERS),
        (32, 0, TWO_INTEGERS),
        (33, 1, TWO_INTEGERS + 4 + 1),
        (36, 4, TWO_INTEGERS + 15 + 1),
        (100, 68, TWO_INTEGERS + 255 + 1),
        (1000, 968, TWO_INTEGERS + 3630 + 1),
        (4096, 4064, TWO_INTEGERS + 15240 + 1),
    ] {
        let limits = EncoderStreamLimits::for_table_capacity(capacity);
        assert_eq!(limits.max_decoded_len, decoded, "capacity {capacity}");
        assert_eq!(limits.max_wire_len, wire, "capacity {capacity}");
    }
}

#[test]
fn the_wire_limit_holds_the_longest_insertion_of_a_capacity() {
    // Every capacity up to a few thousand, against the exact ceiling in
    // wider integers.
    for capacity in 0..4200u64 {
        let limits = EncoderStreamLimits::for_table_capacity(capacity);
        let decoded = u128::from(capacity.saturating_sub(32));
        assert_eq!(limits.max_decoded_len as u128, decoded);
        let literals = if decoded == 0 {
            0
        } else {
            (decoded * 30).div_ceil(8) + 1
        };
        assert_eq!(limits.max_wire_len as u128, 22 + literals, "{capacity}");
    }
}

#[test]
fn huge_capacities_saturate() {
    let huge = EncoderStreamLimits::for_table_capacity(u64::MAX);
    assert_eq!(
        huge.max_decoded_len,
        usize::try_from(u64::MAX - 32).unwrap_or(usize::MAX)
    );
    assert_eq!(huge.max_wire_len, usize::MAX);
    let edge = EncoderStreamLimits::for_table_capacity(u64::from(u32::MAX));
    assert_eq!(
        edge.max_decoded_len,
        usize::try_from(u64::from(u32::MAX) - 32).unwrap_or(usize::MAX)
    );
}

#[test]
fn the_defaults_are_those_of_a_table_of_capacity_0() {
    // SETTINGS_QPACK_MAX_TABLE_CAPACITY is 0 until a SETTINGS frame says
    // otherwise (RFC 9204 Section 5).
    assert_eq!(
        EncoderStreamLimits::default(),
        EncoderStreamLimits {
            max_wire_len: 22,
            max_decoded_len: 0,
        }
    );
    assert_eq!(
        EncoderStreamLimits::default(),
        EncoderStreamLimits::for_table_capacity(0)
    );
    // One prefixed integer takes at most 11 octets.
    assert_eq!(
        DecoderStreamLimits::default(),
        DecoderStreamLimits { max_wire_len: 11 }
    );
}

async fn next_encoder<A: ReceiverAccess<Family: ReadChunk<Metadata = ()>>>(
    reader: &mut EncoderStream<A>,
) -> Result<Option<Instruction>, StartError<<A::Family as Read>::Error>> {
    let next = Option::<ReadValue<Instruction, ()>>::decode_from(reader).await?;
    Ok(next.map(|read| read.value))
}

async fn next_decoder<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    reader: &mut DecoderStream<A>,
) -> Result<Option<DecoderInstruction>, DecodeDecoderInstructionError<F::Error>> {
    let next = Option::<ReadValue<DecoderInstruction, ()>>::decode_from(reader).await?;
    Ok(next.map(|read| read.value))
}

fn int(value: u64) -> PrefixedField {
    PrefixedField::shortest(PrefixedInt::from(value))
}

#[test]
fn a_stream_reports_the_limits_it_was_given_and_the_ones_set() {
    let first = EncoderStreamLimits {
        max_wire_len: 5,
        max_decoded_len: 3,
    };
    let mut stream = EncoderStream::new(ConstructedAccess::new(&b""[..]), first);
    assert_eq!(stream.limits(), first);
    stream.set_limits(EncoderStreamLimits::default());
    assert_eq!(stream.limits(), EncoderStreamLimits::default());
    let mut stream = DecoderStream::new(
        ConstructedAccess::new(&b""[..]),
        DecoderStreamLimits { max_wire_len: 4 },
    );
    assert_eq!(stream.limits(), DecoderStreamLimits { max_wire_len: 4 });
    stream.set_limits(DecoderStreamLimits { max_wire_len: 9 });
    assert_eq!(stream.limits(), DecoderStreamLimits { max_wire_len: 9 });
}

#[test]
fn encoder_limits_set_between_instructions_apply_to_the_next_one() {
    // Duplicate 0 (one octet), then an insertion of ":path" (static 1) with
    // the value "ab", three wire octets, two decoded octets.
    let wire = [0x00, 0xc1, 0x02, b'a', b'b'];
    let mut stream = EncoderStream::new(
        ConstructedAccess::new(&wire[..]),
        EncoderStreamLimits {
            max_wire_len: 1,
            max_decoded_len: 0,
        },
    );
    assert_eq!(
        run(next_encoder(&mut stream)).unwrap(),
        Some(EncoderInstruction::Duplicate { index: int(0) })
    );
    // The insertion needs at least two octets before its value.
    stream.set_limits(EncoderStreamLimits {
        max_wire_len: 1,
        max_decoded_len: 2,
    });
    assert!(matches!(
        run(next_encoder(&mut stream)),
        Err(StartError::WireLimit { .. })
    ));

    let mut stream = EncoderStream::new(
        ConstructedAccess::new(&wire[..]),
        EncoderStreamLimits::default(),
    );
    assert_eq!(
        run(next_encoder(&mut stream)).unwrap(),
        Some(EncoderInstruction::Duplicate { index: int(0) })
    );
    stream.set_limits(EncoderStreamLimits {
        max_wire_len: 4,
        max_decoded_len: 1,
    });
    // Only one decoded octet is allowed, and the value has two.
    assert!(matches!(
        run(next_encoder(&mut stream)),
        Err(StartError::Value {
            source: DecodeLiteralError::DecodedLength { .. }
        })
    ));
}

#[test]
fn a_larger_limit_set_later_admits_what_the_smaller_refused() {
    let wire = [0xc1, 0x02, b'a', b'b'];
    for (limits, admitted) in [
        (
            EncoderStreamLimits {
                max_wire_len: 4,
                max_decoded_len: 1,
            },
            false,
        ),
        (
            EncoderStreamLimits {
                max_wire_len: 4,
                max_decoded_len: 2,
            },
            true,
        ),
    ] {
        let mut stream = EncoderStream::new(ConstructedAccess::new(&wire[..]), limits);
        let read = run(next_encoder(&mut stream));
        assert_eq!(read.is_ok(), admitted, "{read:?}");
        if let Ok(Some(EncoderInstruction::InsertWithNameReference {
            name: NameReference::Static { index },
            value,
        })) = read
        {
            assert_eq!(index.value().entry().0, b":path");
            assert_eq!(octets(&value), b"ab");
        }
    }
}

#[test]
fn decoder_limits_set_between_instructions_apply_to_the_next_one() {
    let id = |id| PrefixedField::shortest(StreamId::try_from(id).unwrap());
    // Stream cancellation of stream 64 takes two octets.
    let wire = [0x84, 0x7f, 0x01];
    let mut stream = DecoderStream::new(
        ConstructedAccess::new(&wire[..]),
        DecoderStreamLimits { max_wire_len: 1 },
    );
    assert_eq!(
        run(next_decoder(&mut stream)).unwrap(),
        Some(DecoderInstruction::SectionAcknowledgment { stream_id: id(4) })
    );
    assert!(run(next_decoder(&mut stream)).is_err());

    let mut stream = DecoderStream::new(
        ConstructedAccess::new(&wire[..]),
        DecoderStreamLimits { max_wire_len: 1 },
    );
    run(next_decoder(&mut stream)).unwrap();
    stream.set_limits(DecoderStreamLimits { max_wire_len: 2 });
    assert_eq!(
        run(next_decoder(&mut stream)).unwrap(),
        Some(DecoderInstruction::StreamCancellation { stream_id: id(64) })
    );
    assert_eq!(run(next_decoder(&mut stream)).unwrap(), None);
}

/// The octets of `symbols` octets 10, whose code has 30 bits (0x3ffffffc in
/// RFC 7541 Appendix B), padded with ones.
fn coded(symbols: usize) -> Vec<u8> {
    let mut bits: Vec<bool> = Vec::new();
    for _ in 0..symbols {
        bits.extend((0..30).rev().map(|bit| (0x3fff_fffcu32 >> bit) & 1 == 1));
    }
    while bits.len() % 8 != 0 {
        bits.push(true);
    }
    bits.chunks(8)
        .map(|chunk| {
            chunk
                .iter()
                .fold(0u8, |byte, &bit| byte << 1 | u8::from(bit))
        })
        .collect()
}

#[test]
fn the_wire_limit_of_a_capacity_admits_an_insertion_at_the_longest_huffman_wire() {
    // A name of one octet 10 and a value of three take 4 and 12 octets with
    // their padding of ones: 16 octets, one more than 4 decoded octets would
    // take in one literal at 30 bits each.
    let (name_octets, value_octets) = (coded(1), coded(3));
    assert_eq!((name_octets.len(), value_octets.len()), (4, 12));
    let mut wire = vec![0x60 | 4]; // literal name, Huffman, length 4
    wire.extend(&name_octets);
    wire.push(0x80 | 12); // Huffman value, length 12
    wire.extend(&value_octets);
    // A capacity that leaves four decoded octets.
    let limits = EncoderStreamLimits::for_table_capacity(36);
    assert_eq!(limits.max_decoded_len, 4);
    assert!(wire.len() <= limits.max_wire_len);
    // The two payloads are longer than one literal of four octets would be.
    assert!(name_octets.len() + value_octets.len() > (4 * 30usize).div_ceil(8));
    assert!(name_octets.len() + value_octets.len() <= limits.max_wire_len - TWO_INTEGERS);
    let mut stream = EncoderStream::new(ConstructedAccess::new(&wire[..]), limits);
    let Ok(Some(EncoderInstruction::InsertWithLiteralName { name, value })) =
        run(next_encoder(&mut stream))
    else {
        panic!("an insertion with a literal name");
    };
    assert_eq!((octets(&name), octets(&value)), (&[10][..], &[10; 3][..]));
}

#[test]
fn a_writer_checks_the_limits_of_a_capacity_before_writing() {
    // The same insertion, made: within the limits of a capacity of 36, and
    // not within those of 35, which leave three decoded octets.
    let insertion = || -> EncoderInstruction<&'static [u8], &'static [u8]> {
        EncoderInstruction::InsertWithLiteralName {
            name: support::huffman(&[10][..]),
            value: support::huffman(&[10; 3][..]),
        }
    };
    assert_eq!((insertion().wire_len(), insertion().decoded_len()), (18, 4));
    let mut output = ConstructedAccess::new(Vec::new());
    let mut stream = EncoderStream::new(&mut output, EncoderStreamLimits::for_table_capacity(35));
    assert!(matches!(
        run(insertion().encode_into(&mut stream)),
        Err(EncodeEncoderInstructionError::DecodedLength { source })
            if source.length() == 4 && source.remaining() == 3
    ));
    stream.set_limits(EncoderStreamLimits::for_table_capacity(36));
    run(insertion().encode_into(&mut stream)).unwrap();
    let mut expected = vec![0x64];
    expected.extend(coded(1));
    expected.push(0x8c);
    expected.extend(coded(3));
    assert_eq!(output.into_inner(), expected);
}

#[test]
fn the_defaults_bound_the_literals_only() {
    // With no literal octet allowed, an insertion that has none passes the
    // limits, though its entry of 32 octets does not fit a capacity of 0:
    // a referenced name and an empty value, and an empty name and value.
    let wire = [0xc0, 0x00, 0x40, 0x00];
    let mut stream = EncoderStream::new(
        ConstructedAccess::new(&wire[..]),
        EncoderStreamLimits::default(),
    );
    assert!(matches!(
        run(next_encoder(&mut stream)),
        Ok(Some(EncoderInstruction::InsertWithNameReference { .. }))
    ));
    assert!(matches!(
        run(next_encoder(&mut stream)),
        Ok(Some(EncoderInstruction::InsertWithLiteralName { .. }))
    ));
    // A name of one octet is past them.
    let wire = [0x41, b'x', 0x00];
    let mut stream = EncoderStream::new(
        ConstructedAccess::new(&wire[..]),
        EncoderStreamLimits::default(),
    );
    assert!(matches!(
        run(next_encoder(&mut stream)),
        Err(StartError::Name {
            source: DecodeLiteralError::DecodedLength { .. }
        })
    ));
}

//! The limits of the instruction streams: the defaults of RFC 9204, the
//! limits that follow from a table capacity, and limits set between
//! instructions.
use hatate_qpack::{
    decoder_instruction::{DecoderInstruction, DecoderStream, DecoderStreamLimits, StreamId},
    encoder_instruction::{
        EncoderStream, EncoderStreamLimits, NameReference, Started,
        codec::{LiteralHeaderError, StartError, ValueError},
    },
};
use nitori_call::{ConstructedAccess, ReceiverAccess};
use nitori_codec::DecodeFrom;
use nitori_io::{Read, calls::ReadValue};

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

async fn next_encoder<'a, F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    reader: &'a mut EncoderStream<A>,
) -> Result<Option<Started<'a, A>>, StartError<F::Error>> {
    let next = Option::<ReadValue<Started<'a, A>, ()>>::decode_from(reader).await?;
    Ok(next.map(|read| read.value))
}

async fn next_decoder<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    reader: &mut DecoderStream<A>,
) -> Result<Option<DecoderInstruction>, hatate_qpack::decoder_instruction::codec::ReadError<F::Error>>
{
    let next = Option::<ReadValue<DecoderInstruction, ()>>::decode_from(reader).await?;
    Ok(next.map(|read| read.value))
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
    assert!(matches!(
        run(next_encoder(&mut stream)),
        Ok(Some(Started::Duplicate(0)))
    ));
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
    assert!(matches!(
        run(next_encoder(&mut stream)),
        Ok(Some(Started::Duplicate(0)))
    ));
    stream.set_limits(EncoderStreamLimits {
        max_wire_len: 4,
        max_decoded_len: 1,
    });
    let Ok(Some(Started::InsertWithNameReference {
        name: NameReference::Static(_),
        value,
    })) = run(next_encoder(&mut stream))
    else {
        panic!("an insertion with a name reference");
    };
    // Only one decoded octet is allowed, and the value has two.
    assert!(matches!(
        run(value.open()),
        Err(ValueError::Value {
            source: LiteralHeaderError::DecodedLength { .. }
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
        let Ok(Some(Started::InsertWithNameReference { value, .. })) =
            run(next_encoder(&mut stream))
        else {
            panic!("an insertion with a name reference");
        };
        assert_eq!(run(value.open()).is_ok(), admitted);
    }
}

#[test]
fn decoder_limits_set_between_instructions_apply_to_the_next_one() {
    // Stream cancellation of stream 64 takes two octets.
    let wire = [0x84, 0x7f, 0x01];
    let mut stream = DecoderStream::new(
        ConstructedAccess::new(&wire[..]),
        DecoderStreamLimits { max_wire_len: 1 },
    );
    assert_eq!(
        run(next_decoder(&mut stream)).unwrap(),
        Some(DecoderInstruction::SectionAcknowledgment(
            StreamId::try_from(4).unwrap()
        ))
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
        Some(DecoderInstruction::StreamCancellation(
            StreamId::try_from(64).unwrap()
        ))
    );
    assert_eq!(run(next_decoder(&mut stream)).unwrap(), None);
}

#[test]
fn the_wire_limit_of_a_capacity_admits_an_insertion_at_the_longest_huffman_wire() {
    // The octet 10 has a 30-bit code (0x3ffffffc) in RFC 7541 Appendix B.
    // A name of one such octet and a value of three take 4 and 12 octets
    // with their padding of ones: 16 octets, one more than 4 decoded octets
    // would take in one literal at 30 bits each.
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
    let Ok(Some(Started::InsertWithLiteralName(mut name))) = run(next_encoder(&mut stream)) else {
        panic!("an insertion with a literal name");
    };
    let mut decoded = Vec::<u8>::new();
    {
        use nitori_io::prelude::*;
        let hatate_qpack::encoder_instruction::literal::LiteralSource::Huffman(mut source) =
            name.source()
        else {
            panic!("a Huffman name");
        };
        let mut buffer = [0u8; 8];
        while let Some(segment) = run(source.read(&mut &mut buffer[..])).unwrap() {
            decoded.extend(&buffer[..segment.count.get()]);
        }
    }
    assert_eq!(decoded, [10]);
    let _ = name.finish().unwrap();
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
    let Ok(Some(Started::InsertWithNameReference { value, .. })) = run(next_encoder(&mut stream))
    else {
        panic!("an insertion with a name reference");
    };
    run(value.open()).unwrap().value.finish().unwrap();
    let Ok(Some(Started::InsertWithLiteralName(name))) = run(next_encoder(&mut stream)) else {
        panic!("an insertion with a literal name");
    };
    let value = name.finish().unwrap();
    run(value.open()).unwrap().value.finish().unwrap();
    // A name of one octet is past them.
    let wire = [0x41, b'x', 0x00];
    let mut stream = EncoderStream::new(
        ConstructedAccess::new(&wire[..]),
        EncoderStreamLimits::default(),
    );
    assert!(matches!(
        run(next_encoder(&mut stream)),
        Err(StartError::Name {
            source: LiteralHeaderError::DecodedLength { .. }
        })
    ));
}

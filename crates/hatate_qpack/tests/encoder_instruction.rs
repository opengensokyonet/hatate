#![feature(impl_trait_in_assoc_type)]
mod common;
mod support;

use bytes::{Bytes, BytesMut};
use common::{PausingSink, Trickle, encoder_stream, next_encoder, octets};
use core::fmt::Debug;
use hatate_qpack::{
    encoder_instruction::{
        DecodeEncoderInstructionError as ReadError, DecodeLiteralError,
        EncodeEncoderInstructionError as WriteError, EncoderInstruction as E, EncoderStream,
        EncoderStreamLimits, NameReference,
    },
    huffman,
    integer::{PrefixedField, PrefixedInt},
    static_table,
    string_literal::{
        CopiedBytes, JoinedBytes, LiteralBytes, StringLiteral, WriteError as Literal,
    },
};
use nitori_call::{AsAccess, ReceiverAccess, call};
use nitori_codec::{DecodeFrom, EncodeInto, EncodedLen};
use nitori_io::{
    Combine, Write,
    calls::{ReadValue, WriteAllError, WriteAllExt as _},
    prelude::*,
};
use support::{huffman, now, raw};

/// An instruction made in a test, of borrowed octets.
type Made = E<&'static [u8], &'static [u8]>;

fn int(value: u64) -> PrefixedField {
    PrefixedField::shortest(PrefixedInt::from(value))
}

fn limits(wire: usize, decoded: usize) -> EncoderStreamLimits {
    EncoderStreamLimits {
        max_wire_len: wire,
        max_decoded_len: decoded,
    }
}

#[call(sync)]
async fn insertion<F: ReadChunk<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    bad: bool,
) where
    <F as Read>::Error: Debug,
{
    let mut reader = encoder_stream(io);
    let next = next_encoder(&mut reader, 8, 8).await;
    if bad {
        assert!(matches!(
            next,
            Err(ReadError::Value {
                source: DecodeLiteralError::Huffman {
                    source: huffman::DecodeError::InvalidPadding
                }
            })
        ));
        assert!(matches!(
            next_encoder(&mut reader, 8, 8).await,
            Err(ReadError::Interrupted)
        ));
        return;
    }
    let Some(E::InsertWithLiteralName { name, value }) = next.unwrap() else {
        panic!()
    };
    assert!(!name.is_huffman() && value.is_huffman());
    assert_eq!((octets(&name), octets(&value)), (&b"x"[..], &b"a"[..]));
    assert_eq!(
        next_encoder(&mut reader, 1, 0).await.unwrap().unwrap(),
        E::Duplicate { index: int(0) }
    );
}

#[test]
fn name_then_huffman_value_on_the_same_cursor() {
    let mut good = &[0x41, b'x', 0x81, 0x1f, 0, 0x20][..];
    good.sync_insertion_unpin(false);
    assert_eq!(good, [0x20]);
    let mut bad = &[0x41, b'x', 0x81, 0x18, 0, 0x20][..];
    bad.sync_insertion_unpin(true);
    assert_eq!(bad, [0, 0x20]);
}

#[call(sync)]
async fn budgets<F: ReadChunk<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    wire: usize,
    decoded: usize,
) where
    <F as Read>::Error: Debug,
{
    let mut reader = encoder_stream(io);
    match next_encoder(&mut reader, wire, decoded).await {
        Ok(Some(E::InsertWithLiteralName { name, value })) => {
            assert_eq!((wire, decoded), (8, 9));
            assert_eq!(octets(&name), b"x");
            assert_eq!(octets(&value), b"00000000");
        }
        Err(ReadError::Value {
            source: DecodeLiteralError::WireLimit { source },
        }) => {
            assert_eq!(wire, 7);
            assert_eq!(source.required(), 8);
        }
        Err(ReadError::Value {
            source:
                DecodeLiteralError::Huffman {
                    source: huffman::DecodeError::OutputTooLong { limit },
                },
        }) => {
            assert_eq!(decoded, 8);
            // The name took one of the eight.
            assert_eq!(limit, 7);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_two_budgets_follow_the_name_and_the_value() {
    for (wire, decoded) in [(8, 9), (7, 9), (8, 8)] {
        let mut input = &[0x41, b'x', 0x85, 0, 0, 0, 0, 0, 0x20][..];
        input.sync_budgets_unpin(wire, decoded);
        assert_eq!(
            input,
            if wire == 7 {
                &[0, 0, 0, 0, 0, 0x20][..]
            } else {
                &[0x20][..]
            }
        );
    }
}

#[call(sync)]
async fn reference<F: ReadChunk<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    truncated: bool,
) where
    <F as Read>::Error: Debug,
{
    let mut reader = encoder_stream(io);
    assert_eq!(
        next_encoder(&mut reader, 3, 0).await.unwrap().unwrap(),
        E::SetDynamicTableCapacity { capacity: int(220) }
    );
    let next = next_encoder(&mut reader, 64, 64).await;
    if truncated {
        assert!(matches!(
            next,
            Err(ReadError::Value { source: DecodeLiteralError::Truncated { missing } })
                if missing.get() == 12
        ));
        return;
    }
    let Some(E::InsertWithNameReference {
        name: NameReference::Static { index },
        value,
    }) = next.unwrap()
    else {
        panic!()
    };
    assert_eq!(index.value().entry().0, b":authority");
    assert_eq!(octets(&value), b"www.example.com");
}

#[test]
fn appendix_b2_and_truncated_raw_literal() {
    let mut src = &b"\x3f\xbd\x01\xc0\x0fwww.example.com\x20"[..];
    src.sync_reference_unpin(false);
    assert_eq!(src, [0x20]);
    let mut src = &b"\x3f\xbd\x01\xc0\x0fwww"[..];
    src.sync_reference_unpin(true);
    assert!(src.is_empty());
}

#[call(sync)]
async fn across_octets<F: ReadChunk<Metadata = ()>, A: ReceiverAccess<Family = F>>(io: &mut A)
where
    <F as Read>::Error: Debug,
{
    let mut reader = encoder_stream(io);
    let Some(E::InsertWithLiteralName { name, value }) =
        next_encoder(&mut reader, 16, 16).await.unwrap()
    else {
        panic!()
    };
    assert!(name.is_huffman());
    assert_eq!(octets(&name), b"www.example.com");
    assert_eq!(octets(&value), b"x");
    assert_eq!(
        next_encoder(&mut reader, 1, 0).await.unwrap().unwrap(),
        E::Duplicate { index: int(0) }
    );
}

#[test]
fn huffman_and_raw_literals_resume_after_each_octet() {
    use core::{
        future::Future,
        pin::{Pin, pin},
        task::{Context, Poll, Waker},
    };
    use nitori_call::CallExecutor;
    // RFC 7541 Appendix C.4 hostname in an RFC 9204 literal name.
    let mut host = Trickle {
        rest: b"\x6c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff\x01x\x00\x20",
        waiting: false,
    };
    {
        let mut call = pin!(CallExecutor::execute(
            Pin::new(&mut host),
            AcrossOctets::new()
        ));
        let mut cx = Context::from_waker(Waker::noop());
        // One wait for each octet of the two instructions.
        for _ in 0..16 {
            assert!(call.as_mut().poll(&mut cx).is_pending());
        }
        assert!(matches!(call.as_mut().poll(&mut cx), Poll::Ready(())));
    }
    assert_eq!(host.rest, [0x20]);
}

#[call(sync)]
async fn borrowed_chunks<F, A>(io: &mut A) -> Vec<&'static [u8]>
where
    F: ReadChunk<Chunk = &'static [u8], Metadata = ()>,
    <F as Read>::Error: Debug,
    A: ReceiverAccess<Family = F>,
{
    let mut reader = encoder_stream(io);
    reader.set_limits(limits(5, 3));
    let next = Option::<ReadValue<E<Vec<&'static [u8]>, Vec<u8>>, ()>>::decode_from(&mut reader)
        .await
        .unwrap()
        .unwrap()
        .value;
    let E::InsertWithNameReference {
        name: NameReference::Relative { index },
        value,
    } = next
    else {
        panic!()
    };
    assert_eq!(index, int(0));
    let LiteralBytes::Raw(chunks) = value.into_bytes() else {
        panic!()
    };
    chunks
}

#[call(sync)]
async fn shared_chunks<F: ReadChunk<Chunk = Bytes, Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> Bytes
where
    <F as Read>::Error: Debug,
{
    let mut reader = encoder_stream(io);
    reader.set_limits(limits(5, 3));
    let next = Option::<ReadValue<E<JoinedBytes, BytesMut>, ()>>::decode_from(&mut reader)
        .await
        .unwrap()
        .unwrap()
        .value;
    let E::InsertWithNameReference { value, .. } = next else {
        panic!()
    };
    let LiteralBytes::Raw(bytes) = value.into_bytes() else {
        panic!()
    };
    bytes.into_bytes()
}

#[test]
fn raw_literals_keep_the_chunks_of_the_input_without_copying() {
    let wire: &'static [u8] = b"\x80\x03abc\x20";
    let mut input = wire;
    let chunks = input.sync_borrowed_chunks_unpin();
    assert_eq!(chunks.len(), 1);
    assert!(core::ptr::eq(chunks[0], &wire[2..5]));
    assert_eq!(input, [0x20]);
    // A literal that arrives in one chunk of `Bytes` shares its storage.
    let wire = Bytes::from_static(b"\x80\x03abc\x20");
    let mut input = wire.clone();
    let value = input.sync_shared_chunks_unpin();
    assert_eq!(value, &b"abc"[..]);
    assert_eq!(value.as_ptr(), wire[2..].as_ptr());
    assert_eq!(input, &b"\x20"[..]);
}

/// Reads every instruction of `input` within `wire` and `decoded`, and
/// writes each to `output` within the same limits as soon as it is read.
#[call(sync)]
async fn relay<F: ReadChunk<Chunk = Bytes, Metadata = ()>, G: Write<Report = ()>>(
    input: &mut impl ReceiverAccess<Family = F>,
    output: &mut impl ReceiverAccess<Family = G>,
    wire: usize,
    decoded: usize,
) -> usize
where
    <F as Read>::Error: Debug,
    <G as Write>::Error: Debug,
{
    let mut reader = EncoderStream::new(input, limits(wire, decoded));
    let mut writer = EncoderStream::new(output, limits(wire, decoded));
    let mut count = 0;
    type Next = Option<ReadValue<E<JoinedBytes, BytesMut>, ()>>;
    while let Some(read) = Next::decode_from(&mut reader).await.unwrap() {
        read.value.encode_into(&mut writer).await.unwrap();
        count += 1;
    }
    count
}

/// As [`relay`], from a source of borrowed chunks.
#[call(sync)]
async fn relay_copied<F, G>(
    input: &mut impl ReceiverAccess<Family = F>,
    output: &mut impl ReceiverAccess<Family = G>,
) -> usize
where
    F: ReadChunk<Chunk = &'static [u8], Metadata = ()>,
    G: Write<Report = ()>,
    <F as Read>::Error: Debug,
    <G as Write>::Error: Debug,
{
    let limits = limits(usize::MAX, usize::MAX);
    let mut reader = EncoderStream::new(input, limits);
    let mut writer = EncoderStream::new(output, limits);
    let mut count = 0;
    type Next = Option<ReadValue<E<CopiedBytes, Vec<u8>>, ()>>;
    while let Some(read) = Next::decode_from(&mut reader).await.unwrap() {
        // `Vec<u8>` collects the decoded octets but is not a `Buf`: move
        // them into one that is.
        let value = match read.value {
            E::SetDynamicTableCapacity { capacity } => E::SetDynamicTableCapacity { capacity },
            E::Duplicate { index } => E::Duplicate { index },
            E::InsertWithNameReference { name, value } => E::InsertWithNameReference {
                name,
                value: rehome::<7>(value),
            },
            E::InsertWithLiteralName { name, value } => E::InsertWithLiteralName {
                name: rehome::<5>(name),
                value: rehome::<7>(value),
            },
        };
        value.encode_into(&mut writer).await.unwrap();
        count += 1;
    }
    count
}

/// The literal with its Huffman octets in `Bytes`, keeping its length
/// prefix of `N` bits.
fn rehome<const N: u8>(
    literal: StringLiteral<CopiedBytes, Vec<u8>>,
) -> StringLiteral<CopiedBytes, Bytes> {
    let padding = literal.length().padding();
    let rebuilt = match literal.into_bytes() {
        LiteralBytes::Raw(bytes) => now(StringLiteral::raw(bytes)).unwrap(),
        LiteralBytes::Huffman(decoded) => StringLiteral::huffman(Bytes::from(decoded)).unwrap(),
    };
    rebuilt.with_length_padding::<N>(padding).unwrap()
}

/// Raw and Huffman literals, names and values, whose length prefixes have
/// a zero group: lengths of at least 31 (names) and 127 (values), so that
/// their prefixes take a continuation octet.
fn padded_literals() -> Vec<u8> {
    let mut wire = vec![0x5f, 0x80, 0x00];
    wire.extend([b'n'; 31]);
    wire.extend([0x7f, 0x80, 0x00]);
    wire.extend([b'v'; 127]);
    // "a" has a five-bit code: 50 of them take 32 octets, 210 take 132.
    let mut name = Vec::new();
    huffman::encode(&mut name, &[b'a'; 50][..]).unwrap();
    assert_eq!(name.len(), 32);
    let mut value = Vec::new();
    huffman::encode(&mut value, &[b'a'; 210][..]).unwrap();
    assert_eq!(value.len(), 132);
    wire.extend([0x7f, 0x81, 0x00]);
    wire.extend(name);
    wire.extend([0xff, 0x85, 0x00]);
    wire.extend(value);
    wire
}

#[test]
fn instructions_read_and_written_back_yield_their_original_octets() {
    let padded = padded_literals();
    let cases: &[&[u8]] = &[
        // RFC 9204 Appendix B.2: capacity 220 and a static name reference.
        b"\x3f\xbd\x01\xc0\x0fwww.example.com",
        // RFC 9204 Appendix B.3: a literal name, a duplicate.
        b"\x4acustom-key\x0ccustom-value\x02",
        // A capacity and a duplicate with one and two zero groups.
        b"\x3f\xbd\x81\x00\x1f\x80\x80\x00",
        // Static and relative name indices with a zero group, the second
        // in the longest encoding a stream reads, of ten continuation
        // octets.
        b"\xff\x80\x00\x00\xbf\x80\x80\x80\x80\x80\x80\x80\x80\x80\x00\x00",
        &padded,
        // Huffman name ("www.example.com") and value ("a").
        b"\x6c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff\x81\x1f",
        // Empty raw and Huffman literals.
        b"\x40\x00\x60\x80\xc0\x80",
    ];
    for &case in cases {
        let wire = Bytes::copy_from_slice(case);
        let mut hosts = (wire.clone(), Vec::new());
        assert!(hosts.sync_relay_unpin(usize::MAX, usize::MAX) > 0);
        assert_eq!(hosts.1, case, "{case:x?}");
    }
    // The same from a source of borrowed chunks, copying the raw octets.
    for &case in cases {
        let wire: &'static [u8] = Vec::leak(case.to_vec());
        let mut hosts = (wire, Vec::new());
        assert!(hosts.sync_relay_copied_unpin() > 0);
        assert_eq!(hosts.1, case, "{case:x?}");
    }
}

/// Why writing an instruction made of borrowed octets to a sink whose
/// failures are `W` failed.
type Refused<W> = WriteError<W, WriteAllError<W>>;

/// Writes each instruction to one stream within `wire` and `decoded`,
/// whatever each returns.
#[call(sync)]
async fn put_each<G: Write<Report = ()>>(
    output: &mut impl ReceiverAccess<Family = G>,
    instructions: Vec<Made>,
    wire: usize,
    decoded: usize,
) -> Vec<Result<(), Refused<<G as Write>::Error>>> {
    let mut writer = EncoderStream::new(output, limits(wire, decoded));
    let mut results = Vec::new();
    for instruction in instructions {
        results.push(instruction.encode_into(&mut writer).await.map(|_| ()));
    }
    results
}

fn static_name(index: u64) -> NameReference {
    NameReference::Static {
        index: PrefixedField::shortest(static_table::Index::try_from(index).unwrap()),
    }
}

#[test]
fn written_instructions_match_appendix_b_and_check_their_limits_first() {
    let mut output = Vec::new();
    let results = output.sync_put_each_unpin(
        vec![
            E::SetDynamicTableCapacity { capacity: int(220) },
            // Too long for the wire limit of 17 below: nothing of it is
            // written.
            E::InsertWithNameReference {
                name: static_name(0),
                value: raw(&b"www.example.com.."[..]),
            },
            E::InsertWithNameReference {
                name: static_name(0),
                value: raw(&b"www.example.com"[..]),
            },
            E::InsertWithNameReference {
                name: NameReference::Relative { index: int(63) },
                value: raw(&b""[..]),
            },
            E::Duplicate { index: int(31) },
        ],
        17,
        15,
    );
    assert!(results[0].is_ok());
    assert!(matches!(
        &results[1],
        Err(WriteError::WireLimit { source }) if source.required() == 19 && source.limit() == 17
    ));
    assert!(results[2..].iter().all(Result::is_ok), "{results:?}");
    assert_eq!(
        output,
        b"\x3f\xbd\x01\xc0\x0fwww.example.com\xbf\x00\x00\x1f\x00"
    );
}

#[test]
fn the_decoded_limit_counts_both_literals_and_not_a_referenced_name() {
    let insertion = || E::InsertWithLiteralName {
        name: raw(&b"color"[..]),
        value: raw(&b"blue"[..]),
    };
    let reference = E::InsertWithNameReference {
        name: static_name(0),
        value: raw(&b"blue"[..]),
    };
    assert_eq!((insertion().decoded_len(), reference.decoded_len()), (9, 4));
    assert_eq!(insertion().wire_len(), 11);
    let mut output = Vec::new();
    let results = output.sync_put_each_unpin(
        vec![insertion(), reference, E::Duplicate { index: int(0) }],
        11,
        8,
    );
    assert!(matches!(
        &results[0],
        Err(WriteError::DecodedLength { source }) if source.length() == 9 && source.remaining() == 8
    ));
    // A refused instruction leaves the stream at the boundary.
    assert!(results[1].is_ok() && results[2].is_ok(), "{results:?}");
    assert_eq!(output, b"\xc0\x04blue\x00");
    let mut output = Vec::new();
    let results = output.sync_put_each_unpin(vec![insertion()], 10, 9);
    assert!(matches!(
        &results[0],
        Err(WriteError::WireLimit { source }) if source.required() == 11 && source.limit() == 10
    ));
    assert!(output.is_empty());
}

#[test]
fn huffman_literals_are_encoded_as_they_are_written() {
    const HOST: &[u8] = b"\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff";
    let insertion = |name: &'static [u8], value: &'static [u8]| E::InsertWithLiteralName {
        name: huffman(name),
        value: huffman(value),
    };
    let mut output = Vec::new();
    let results = output.sync_put_each_unpin(
        vec![
            insertion(b"www.example.com", b"a"),
            E::Duplicate { index: int(2) },
        ],
        usize::MAX,
        16,
    );
    assert!(results.iter().all(Result::is_ok), "{results:?}");
    assert_eq!(output, [&[0x6c][..], HOST, &[0x81, 0x1f, 2]].concat());
    // The decoded octets, not the encoded ones, count toward the limit.
    let mut output = Vec::new();
    let results =
        output.sync_put_each_unpin(vec![insertion(b"www.example.com", b"a")], usize::MAX, 15);
    assert!(matches!(
        &results[0],
        Err(WriteError::DecodedLength { source }) if source.length() == 16
    ));
    assert!(output.is_empty());
    let mut output = Vec::new();
    let results = output.sync_put_each_unpin(
        vec![insertion(b"", b""), E::Duplicate { index: int(2) }],
        usize::MAX,
        0,
    );
    assert!(results.iter().all(Result::is_ok), "{results:?}");
    assert_eq!(output, [0x60, 0x80, 2]);
}

#[test]
fn a_field_without_an_encoding_in_its_position_is_refused_before_writing() {
    // 63 takes a continuation octet in a prefix of five or six bits; 31
    // takes one in a five-bit prefix and none in a seven-bit one, where its
    // padding has no encoding.
    let index = PrefixedField::new::<6>(PrefixedInt::from(63u8), 1).unwrap();
    let length_padded = raw::<_, &'static [u8]>(&[b'x'; 31][..])
        .with_length_padding::<5>(1)
        .unwrap();
    let mut output = Vec::new();
    let results = output.sync_put_each_unpin(
        vec![
            // The index of a name reference has six prefix bits: valid.
            E::InsertWithNameReference {
                name: NameReference::Relative { index },
                value: raw(&b""[..]),
            },
            // The same field as a capacity, of five bits: valid too.
            E::SetDynamicTableCapacity { capacity: index },
            // A name length padded for five bits, moved to the value, of
            // seven bits, where 31 fits in the prefix.
            E::InsertWithLiteralName {
                name: raw(&b""[..]),
                value: length_padded.clone(),
            },
            E::InsertWithLiteralName {
                name: length_padded,
                value: raw(&b""[..]),
            },
        ],
        usize::MAX,
        usize::MAX,
    );
    assert!(results[0].is_ok() && results[1].is_ok(), "{results:?}");
    assert!(matches!(
        &results[2],
        Err(WriteError::Value {
            source: Literal::Padding { .. }
        })
    ));
    assert!(results[3].is_ok(), "{results:?}");
    let mut expected = vec![0xbf, 0x80, 0x00, 0x00, 0x3f, 0xa0, 0x00];
    expected.extend_from_slice(&[0x5f, 0x80, 0x00]);
    expected.extend_from_slice(&[b'x'; 31]);
    expected.push(0x00);
    assert_eq!(output, expected);
}

/// A raw payload that reports one length and writes another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Liar {
    claimed: u64,
    actual: &'static [u8],
}

impl EncodedLen for Liar {
    type LengthError = !;
    async fn encoded_len(&mut self) -> Result<u64, !> {
        Ok(self.claimed)
    }
}

impl<K: AsAccess<Family: Write<Report: Combine>>> EncodeInto<K> for Liar {
    type Output = <K::Family as Write>::Report;
    type Error = WriteAllError<<K::Family as Write>::Error>;
    async fn encode_into(self, mut sink: K) -> Result<Self::Output, Self::Error> {
        sink.access().write_all(self.actual).await
    }
}

#[call(sync)]
async fn lie<G: Write<Report = ()>>(
    output: &mut impl ReceiverAccess<Family = G>,
    name: Liar,
) -> [bool; 2]
where
    <G as Write>::Error: Debug,
{
    let mut writer = EncoderStream::new(output, limits(usize::MAX, usize::MAX));
    let insertion: E<Liar, &[u8]> = E::InsertWithLiteralName {
        name: raw(name),
        value: raw(Liar {
            claimed: 1,
            actual: b"v",
        }),
    };
    let short = matches!(
        insertion.encode_into(&mut writer).await,
        Err(WriteError::Name {
            source: Literal::PayloadLength {
                expected: 3,
                actual: 2
            }
        })
    );
    let long = matches!(
        E::<Liar, &[u8]>::Duplicate { index: int(0) }
            .encode_into(&mut writer)
            .await,
        Err(WriteError::Interrupted)
    );
    [short, long]
}

#[call(sync)]
async fn overlong<G: Write<Report = ()>>(output: &mut impl ReceiverAccess<Family = G>) -> bool
where
    <G as Write>::Error: Debug,
{
    let mut writer = EncoderStream::new(output, limits(usize::MAX, usize::MAX));
    // The value writes more than the instruction has left.
    let insertion: E<Liar, &[u8]> = E::InsertWithNameReference {
        name: static_name(0),
        value: raw(Liar {
            claimed: 1,
            actual: b"vw",
        }),
    };
    matches!(
        insertion.encode_into(&mut writer).await,
        Err(WriteError::Payload {
            source: WriteAllError::WriteZero { .. }
        })
    )
}

#[test]
fn a_raw_payload_that_writes_another_length_fails_the_instruction() {
    let mut output = Vec::new();
    assert_eq!(
        output.sync_lie_unpin(Liar {
            claimed: 3,
            actual: b"ab",
        }),
        [true, true]
    );
    assert_eq!(output, b"\x43ab");
    let mut output = Vec::new();
    assert!(output.sync_overlong_unpin());
    // The sink holds the instruction to its length.
    assert_eq!(output, b"\xc0\x01v");
}

#[test]
fn pending_writes_do_not_repeat_octets() {
    use core::{
        future::Future,
        pin::{Pin, pin},
        task::{Context, Poll, Waker},
    };
    use nitori_call::CallExecutor;
    let name = b"\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff";
    let mut sink = PausingSink::default();
    {
        let mut call = pin!(CallExecutor::execute(
            Pin::new(&mut sink),
            PutEach::new(
                vec![
                    E::InsertWithLiteralName {
                        name: huffman(&b"www.example.com"[..]),
                        value: raw(&b"x"[..]),
                    },
                    E::Duplicate { index: int(2) },
                ],
                usize::MAX,
                16,
            )
        ));
        let mut cx = Context::from_waker(Waker::noop());
        // One pending write per wire octet.
        for _ in 0..16 {
            assert!(call.as_mut().poll(&mut cx).is_pending());
        }
        let Poll::Ready(results) = call.as_mut().poll(&mut cx) else {
            panic!("the call did not finish");
        };
        assert!(results.iter().all(Result::is_ok), "{results:?}");
    }
    assert_eq!(sink.wire, [&[0x6c], &name[..], &[0x01, b'x', 2]].concat());
}

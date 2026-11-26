//! The metadata of the bytes of an instruction, merged into what is read
//! from them, and the reports of what is written.
mod common;
mod support;

use bytes::{Buf, BufMut};
use common::{Collected, octets};
use core::{
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};
use hatate_qpack::{
    decoder_instruction::{
        DecoderInstruction as D, DecoderStream, DecoderStreamLimits, Increment, StreamId,
    },
    encoder_instruction::{
        EncodeEncoderInstructionError, EncoderInstruction, EncoderInstructionOutput, EncoderStream,
        EncoderStreamLimits, NameReference,
    },
    integer::{PrefixedField, PrefixedInt},
    static_table::Index,
    string_literal::StringLiteral,
};
use nitori_call::{ConstructedAccess, family_receiver};
use nitori_codec::{
    DecodeFrom, EncodeInto, EncodedLen,
    payload::{Buffered, Chunks, Fill},
};
use nitori_io::{
    ChunkSegment, Combine, Read, ReadChunk, ReadSegment, Write, WriteSegment,
    calls::{CopyTotal, ReadValue},
};
use support::{huffman, raw};

/// An instruction as these tests read it.
type E = EncoderInstruction<Collected, Vec<u8>>;

/// The positions in the stream of the bytes read, in the order they were
/// merged: a metadata that shows which segments were merged and how.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Positions(Vec<usize>);

impl Combine for Positions {
    fn combine(mut self, next: Self) -> Self {
        self.0.extend(next.0);
        self
    }
}

fn at(positions: &[usize]) -> Positions {
    Positions(positions.to_vec())
}

/// A stream that hands out one byte per read or chunk; the metadata of each
/// byte is its position.
struct Numbered<'a> {
    data: &'a [u8],
    position: usize,
}

family_receiver!(impl ['a] for Numbered<'a>);

impl Read for Numbered<'_> {
    type Error = !;
    type Metadata = Positions;
    fn poll_read<'v, O: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        _: &mut Context<'_>,
        out: &mut O,
    ) -> Poll<Result<Option<ReadSegment<Positions>>, !>>
    where
        Self: 'v,
    {
        let this = host.get_pin_mut().get_mut();
        let Some((&byte, rest)) = this.data.split_first().filter(|_| out.has_remaining_mut())
        else {
            return Poll::Ready(Ok(None));
        };
        out.put_u8(byte);
        this.data = rest;
        let metadata = Positions(vec![this.position]);
        this.position += 1;
        Poll::Ready(Ok(Some(ReadSegment {
            count: NonZeroUsize::MIN,
            metadata,
        })))
    }
}

impl<'a> ReadChunk for Numbered<'a> {
    type Chunk = &'a [u8];
    fn poll_read_chunk<'v>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        _: &mut Context<'_>,
        _: NonZeroUsize,
    ) -> Poll<Result<Option<ChunkSegment<&'a [u8], Positions>>, !>>
    where
        Self: 'v,
    {
        let this = host.get_pin_mut().get_mut();
        if this.data.is_empty() {
            return Poll::Ready(Ok(None));
        }
        let (chunk, rest) = this.data.split_at(1);
        this.data = rest;
        let metadata = Positions(vec![this.position]);
        this.position += 1;
        Poll::Ready(Ok(Some(ChunkSegment { chunk, metadata })))
    }
}

fn numbered(data: &[u8]) -> ConstructedAccess<Numbered<'_>> {
    ConstructedAccess::new(Numbered { data, position: 0 })
}

fn run<T>(future: impl core::future::Future<Output = T>) -> T {
    nitori_call::__private::run_sync(future)
}

const LIMITS: EncoderStreamLimits = EncoderStreamLimits {
    max_wire_len: 64,
    max_decoded_len: 64,
};

fn int(value: u64) -> PrefixedField {
    PrefixedField::shortest(PrefixedInt::from(value))
}

/// The next instruction of `stream` with the metadata of its octets.
fn next<A: nitori_call::ReceiverAccess<Family: ReadChunk<Metadata = M, Chunk = &'static [u8]>>, M>(
    stream: &mut EncoderStream<A>,
) -> Option<ReadValue<E, M>>
where
    M: Combine + Unpin,
    <A::Family as Read>::Error: core::fmt::Debug,
{
    run(Option::<ReadValue<E, M>>::decode_from(stream)).unwrap()
}

#[test]
fn an_integer_instruction_has_the_metadata_of_its_octets() {
    // Set Dynamic Table Capacity 220 (three octets), Duplicate 1, Duplicate
    // 31 (two octets) and Set Dynamic Table Capacity 0.
    let wire: &'static [u8] = &[0x3f, 0xbd, 0x01, 0x01, 0x1f, 0x00, 0x20];
    let mut stream = EncoderStream::new(numbered(wire), LIMITS);
    let read = next(&mut stream).unwrap();
    assert_eq!(
        read.value,
        E::SetDynamicTableCapacity { capacity: int(220) }
    );
    assert_eq!(read.metadata, at(&[0, 1, 2]));
    let read = next(&mut stream).unwrap();
    assert_eq!(read.value, E::Duplicate { index: int(1) });
    assert_eq!(read.metadata, at(&[3]));
    let read = next(&mut stream).unwrap();
    assert_eq!(read.value, E::Duplicate { index: int(31) });
    assert_eq!(read.metadata, at(&[4, 5]));
    let read = next(&mut stream).unwrap();
    assert_eq!(read.value, E::SetDynamicTableCapacity { capacity: int(0) });
    assert_eq!(read.metadata, at(&[6]));
    // The end at the boundary has read nothing, so it has no metadata.
    assert!(next(&mut stream).is_none());
}

#[test]
fn an_insertion_has_the_metadata_of_all_of_its_octets() {
    // A relative index of 64 (two octets), then the value "xy" with its
    // length, and Set Dynamic Table Capacity 0.
    let wire: &'static [u8] = &[0xbf, 0x01, 0x02, b'x', b'y', 0x20];
    let mut stream = EncoderStream::new(numbered(wire), LIMITS);
    let read = next(&mut stream).unwrap();
    let E::InsertWithNameReference {
        name: NameReference::Relative { index },
        value,
    } = read.value
    else {
        panic!("a reference to a dynamic entry");
    };
    assert_eq!((index, octets(&value)), (int(64), &b"xy"[..]));
    assert_eq!(read.metadata, at(&[0, 1, 2, 3, 4]));
    let read = next(&mut stream).unwrap();
    assert_eq!(read.value, E::SetDynamicTableCapacity { capacity: int(0) });
    assert_eq!(read.metadata, at(&[5]));
    // The name "ab" (raw), the value "c" (raw).
    let wire: &'static [u8] = &[0x42, b'a', b'b', 0x01, b'c'];
    let mut stream = EncoderStream::new(numbered(wire), LIMITS);
    let read = next(&mut stream).unwrap();
    let E::InsertWithLiteralName { name, value } = &read.value else {
        panic!("a literal name");
    };
    assert_eq!((octets(name), octets(value)), (&b"ab"[..], &b"c"[..]));
    assert_eq!(read.metadata, at(&[0, 1, 2, 3, 4]));
}

#[test]
fn a_huffman_value_has_the_metadata_of_the_octets_it_was_decoded_from() {
    // A static name reference to :authority, then the value
    // "www.example.com" as a Huffman literal of 12 octets (RFC 7541 C.4.1).
    let wire: &'static [u8] = &[
        0xc0, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
    ];
    let mut stream = EncoderStream::new(numbered(wire), LIMITS);
    let read = next(&mut stream).unwrap();
    let E::InsertWithNameReference { value, .. } = &read.value else {
        panic!("a name reference");
    };
    assert_eq!(octets(value), b"www.example.com");
    assert_eq!(read.metadata, at(&(0..14).collect::<Vec<_>>()));
}

#[test]
fn a_decoder_instruction_has_the_metadata_of_its_octets() {
    // Section acknowledgment of stream 4, Insert Count Increment 5, and the
    // cancellation of stream 64 (two octets).
    let wire = [0x84, 0x05, 0x7f, 0x01];
    let mut stream = DecoderStream::new(numbered(&wire), DecoderStreamLimits { max_wire_len: 8 });
    let mut seen = Vec::new();
    while let Some(read) = run(Option::<ReadValue<D, Positions>>::decode_from(&mut stream)).unwrap()
    {
        seen.push((read.value, read.metadata));
    }
    let id = |id| PrefixedField::shortest(StreamId::try_from(id).unwrap());
    assert_eq!(
        seen,
        [
            (D::SectionAcknowledgment { stream_id: id(4) }, at(&[0])),
            (
                D::InsertCountIncrement {
                    increment: PrefixedField::shortest(Increment::new(
                        core::num::NonZeroU64::new(5).unwrap()
                    ))
                },
                at(&[1])
            ),
            (D::StreamCancellation { stream_id: id(64) }, at(&[2, 3])),
        ]
    );
}

#[test]
fn an_instruction_read_without_metadata_is_the_same() {
    let wire = [0xbf, 0x01, 0x02, b'x', b'y', 0x20];
    let mut input = &wire[..];
    let mut stream = EncoderStream::new(ConstructedAccess::new(&mut input), LIMITS);
    let read = run(Option::<ReadValue<E, ()>>::decode_from(&mut stream))
        .unwrap()
        .unwrap();
    assert_eq!(read.metadata, ());
    assert!(matches!(
        read.value,
        E::InsertWithNameReference {
            name: NameReference::Relative { index },
            ..
        } if index == int(64)
    ));
    assert_eq!(input, [0x20]);
}

/// What a sink counts of the writes it accepts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Writes(u32);

impl Combine for Writes {
    fn combine(self, next: Self) -> Self {
        Self(self.0 + next.0)
    }
}

/// A sink that accepts one byte at a time and reports one write for each.
#[derive(Default)]
struct Tally {
    bytes: Vec<u8>,
}

family_receiver!(impl [] for Tally);

impl Write for Tally {
    type Error = !;
    type Report = Writes;
    fn poll_write<'v, B: Buf + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        _: &mut Context<'_>,
        input: &mut B,
    ) -> Poll<Result<Option<WriteSegment<Writes>>, !>>
    where
        Self: 'v,
    {
        let this = host.get_pin_mut().get_mut();
        if !input.has_remaining() {
            return Poll::Ready(Ok(None));
        }
        this.bytes.push(input.get_u8());
        Poll::Ready(Ok(Some(WriteSegment {
            count: NonZeroUsize::MIN,
            report: Writes(1),
        })))
    }
}

#[test]
fn a_decoder_instruction_is_written_with_the_report_of_its_octets() {
    let mut sink = ConstructedAccess::new(Tally::default());
    let mut stream = DecoderStream::new(&mut sink, DecoderStreamLimits { max_wire_len: 8 });
    let cancellation = D::StreamCancellation {
        stream_id: PrefixedField::shortest(StreamId::try_from(64).unwrap()),
    };
    let report = run(cancellation.encode_into(&mut stream)).unwrap();
    assert_eq!(report, Writes(2));
    assert_eq!(sink.into_inner().bytes, [0x7f, 0x01]);
}

#[test]
fn an_encoder_instruction_is_written_with_the_report_of_all_of_its_octets() {
    type Made = EncoderInstruction<&'static [u8], &'static [u8]>;
    let mut sink = ConstructedAccess::new(Tally::default());
    let mut stream = EncoderStream::new(&mut sink, LIMITS);
    let mut write = |instruction: Made| run(instruction.encode_into(&mut stream)).unwrap();
    let output = |head, name, value| EncoderInstructionOutput { head, name, value };
    // The integer instructions: the report of their octets.
    assert_eq!(
        write(EncoderInstruction::SetDynamicTableCapacity { capacity: int(220) }),
        output(Writes(3), None, None)
    );
    assert_eq!(
        write(EncoderInstruction::Duplicate { index: int(31) }),
        output(Writes(2), None, None)
    );
    // An insertion with a name reference: the reference and the value's
    // length, then the value's octets, which the raw literal writes itself
    // and reports as its own output.
    let static_name = NameReference::Static {
        index: PrefixedField::shortest(Index::try_from(1).unwrap()),
    };
    assert_eq!(
        write(EncoderInstruction::InsertWithNameReference {
            name: static_name,
            value: raw(&b"xy"[..]),
        }),
        output(Writes(2), None, Some(Writes(2)))
    );
    // An insertion with a literal name: the name's header with the value's
    // header and Huffman code, which the instruction writes itself, and the
    // name's raw payload.
    assert_eq!(
        write(EncoderInstruction::InsertWithLiteralName {
            name: raw(&b"ab"[..]),
            value: huffman(&b"a"[..]),
        }),
        output(Writes(3), Some(Writes(2)), None)
    );
    assert_eq!(
        sink.into_inner().bytes,
        b"\x3f\xbd\x01\x1f\x00\xc1\x02xy\x42ab\x81\x1f"
    );
}

#[test]
fn a_raw_literal_from_a_source_gives_the_output_of_its_copy() {
    type Source = Chunks<ConstructedAccess<&'static [u8]>>;
    let source = |bytes: &'static [u8]| -> StringLiteral<Source, &'static [u8]> {
        let chunks = Chunks {
            source: ConstructedAccess::new(bytes),
            chunk_maximum: NonZeroUsize::new(2).unwrap(),
        };
        run(StringLiteral::raw(chunks)).unwrap()
    };
    let mut sink = ConstructedAccess::new(Tally::default());
    let mut stream = EncoderStream::new(&mut sink, LIMITS);
    let instruction = EncoderInstruction::InsertWithLiteralName {
        name: source(b"abc"),
        value: source(b"xy"),
    };
    let copied = |count, report| CopyTotal {
        count,
        metadata: (),
        report,
    };
    // The two length prefixes are the instruction's; each payload is copied
    // from its source, two octets at a time.
    assert_eq!(
        run(instruction.encode_into(&mut stream)).unwrap(),
        EncoderInstructionOutput {
            head: Writes(2),
            name: Some(copied(3, Writes(3))),
            value: Some(copied(2, Writes(2))),
        }
    );
    assert_eq!(sink.into_inner().bytes, b"\x43abc\x02xy");
}

/// A source that claims the length `claimed` and writes as its wrapped
/// source does.
struct Claims<S> {
    claimed: u64,
    inner: S,
}

impl<S> EncodedLen for Claims<S> {
    type LengthError = !;
    async fn encoded_len(&mut self) -> Result<u64, !> {
        Ok(self.claimed)
    }
}

impl<K, S: EncodeInto<K>> EncodeInto<K> for Claims<S> {
    type Output = S::Output;
    type Error = S::Error;
    async fn encode_into(self, sink: K) -> Result<S::Output, S::Error> {
        self.inner.encode_into(sink).await
    }
}

fn filled(bytes: &'static [u8]) -> Fill<ConstructedAccess<&'static [u8]>> {
    Fill {
        source: ConstructedAccess::new(bytes),
        chunk_maximum: NonZeroUsize::new(2).unwrap(),
    }
}

fn buffered(bytes: &'static [u8]) -> Buffered<ConstructedAccess<&'static [u8]>, [u8; 2]> {
    Buffered {
        source: ConstructedAccess::new(bytes),
        buffer: [0; 2],
    }
}

/// A raw literal of a source that tells its length.
fn lit<S: EncodedLen<LengthError: core::fmt::Debug>>(source: S) -> StringLiteral<S, &'static [u8]> {
    run(StringLiteral::raw(source)).unwrap()
}

fn copied(count: u64) -> CopyTotal<(), ()> {
    CopyTotal {
        count,
        metadata: (),
        report: (),
    }
}

/// A raw literal made of a source and the output of its copy: the wire
/// holds the length prefixes and the payloads, and the output is the
/// wrapper's.
#[test]
fn a_raw_literal_from_a_fill_or_a_buffer_gives_the_output_of_its_copy() {
    let expected = EncoderInstructionOutput {
        head: (),
        name: Some(copied(3)),
        value: Some(copied(2)),
    };
    let mut sink = ConstructedAccess::new(Vec::<u8>::new());
    let mut stream = EncoderStream::new(&mut sink, LIMITS);
    let instruction = EncoderInstruction::InsertWithLiteralName {
        name: lit(filled(b"abc")),
        value: lit(filled(b"xy")),
    };
    assert_eq!(run(instruction.encode_into(&mut stream)).unwrap(), expected);
    assert_eq!(sink.into_inner(), b"\x43abc\x02xy");
    let mut sink = ConstructedAccess::new(Vec::<u8>::new());
    let mut stream = EncoderStream::new(&mut sink, LIMITS);
    let instruction = EncoderInstruction::InsertWithLiteralName {
        name: lit(buffered(b"abc")),
        value: lit(buffered(b"xy")),
    };
    assert_eq!(run(instruction.encode_into(&mut stream)).unwrap(), expected);
    assert_eq!(sink.into_inner(), b"\x43abc\x02xy");
}

/// A source with more octets than its literal claims: the octets beyond the
/// length do not reach the stream, and the instruction fails.
#[test]
fn a_raw_literal_from_a_fill_or_a_buffer_longer_than_its_length_stops_at_it() {
    let mut sink = ConstructedAccess::new(Vec::<u8>::new());
    let mut stream = EncoderStream::new(&mut sink, LIMITS);
    let instruction = EncoderInstruction::InsertWithLiteralName {
        name: raw::<_, &'static [u8]>(Claims {
            claimed: 2,
            inner: filled(b"abcd"),
        }),
        value: raw(Claims {
            claimed: 1,
            inner: filled(b"x"),
        }),
    };
    assert!(matches!(
        run(instruction.encode_into(&mut stream)),
        Err(EncodeEncoderInstructionError::Payload { .. })
    ));
    // The stream is left inside the instruction.
    let after = EncoderInstruction::<&'static [u8], &'static [u8]>::Duplicate { index: int(0) };
    assert!(matches!(
        run(after.encode_into(&mut stream)),
        Err(EncodeEncoderInstructionError::Interrupted)
    ));
    assert_eq!(sink.into_inner(), b"\x42ab");
    // The value of a name reference, from a buffer.
    let mut sink = ConstructedAccess::new(Vec::<u8>::new());
    let mut stream = EncoderStream::new(&mut sink, LIMITS);
    let instruction = EncoderInstruction::<_, &'static [u8]>::InsertWithNameReference {
        name: NameReference::Relative { index: int(0) },
        value: raw(Claims {
            claimed: 2,
            inner: buffered(b"xyz"),
        }),
    };
    assert!(matches!(
        run(instruction.encode_into(&mut stream)),
        Err(EncodeEncoderInstructionError::Payload { .. })
    ));
    assert_eq!(sink.into_inner(), b"\x80\x02xy");
}

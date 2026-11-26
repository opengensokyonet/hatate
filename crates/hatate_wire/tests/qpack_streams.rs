//! The QPACK streams of HTTP/3: the limits they read with, which start as
//! those of a peer without a dynamic table, and the metadata of the bytes of
//! an instruction.
mod common;

use bytes::BufMut;
use common::Instruction;
use core::{
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};
use frunk_core::{HList, coproduct::Coproduct};
use hatate_qpack::{
    decoder_instruction::{DecoderInstruction, DecoderStreamLimits, StreamId},
    encoder_instruction::{
        DecodeEncoderInstructionError, DecodeLiteralError, EncoderInstruction, EncoderStreamLimits,
    },
    integer::{PrefixedField, PrefixedInt},
};
use hatate_wire::{
    Part,
    stream::{
        ReceivedStream, class::ClientInitiatedUnidirectional, codec::read_unidirectional_stream,
        http3::Http3UnidirectionalStream,
    },
};
use hatate_wire_qpack::stream::{
    CriticalStream, DecodeQpackEncoderInstructionError, QpackDecoderStream, QpackEncoderStream,
};
use nitori_call::{Composed, ConstructedAccess, ReceiverAccess, family_receiver};
use nitori_codec::DecodeFrom;
use nitori_io::{ChunkSegment, Combine, Read, ReadChunk, ReadSegment, calls::ReadValue};

fn run<T>(future: impl core::future::Future<Output = T>) -> T {
    nitori_call::__private::run_sync(future)
}

/// The positions in the stream of the bytes read, in the order merged.
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

type Critical<A> = Composed<A, CriticalStream>;

/// The next instruction with the limits the stream has.
async fn next<A, M>(
    stream: &mut QpackEncoderStream<A>,
) -> Result<
    ReadValue<Instruction, M>,
    DecodeQpackEncoderInstructionError<<<Critical<A> as ReceiverAccess>::Family as Read>::Error>,
>
where
    A: ReceiverAccess,
    Critical<A>: ReceiverAccess<Family: ReadChunk<Metadata = M>>,
    M: Combine + Unpin,
{
    ReadValue::decode_from(stream).await
}

fn int(value: u64) -> PrefixedField {
    PrefixedField::shortest(PrefixedInt::from(value))
}

#[test]
fn the_encoder_stream_starts_with_the_limits_of_a_table_of_no_capacity() {
    let mut stream = QpackEncoderStream::new(ConstructedAccess::new(&b""[..]));
    assert_eq!(stream.limits(), EncoderStreamLimits::default());
    assert_eq!(stream.limits(), EncoderStreamLimits::for_table_capacity(0));
    stream.set_max_table_capacity(4096);
    assert_eq!(
        stream.limits(),
        EncoderStreamLimits::for_table_capacity(4096)
    );
}

#[test]
fn an_insertion_is_refused_before_the_settings_allow_a_table() {
    // A literal name of one octet, and a reference to a static name with a
    // value of one octet: each has a decoded octet more than the default
    // limit of none.
    let literal_name = [0x41, b'x', 0x00];
    let reference = [0xc1, 0x01, b'x'];
    let mut stream = QpackEncoderStream::new(ConstructedAccess::new(&literal_name[..]));
    assert!(matches!(
        run(next::<_, ()>(&mut stream))
            .unwrap_err()
            .instruction_error(),
        DecodeEncoderInstructionError::Name {
            source: DecodeLiteralError::DecodedLength { .. }
        }
    ));
    let mut stream = QpackEncoderStream::new(ConstructedAccess::new(&reference[..]));
    assert!(matches!(
        run(next::<_, ()>(&mut stream))
            .unwrap_err()
            .instruction_error(),
        DecodeEncoderInstructionError::Value {
            source: DecodeLiteralError::DecodedLength { .. }
        }
    ));
}

#[test]
fn the_limits_that_follow_from_the_settings_admit_the_insertion() {
    let literal_name = [0x41, b'x', 0x00];
    let reference = [0xc1, 0x01, b'x'];
    // A capacity of 33 leaves one decoded octet for the name and the value.
    let mut stream = QpackEncoderStream::new(ConstructedAccess::new(&literal_name[..]));
    stream.set_max_table_capacity(33);
    let read = run(next::<_, ()>(&mut stream)).unwrap();
    let EncoderInstruction::InsertWithLiteralName { name, value } = &read.value else {
        panic!("an insertion with a literal name");
    };
    assert_eq!((name.as_ref(), value.as_ref()), (&b"x"[..], &b""[..]));
    let mut stream = QpackEncoderStream::new(ConstructedAccess::new(&reference[..]));
    stream.set_max_table_capacity(33);
    let read = run(next::<_, ()>(&mut stream)).unwrap();
    let EncoderInstruction::InsertWithNameReference { value, .. } = &read.value else {
        panic!("an insertion with a name reference");
    };
    assert_eq!(value.as_ref(), b"x");
}

#[test]
fn an_instruction_with_a_number_is_within_the_default_limits() {
    // Set Dynamic Table Capacity 220 takes three octets of the 22 that are
    // allowed.
    let wire = [0x3f, 0xbd, 0x01];
    let mut stream = QpackEncoderStream::new(ConstructedAccess::new(&wire[..]));
    let read = run(next::<_, ()>(&mut stream)).unwrap();
    assert_eq!(
        read.value,
        EncoderInstruction::SetDynamicTableCapacity { capacity: int(220) }
    );
}

#[test]
fn the_encoder_stream_gives_the_metadata_of_all_the_octets_of_an_instruction() {
    // Set Dynamic Table Capacity 220, then an insertion with a name
    // reference whose value header and value follow.
    let wire = [0x3f, 0xbd, 0x01, 0xc1, 0x01, b'x'];
    let mut stream = QpackEncoderStream::new(numbered(&wire));
    stream.set_max_table_capacity(100);
    let capacity = run(next::<_, Positions>(&mut stream)).unwrap();
    assert_eq!(
        capacity.value,
        EncoderInstruction::SetDynamicTableCapacity { capacity: int(220) }
    );
    assert_eq!(capacity.metadata, at(&[0, 1, 2]));
    let insertion = run(next::<_, Positions>(&mut stream)).unwrap();
    assert_eq!(insertion.metadata, at(&[3, 4, 5]));
    let EncoderInstruction::InsertWithNameReference { value, .. } = insertion.value else {
        panic!("an insertion with a name reference");
    };
    assert_eq!(value.as_ref(), b"x");
    // The stream does not end: its end is a failure.
    assert!(run(next::<_, Positions>(&mut stream)).is_err());
}

#[test]
fn the_decoder_stream_has_its_limit_and_gives_the_metadata_of_an_instruction() {
    let mut stream = QpackDecoderStream::new(ConstructedAccess::new(&b""[..]));
    assert_eq!(stream.limits(), DecoderStreamLimits::default());
    stream.set_limits(DecoderStreamLimits { max_wire_len: 2 });
    assert_eq!(stream.limits(), DecoderStreamLimits { max_wire_len: 2 });

    // Section acknowledgment of stream 4, then the cancellation of stream 64
    // with two octets.
    let wire = [0x84, 0x7f, 0x01];
    let mut stream = QpackDecoderStream::new(numbered(&wire));
    let first = run(ReadValue::<DecoderInstruction, Positions>::decode_from(
        &mut stream,
    ))
    .unwrap();
    let id = |id| PrefixedField::shortest(StreamId::try_from(id).unwrap());
    assert_eq!(
        first.value,
        DecoderInstruction::SectionAcknowledgment { stream_id: id(4) }
    );
    assert_eq!(first.metadata, at(&[0]));
    let second = run(ReadValue::<DecoderInstruction, Positions>::decode_from(
        &mut stream,
    ))
    .unwrap();
    assert_eq!(
        second.value,
        DecoderInstruction::StreamCancellation { stream_id: id(64) }
    );
    assert_eq!(second.metadata, at(&[1, 2]));
    // The stream does not end: its end is a failure.
    assert!(
        run(ReadValue::<DecoderInstruction, Positions>::decode_from(
            &mut stream
        ))
        .is_err()
    );
}

#[test]
fn the_qpack_streams_read_from_the_wire_start_with_the_default_limits() {
    let read = |stream_type: &'static [u8]| {
        let start = read_unidirectional_stream::<HList![Part], ClientInitiatedUnidirectional, _, ()>(
            ConstructedAccess::new(stream_type),
        );
        let ReceivedStream::Known(known) = run(start).unwrap().unwrap().transpose() else {
            panic!("a known stream");
        };
        let Coproduct::Inl(http3) = known.transpose() else {
            panic!("an HTTP/3 stream");
        };
        http3.transpose()
    };
    let Http3UnidirectionalStream::QpackEncoder(stream) = read(&[0x02]) else {
        panic!("the QPACK encoder stream");
    };
    assert_eq!(
        stream.into_stream().limits(),
        EncoderStreamLimits::default()
    );
    let Http3UnidirectionalStream::QpackDecoder(stream) = read(&[0x03]) else {
        panic!("the QPACK decoder stream");
    };
    assert_eq!(
        stream.into_stream().limits(),
        DecoderStreamLimits::default()
    );
}

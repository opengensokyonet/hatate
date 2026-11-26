#![feature(impl_trait_in_assoc_type)]
mod common;

use common::Flaky;
use core::{fmt::Debug, num::NonZeroU64};
use hatate_qpack::{
    decoder_instruction::{
        DecodeDecoderInstructionError as ReadError, DecoderInstruction as D, DecoderStream,
        DecoderStreamLimits, EncodeDecoderInstructionError as WriteError, Increment, StreamId,
    },
    instruction::{NumberError, OctetError},
    integer::{PrefixedField, PrefixedInt},
};
use nitori_call::{ReceiverAccess, call};
use nitori_codec::{DecodeFrom, EncodeInto};
use nitori_io::{
    Read, Write,
    calls::{ReadArrayError, ReadValue},
};

async fn next_decoder<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    reader: &mut DecoderStream<A>,
    wire: usize,
) -> Result<Option<D>, ReadError<F::Error>> {
    reader.set_limits(DecoderStreamLimits { max_wire_len: wire });
    let next = Option::<ReadValue<D, ()>>::decode_from(reader).await?;
    Ok(next.map(|read| read.value))
}

fn decoder_stream<A>(io: A) -> DecoderStream<A> {
    DecoderStream::new(io, DecoderStreamLimits::default())
}

fn ack(id: u64) -> D {
    D::SectionAcknowledgment {
        stream_id: PrefixedField::shortest(StreamId::try_from(id).unwrap()),
    }
}

fn cancel(id: u64) -> D {
    D::StreamCancellation {
        stream_id: PrefixedField::shortest(StreamId::try_from(id).unwrap()),
    }
}

fn increment(n: u64) -> D {
    D::InsertCountIncrement {
        increment: PrefixedField::shortest(Increment::new(NonZeroU64::new(n).unwrap())),
    }
}

/// One instruction from a fresh stream.
#[call(sync)]
async fn one<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    max_wire_len: usize,
) -> Result<Option<D>, ReadError<F::Error>> {
    next_decoder(&mut decoder_stream(io), max_wire_len).await
}

/// `count` instructions from one stream, whatever each returns.
#[call(sync)]
async fn sequence<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    max_wire_len: usize,
    count: usize,
) -> Vec<Result<Option<D>, ReadError<F::Error>>> {
    let mut stream = decoder_stream(io);
    let mut results = Vec::new();
    for _ in 0..count {
        results.push(next_decoder(&mut stream, max_wire_len).await);
    }
    results
}

/// Writes each instruction within `max_wire_len` to one stream, whatever
/// each returns.
#[call(sync)]
async fn put_each<G: Write<Report = ()>, A: ReceiverAccess<Family = G>>(
    io: &mut A,
    instructions: Vec<D>,
    max_wire_len: usize,
) -> Vec<Result<(), WriteError<<G as Write>::Error>>> {
    let mut stream = DecoderStream::new(io, DecoderStreamLimits { max_wire_len });
    let mut results = Vec::new();
    for instruction in instructions {
        results.push(instruction.encode_into(&mut stream).await);
    }
    results
}

/// Reads one instruction, takes the access back and reads one more from a
/// new stream on it.
#[call(sync)]
async fn handed_back<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> (D, Option<D>) {
    let mut stream = decoder_stream(io);
    let first = next_decoder(&mut stream, 1).await.ok().flatten().unwrap();
    let io = stream.into_io();
    let second = next_decoder(&mut decoder_stream(io), 1).await.ok().unwrap();
    (first, second)
}

#[test]
fn successive_decoder_instructions_keep_the_next_opcode() {
    // RFC 9204 Appendix B.2 (ack stream 4), B.3 (increment), B.4 (cancel stream 8).
    let cases = [(ack(4), 0x84), (increment(1), 1), (cancel(8), 0x48)];
    let mut wire = Vec::new();
    let written = wire.sync_put_each_unpin(cases.iter().map(|&(op, _)| op).collect(), 1);
    assert!(written.iter().all(Result::is_ok), "{written:?}");
    assert_eq!(wire, [0x84, 1, 0x48]);
    let mut input = wire.as_slice();
    let results = input.sync_sequence_unpin(1, 5);
    assert_eq!(results.len(), 5);
    for (result, &(op, _)) in results.iter().zip(&cases) {
        assert!(matches!(result, Ok(Some(actual)) if *actual == op));
    }
    // The end at a boundary is not an error, and stays the end.
    assert!(matches!(results[3], Ok(None)));
    assert!(matches!(results[4], Ok(None)));
    assert!(input.is_empty());
}

#[test]
fn stream_ending_at_a_boundary_gives_none() {
    // Nothing at all.
    let mut empty = &[][..];
    assert!(matches!(empty.sync_one_unpin(1), Ok(None)));
    // One instruction and then the end.
    let mut input = &[0x84][..];
    let results = input.sync_sequence_unpin(1, 2);
    assert!(matches!(&results[0], Ok(Some(instruction)) if *instruction == ack(4)));
    assert!(matches!(results[1], Ok(None)));
}

#[test]
fn zero_increment_and_unrepresentable_stream_ids_are_distinct() {
    assert!(matches!(
        (&[0][..]).sync_one_unpin(1),
        Err(ReadError::ZeroIncrement)
    ));
    assert!(Increment::try_from(PrefixedInt::ZERO).is_err());
    assert_eq!(StreamId::try_from(1 << 62).unwrap_err().value(), 1 << 62);
    let too_large = PrefixedField::shortest(PrefixedInt::from(1u64 << 62));
    for acknowledgment in [true, false] {
        let mut wire = Vec::new();
        if acknowledgment {
            hatate_qpack::integer::write::<7, _>(&mut wire, 0x80, too_large).unwrap();
        } else {
            hatate_qpack::integer::write::<6, _>(&mut wire, 0x40, too_large).unwrap();
        }
        let result = wire.as_slice().sync_one_unpin(wire.len());
        assert!(matches!(
            (acknowledgment, result),
            (true, Err(ReadError::AcknowledgmentStream { .. }))
                | (false, Err(ReadError::CancellationStream { .. }))
        ));
    }
}

#[test]
fn wire_budget_applies_before_reading_or_writing_the_next_octet() {
    let mut rest = &[0x3f, 0, 0x84][..];
    assert!(matches!(
        rest.sync_one_unpin(0),
        Err(ReadError::Prefix {
            source: OctetError::WireLimit { .. }
        })
    ));
    assert_eq!(rest, &[0x3f, 0, 0x84]);
    assert!(matches!(rest.sync_one_unpin(1),
        Err(ReadError::IncrementNumber {source:NumberError::Continuation {source:OctetError::WireLimit {source}}})
            if source.required()==2 && source.limit()==1));
    assert_eq!(rest, &[0, 0x84]);
    // A write over the limit writes nothing and leaves the stream at the
    // boundary: the next instruction is written.
    let mut dst = Vec::from(b"prefix");
    let results = dst.sync_put_each_unpin(vec![increment(63), increment(62)], 1);
    assert!(
        matches!(&results[0], Err(WriteError::WireLimit {source}) if source.required()==2 && source.limit()==1)
    );
    assert!(results[1].is_ok());
    assert_eq!(dst, b"prefix\x3e");
}

#[test]
fn continuation_truncation_and_nonminimal_length() {
    assert!(matches!(
        (&[0xff][..]).sync_one_unpin(11),
        Err(ReadError::AcknowledgmentNumber {
            source: NumberError::Continuation {
                source: OctetError::Read {
                    source: ReadArrayError::Incomplete { .. }
                }
            }
        })
    ));
    let mut input = &[0xff, 0x80, 0, 0x48][..];
    let read = input.sync_one_unpin(3).unwrap().unwrap();
    let D::SectionAcknowledgment { stream_id } = read else {
        panic!("{read:?}");
    };
    assert_eq!((stream_id.value().get(), stream_id.padding()), (127, 1));
    assert_eq!(read.wire_len(), 3);
    assert_eq!(input, [0x48]);
}

#[test]
fn padded_integers_write_back_their_original_octets() {
    // Each instruction with an integer one octet longer than it needs, and
    // with the longest encoding a stream reads (ten continuation octets).
    let wire: &[u8] = &[
        0xff, 0x80, 0x00, // acknowledgment of stream 127
        0x7f, 0x81, 0x00, // cancellation of stream 64
        0x3f, 0x82, 0x00, // increment of 65
        0x3f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00, // increment of 63
    ];
    let mut input = wire;
    let results = input.sync_sequence_unpin(11, 5);
    let instructions: Vec<D> = results
        .into_iter()
        .map_while(|result| result.unwrap())
        .collect();
    assert_eq!(instructions.len(), 4);
    let mut output = Vec::new();
    let written = output.sync_put_each_unpin(instructions.clone(), 11);
    assert!(written.iter().all(Result::is_ok), "{written:?}");
    assert_eq!(output, wire);
    // Hand-made instructions take their shortest encodings.
    let mut output = Vec::new();
    output.sync_put_each_unpin(vec![ack(127), cancel(64), increment(65)], 11);
    assert_eq!(output, [0xff, 0x00, 0x7f, 0x01, 0x3f, 0x02]);
    // A field padded for one position is written there, and refused before
    // writing in a position whose prefix cannot take the padding: 63 fits in
    // a seven-bit prefix, which leaves nothing to pad.
    let padded = PrefixedField::new::<6>(StreamId::try_from(63).unwrap(), 9).unwrap();
    let cancellation = D::StreamCancellation { stream_id: padded };
    assert_eq!(cancellation.wire_len(), 11);
    let acknowledgment = D::SectionAcknowledgment { stream_id: padded };
    let mut output = Vec::new();
    let results = output.sync_put_each_unpin(vec![cancellation, acknowledgment], 11);
    assert!(results[0].is_ok());
    assert!(matches!(results[1], Err(WriteError::Integer { .. })));
    assert_eq!(output, [&[0x7f][..], &[0x80; 9], &[0x00]].concat());
}

#[test]
fn failed_instruction_interrupts_the_stream() {
    // Failure inside a number and a zero increment: each one leaves the
    // stream interrupted.
    let cases: [(&[u8], usize); 2] = [(&[0xff], 11), (&[0, 0x84], 1)];
    for (wire, limit) in cases {
        let mut input = wire;
        let results = input.sync_sequence_unpin(limit, 3);
        assert!(results[0].is_err(), "{wire:?}");
        assert!(matches!(results[1], Err(ReadError::Interrupted)));
        assert!(matches!(results[2], Err(ReadError::Interrupted)));
    }
    // A wire limit that stops before the first octet reads nothing: the
    // stream stays at the boundary and fails the same way each time.
    let mut input = &[0x84][..];
    let results = input.sync_sequence_unpin(0, 3);
    assert!(results.iter().all(|result| matches!(
        result,
        Err(ReadError::Prefix {
            source: hatate_qpack::instruction::OctetError::WireLimit { .. }
        })
    )));
    assert_eq!(input, [0x84]);
    // A stream that failed does not read on: the byte after the failed
    // instruction is untouched by the later calls.
    let mut input = &[0, 0x84][..];
    let _ = input.sync_sequence_unpin(1, 3);
    assert_eq!(input, [0x84]);
}

#[test]
fn into_io_gives_back_the_access_at_the_cursor() {
    let mut input = &[0x84, 0x48, 0x20][..];
    let (first, second) = input.sync_handed_back_unpin();
    assert_eq!(first, ack(4));
    assert_eq!(second, Some(cancel(8)));
    assert_eq!(input, [0x20]);
}

struct Fragmented<'a> {
    input: &'a [u8],
    waiting: bool,
}
nitori_call::family_receiver!(impl ['a] for Fragmented<'a>);

impl nitori_io::Read for Fragmented<'_> {
    type Error = core::convert::Infallible;
    type Metadata = ();
    fn poll_read<'visit, B: bytes::BufMut + ?Sized>(
        host: core::pin::Pin<&mut Self::ReceiverView<'visit>>,
        cx: &mut core::task::Context<'_>,
        dst: &mut B,
    ) -> core::task::Poll<Result<Option<nitori_io::ReadSegment<()>>, Self::Error>>
    where
        Self: 'visit,
    {
        use core::task::Poll;
        let this = host.get_pin_mut().get_mut();
        if !this.waiting {
            this.waiting = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        this.waiting = false;
        let Some((&byte, rest)) = this.input.split_first() else {
            return Poll::Ready(Ok(None));
        };
        dst.put_u8(byte);
        this.input = rest;
        Poll::Ready(Ok(Some(nitori_io::ReadSegment {
            count: core::num::NonZeroUsize::MIN,
            metadata: (),
        })))
    }
}

/// A sink that waits before it accepts each octet.
#[derive(Default)]
struct PausingSink {
    wire: Vec<u8>,
    waiting: bool,
}
nitori_call::family_receiver!(impl [] for PausingSink);

impl nitori_io::Write for PausingSink {
    type Error = !;
    type Report = ();
    fn poll_write<'v, B: bytes::Buf + ?Sized>(
        view: core::pin::Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut core::task::Context<'_>,
        src: &mut B,
    ) -> core::task::Poll<Result<Option<nitori_io::WriteSegment<()>>, Self::Error>>
    where
        Self: 'v,
    {
        use core::task::Poll;
        let sink = view.get_pin_mut().get_mut();
        if !sink.waiting {
            sink.waiting = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        sink.waiting = false;
        if !src.has_remaining() {
            return Poll::Ready(Ok(None));
        }
        sink.wire.push(src.get_u8());
        Poll::Ready(Ok(Some(nitori_io::WriteSegment {
            count: core::num::NonZeroUsize::MIN,
            report: (),
        })))
    }
}

#[call(sync)]
async fn pending_read<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    max_wire_len: usize,
) -> Result<Option<D>, ReadError<F::Error>> {
    next_decoder(&mut decoder_stream(io), max_wire_len).await
}

#[test]
fn integer_state_and_budget_survive_pending_between_every_octet() {
    use core::{
        future::Future,
        pin::{Pin, pin},
        task::{Context, Poll, Waker},
    };
    use nitori_call::CallExecutor;

    let mut host = Fragmented {
        input: &[0xff, 0x80, 0, 0x48],
        waiting: false,
    };
    {
        let mut call = pin!(CallExecutor::execute(
            Pin::new(&mut host),
            PendingRead::new(3)
        ));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..3 {
            assert!(call.as_mut().poll(&mut cx).is_pending());
        }
        assert!(matches!(
            call.as_mut().poll(&mut cx),
            Poll::Ready(Ok(Some(D::SectionAcknowledgment { stream_id })))
                if stream_id.value().get() == 127
        ));
    }
    assert_eq!(host.input, [0x48]);
}

/// Drops the read after `polls` pending polls, then asks again: the
/// instruction, or `None` if the stream was left interrupted.
#[call(sync)]
async fn dropped_read<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    polls: usize,
) -> Option<D> {
    use core::{
        future::{Future, poll_fn},
        pin::pin,
        task::Poll,
    };
    let mut stream = decoder_stream(io);
    {
        let mut read = pin!(next_decoder(&mut stream, 8));
        poll_fn(|cx| {
            for _ in 0..polls {
                assert!(read.as_mut().poll(cx).is_pending());
            }
            Poll::Ready(())
        })
        .await;
    }
    match next_decoder(&mut stream, 8).await {
        Ok(instruction) => Some(instruction.unwrap()),
        Err(ReadError::Interrupted) => None,
        Err(_) => panic!("a read failed other than by interruption"),
    }
}

/// Drops the write of `first` after `polls` pending polls, then writes
/// `second`: whether it was written, or refused as the stream was left
/// interrupted.
#[call(sync)]
async fn dropped_write<G: Write<Report = ()>, A: ReceiverAccess<Family = G>>(
    io: &mut A,
    first: D,
    second: D,
    polls: usize,
) -> bool
where
    <G as Write>::Error: Debug,
{
    use core::{
        future::{Future, poll_fn},
        pin::pin,
        task::Poll,
    };
    let mut stream = DecoderStream::new(io, DecoderStreamLimits::default());
    {
        let mut write = pin!(first.encode_into(&mut stream));
        poll_fn(|cx| {
            for _ in 0..polls {
                assert!(write.as_mut().poll(cx).is_pending());
            }
            Poll::Ready(())
        })
        .await;
    }
    match second.encode_into(&mut stream).await {
        Ok(()) => true,
        Err(WriteError::Interrupted) => false,
        Err(other) => panic!("{other:?}"),
    }
}

/// Drives the call to completion, whatever the host makes it wait for.
fn finish<T>(call: impl core::future::Future<Output = T>) -> T {
    use core::{
        pin::pin,
        task::{Context, Poll, Waker},
    };
    let mut call = pin!(call);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..64 {
        if let Poll::Ready(value) = call.as_mut().poll(&mut cx) {
            return value;
        }
    }
    panic!("the call did not finish");
}

#[test]
fn dropped_read_before_the_first_octet_leaves_the_stream_at_the_boundary() {
    use core::pin::Pin;
    use nitori_call::CallExecutor;

    let read_after = |polls| {
        let mut host = Fragmented {
            input: &[0xff, 0x80, 0, 0x48],
            waiting: false,
        };
        finish(CallExecutor::execute(
            Pin::new(&mut host),
            DroppedRead::new(polls),
        ))
    };
    let section_127 = Some(D::SectionAcknowledgment {
        stream_id: PrefixedField::new::<7>(StreamId::try_from(127).unwrap(), 1).unwrap(),
    });
    // No poll, or one in which the host has not produced the opcode yet:
    // nothing was read, so the next call reads the instruction as if the
    // first had not been made.
    assert_eq!(read_after(0), section_127);
    assert_eq!(read_after(1), section_127);
    // Once the opcode is consumed, a dropped read leaves the stream
    // interrupted.
    for polls in [2, 3] {
        assert_eq!(read_after(polls), None, "{polls}");
    }
}

#[test]
fn dropped_write_before_the_first_octet_leaves_the_stream_at_the_boundary() {
    use core::pin::Pin;
    use nitori_call::CallExecutor;

    // Section Acknowledgment of stream 127, in three octets.
    let padded_127 = D::SectionAcknowledgment {
        stream_id: PrefixedField::new::<7>(StreamId::try_from(127).unwrap(), 1).unwrap(),
    };
    let write_after = |polls| {
        let mut sink = PausingSink::default();
        let written = finish(CallExecutor::execute(
            Pin::new(&mut sink),
            DroppedWrite::new(padded_127, increment(5), polls),
        ));
        (written, sink.wire)
    };
    // No poll, or one in which the sink has not accepted an octet: nothing
    // was written, so the next instruction is.
    assert_eq!(write_after(0), (true, vec![0x05]));
    assert_eq!(write_after(1), (true, vec![0x05]));
    // Once the sink accepted an octet, the dropped write leaves the stream
    // interrupted, and the rest of it is never written.
    assert_eq!(write_after(2), (false, vec![0xff]));
    assert_eq!(write_after(3), (false, vec![0xff, 0x80]));
}

#[test]
fn host_write_failure_preserves_the_accepted_prefix_and_interrupts() {
    let mut buffer = [0u8; 1];
    let results = buffer
        .as_mut_slice()
        .sync_put_each_unpin(vec![increment(63), increment(1)], 2);
    assert!(matches!(&results[0], Err(WriteError::Send { source }) if source.completed()==1));
    assert!(matches!(results[1], Err(WriteError::Interrupted)));
    assert_eq!(buffer, [0x3f]);
    // A sink that accepts nothing leaves the stream at the boundary.
    let mut buffer = [0u8; 0];
    let results = buffer
        .as_mut_slice()
        .sync_put_each_unpin(vec![increment(1), increment(1)], 2);
    assert!(matches!(&results[0], Err(WriteError::Send { source }) if source.completed()==0));
    assert!(matches!(results[1], Err(WriteError::Send { .. })));
}

#[test]
fn a_host_failure_before_the_first_octet_leaves_the_stream_at_the_boundary() {
    // Two acknowledgments of stream 127, two octets each.
    let wire = [0xff, 0x00, 0xff, 0x00];
    // The failure is the first octet's: the next call reads the instruction.
    let mut host = Flaky::new(&wire, 0);
    let results = host.sync_sequence_unpin(11, 3);
    assert!(
        matches!(results[0], Err(ReadError::Prefix { .. })),
        "{results:?}"
    );
    assert_eq!(results[1].as_ref().unwrap().as_ref(), Some(&ack(127)));
    assert_eq!(results[2].as_ref().unwrap().as_ref(), Some(&ack(127)));
    // The same at the first octet of a later instruction.
    let mut host = Flaky::new(&wire, 2);
    let results = host.sync_sequence_unpin(11, 3);
    assert_eq!(results[0].as_ref().unwrap().as_ref(), Some(&ack(127)));
    assert!(
        matches!(results[1], Err(ReadError::Prefix { .. })),
        "{results:?}"
    );
    assert_eq!(results[2].as_ref().unwrap().as_ref(), Some(&ack(127)));
}

#[test]
fn a_host_failure_after_the_first_octet_interrupts_the_stream() {
    let wire = [0xff, 0x00, 0xff, 0x00];
    // Failing at the second octet of the first instruction.
    let mut host = Flaky::new(&wire, 1);
    let results = host.sync_sequence_unpin(11, 3);
    assert!(matches!(results[0], Err(ref error) if !matches!(error, ReadError::Interrupted)));
    assert!(
        matches!(results[1], Err(ReadError::Interrupted)),
        "{results:?}"
    );
    assert!(
        matches!(results[2], Err(ReadError::Interrupted)),
        "{results:?}"
    );
    // And at the second octet of a later one.
    let mut host = Flaky::new(&wire, 3);
    let results = host.sync_sequence_unpin(11, 3);
    assert_eq!(results[0].as_ref().unwrap().as_ref(), Some(&ack(127)));
    assert!(matches!(results[1], Err(ref error) if !matches!(error, ReadError::Interrupted)));
    assert!(
        matches!(results[2], Err(ReadError::Interrupted)),
        "{results:?}"
    );
}

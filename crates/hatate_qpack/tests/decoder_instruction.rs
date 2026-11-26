#![feature(impl_trait_in_assoc_type)]
use core::num::NonZeroU64;
use hatate_qpack::{
    decoder_instruction::{
        DecoderInstruction as D, DecoderStream, DecoderStreamLimits, StreamId,
        codec::{ReadError, WriteDecoderInstructionHostExt, WriteError},
    },
    instruction::{NumberError, OctetError},
};
use nitori_call::{ReceiverAccess, call};
use nitori_codec::DecodeFrom;
use nitori_io::{
    Read,
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
    let cases = [
        (
            D::SectionAcknowledgment(StreamId::try_from(4).unwrap()),
            0x84,
        ),
        (D::InsertCountIncrement(NonZeroU64::MIN), 1),
        (D::StreamCancellation(StreamId::try_from(8).unwrap()), 0x48),
    ];
    let mut wire = Vec::new();
    for &(op, byte) in &cases {
        wire.sync_write_decoder_instruction_unpin(op, 1).unwrap();
        assert_eq!(wire.last(), Some(&byte));
    }
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
    assert!(matches!(&results[0], Ok(Some(D::SectionAcknowledgment(id))) if id.get() == 4));
    assert!(matches!(results[1], Ok(None)));
}

#[test]
fn zero_increment_and_unrepresentable_stream_ids_are_distinct() {
    assert!(matches!(
        (&[0][..]).sync_one_unpin(1),
        Err(ReadError::ZeroIncrement)
    ));
    assert_eq!(StreamId::try_from(1 << 62).unwrap_err().value(), 1 << 62);
    for acknowledgment in [true, false] {
        let mut wire = Vec::new();
        if acknowledgment {
            hatate_qpack::integer::write::<7>(&mut wire, 0x80, 1 << 62).unwrap();
        } else {
            hatate_qpack::integer::write::<6>(&mut wire, 0x40, 1 << 62).unwrap();
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
    let mut dst = Vec::from(b"prefix");
    assert!(
        matches!(dst.sync_write_decoder_instruction_unpin(D::InsertCountIncrement(NonZeroU64::new(63).unwrap()),1),
        Err(WriteError::WireLimit {source}) if source.required()==2 && source.limit()==1)
    );
    assert_eq!(dst, b"prefix");
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
    assert!(matches!(
        input.sync_one_unpin(3),
        Ok(Some(D::SectionAcknowledgment(id))) if id.get() == 127
    ));
    assert_eq!(input, [0x48]);
}

#[test]
fn failed_instruction_interrupts_the_stream() {
    // Failure inside a number, a zero increment, and a wire limit that stops
    // before the first octet is read: each one leaves the stream interrupted.
    let cases: [(&[u8], usize); 3] = [(&[0xff], 11), (&[0, 0x84], 1), (&[0x84], 0)];
    for (wire, limit) in cases {
        let mut input = wire;
        let results = input.sync_sequence_unpin(limit, 3);
        assert!(results[0].is_err(), "{wire:?}");
        assert!(matches!(results[1], Err(ReadError::Interrupted)));
        assert!(matches!(results[2], Err(ReadError::Interrupted)));
    }
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
    assert_eq!(
        first,
        D::SectionAcknowledgment(StreamId::try_from(4).unwrap())
    );
    assert_eq!(
        second,
        Some(D::StreamCancellation(StreamId::try_from(8).unwrap()))
    );
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
        assert!(
            matches!(call.as_mut().poll(&mut cx),Poll::Ready(Ok(Some(D::SectionAcknowledgment(id)))) if id.get()==127)
        );
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
    let section_127 = Some(D::SectionAcknowledgment(StreamId::try_from(127).unwrap()));
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
fn host_write_failure_preserves_the_accepted_prefix() {
    let mut buffer = [0u8; 1];
    let error = buffer
        .as_mut_slice()
        .sync_write_decoder_instruction_unpin(
            D::InsertCountIncrement(NonZeroU64::new(63).unwrap()),
            2,
        )
        .unwrap_err();
    assert!(matches!(error, WriteError::Send { source } if source.completed()==1));
    assert_eq!(buffer, [0x3f]);
}

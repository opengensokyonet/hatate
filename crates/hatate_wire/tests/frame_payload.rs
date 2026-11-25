#![feature(impl_trait_in_assoc_type)]
//! FramePayload: the delimited payload of a frame (RFC 9114 §7.1).
mod common;

use bytes::{Buf, Bytes};
use common::{Boom, Dribble, Failing, Overskip, run};
use core::{
    future::Future,
    num::NonZeroUsize,
    pin::pin,
    task::{Context, Poll, Waker},
};
use hatate_wire::{
    error_code::{ErrorCode, ErrorCodeOf as _},
    frame::{
        DataFrameType, Frame, HeadersFrameType,
        codec::DecodeFrameError,
        payload::{FramePayload, PayloadError},
    },
};
use nitori_call::{AsAccess, ReceiverAccess, call};
use nitori_codec::prelude::*;
use nitori_io::{Read, ReadChunk, Skip, prelude::*};
use sakuya_var_int::{VarInt, VarIntField};

/// The bytes of a DATA frame of a payload of up to 63 bytes, at the shortest
/// widths.
fn data(body: &[u8]) -> Vec<u8> {
    let mut wire = vec![0x00, u8::try_from(body.len()).unwrap()];
    wire.extend_from_slice(body);
    wire
}

/// The payload of the DATA frame at the start of the stream.
async fn open<A: ReceiverAccess<Family: Read<Metadata = ()>>>(io: &mut A) -> FramePayload<&mut A>
where
    <A::Family as Read>::Error: core::fmt::Debug,
{
    Frame::<DataFrameType, FramePayload<&mut A>, ()>::decode_from(io)
        .await
        .unwrap()
        .into_payload()
}

/// What to do with the payload next.
#[derive(Clone, Copy, Debug)]
enum Step {
    /// One read of at most this many bytes.
    Some(usize),
    /// Reads of at most three bytes to the end.
    All,
    /// Skips the rest.
    Skip,
}

/// What the steps gave, and the remaining length after each of them, as the
/// payload counts it and as the stream reports it.
#[derive(Debug)]
struct Taken<E> {
    start: u64,
    steps: Vec<Result<Vec<u8>, PayloadError<E>>>,
    after: Vec<u64>,
    exact: Vec<u64>,
}

/// Opens the payload at the start of the stream and takes the steps on it.
#[call(sync)]
async fn script<F: Skip<Count = usize, Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    steps: &[Step],
) -> Taken<F::Error>
where
    <F as Read>::Error: core::fmt::Debug,
{
    let mut payload = open(io).await;
    let mut script = Taken {
        start: payload.remaining(),
        steps: Vec::new(),
        after: Vec::new(),
        exact: Vec::new(),
    };
    for step in steps {
        let result = match *step {
            Step::Some(size) => {
                let mut buffer = vec![0; size];
                payload
                    .access()
                    .read(&mut &mut buffer[..])
                    .await
                    .map(|segment| {
                        buffer.truncate(segment.map_or(0, |segment| segment.count.get()));
                        buffer
                    })
            }
            Step::All => {
                let mut all = Vec::new();
                loop {
                    let mut buffer = [0; 3];
                    match payload.access().read(&mut &mut buffer[..]).await {
                        Ok(Some(segment)) => all.extend_from_slice(&buffer[..segment.count.get()]),
                        Ok(None) => break Ok(all),
                        Err(error) => break Err(error),
                    }
                }
            }
            Step::Skip => payload.access().skip_to_end().await.map(|()| Vec::new()),
        };
        script.steps.push(result);
        script.after.push(payload.remaining());
        let Ok(length) = payload.access().remaining_len().await;
        script.exact.push(length);
    }
    script
}

/// What reading the payload in chunks gave each time, and what was left.
type Chunked<E> = (Vec<Result<Vec<Vec<u8>>, PayloadError<E>>>, u64);

/// Reads the payload to its end in chunks of at most `maximum` bytes, `times`
/// times.
#[call(sync)]
async fn chunks<F: ReadChunk<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    maximum: usize,
    times: usize,
) -> Chunked<<F as Read>::Error>
where
    <F as Read>::Error: core::fmt::Debug,
{
    let mut payload = open(io).await;
    let mut all = Vec::new();
    for _ in 0..times {
        let mut chunks = Vec::new();
        let result = loop {
            match payload
                .access()
                .read_chunk(NonZeroUsize::new(maximum).unwrap())
                .await
            {
                Ok(Some(mut chunk)) => {
                    chunks.push(chunk.chunk.copy_to_bytes(chunk.chunk.remaining()).to_vec());
                }
                Ok(None) => break Ok(chunks),
                Err(error) => break Err(error),
            }
        };
        all.push(result);
    }
    (all, payload.remaining())
}

#[test]
fn the_payload_ends_where_its_length_ends() {
    let wire = [data(&[1, 2, 3]), vec![4, 5, 6]].concat();
    let mut input = &wire[..];
    let script = input.sync_script_unpin(&[Step::All]);
    assert_eq!(script.steps.into_iter().next().unwrap().unwrap(), [1, 2, 3]);
    assert_eq!(input, [4, 5, 6]);
    assert_eq!(script.after, [0]);
}

#[test]
fn an_empty_payload_reads_nothing_and_is_finished() {
    let wire = [data(&[]), vec![9, 9]].concat();
    let mut input = &wire[..];
    let script = input.sync_script_unpin(&[Step::All]);
    assert_eq!(script.start, 0);
    assert!(script.steps.into_iter().next().unwrap().unwrap().is_empty());
    assert_eq!(input, [9, 9]);
}

#[test]
fn a_single_read_never_passes_the_length() {
    let wire = [data(&[1, 2, 3, 4]), vec![5, 6]].concat();
    let mut input = &wire[..];
    let script = input.sync_script_unpin(&[Step::Some(100), Step::Some(100)]);
    let mut steps = script.steps.into_iter();
    assert_eq!(steps.next().unwrap().unwrap(), [1, 2, 3, 4]);
    assert!(steps.next().unwrap().unwrap().is_empty());
    assert_eq!(input, [5, 6]);
}

#[test]
fn chunks_are_cut_at_the_length_and_the_maximum() {
    let wire = [data(&[1, 2, 3, 4, 5]), vec![6, 7]].concat();
    let mut input = Bytes::from(wire);
    let (results, remaining) = input.sync_chunks_unpin(2, 1);
    assert_eq!(
        results.into_iter().next().unwrap().unwrap(),
        [vec![1, 2], vec![3, 4], vec![5]]
    );
    assert_eq!(input, [6, 7][..]);
    assert_eq!(remaining, 0);

    let wire = [data(&[1, 2, 3]), vec![4]].concat();
    let mut input = Bytes::from(wire);
    let (results, _) = input.sync_chunks_unpin(100, 1);
    assert_eq!(
        results.into_iter().next().unwrap().unwrap(),
        [vec![1, 2, 3]]
    );
    assert_eq!(input, [4][..]);
}

#[test]
fn the_byte_host_reads_the_same_through_read() {
    let wire = [data(&[1, 2, 3, 4]), vec![5]].concat();
    let mut input = Bytes::from(wire);
    let script = input.sync_script_unpin(&[Step::All]);
    assert_eq!(
        script.steps.into_iter().next().unwrap().unwrap(),
        [1, 2, 3, 4]
    );
    assert_eq!(input, [5][..]);
}

#[test]
fn a_stream_that_ends_inside_the_payload_is_truncated_and_then_failed() {
    let wire = [0x00, 5, 1, 2];
    let mut input = &wire[..];
    let script = input.sync_script_unpin(&[
        Step::Some(8),
        Step::Some(8),
        Step::Some(8),
        // Skipping the rest of a failed payload is the same failure, with the
        // missing bytes still unconsumed.
        Step::Skip,
    ]);
    let mut steps = script.steps.into_iter();
    assert_eq!(steps.next().unwrap().unwrap(), [1, 2]);
    let error = steps.next().unwrap().unwrap_err();
    assert!(
        matches!(error, PayloadError::Truncated { missing } if missing.get() == 3),
        "{error:?}"
    );
    let error = steps.next().unwrap().unwrap_err();
    assert!(matches!(error, PayloadError::Failed), "{error:?}");
    let error = steps.next().unwrap().unwrap_err();
    assert!(matches!(error, PayloadError::Failed), "{error:?}");
    assert_eq!(script.after.last(), Some(&3));
}

#[test]
fn truncation_is_reported_for_chunks_with_the_missing_count() {
    let mut input = Bytes::from_static(&[0x00, 5, 1, 2]);
    let (results, remaining) = input.sync_chunks_unpin(8, 2);
    let mut results = results.into_iter();
    let error = results.next().unwrap().unwrap_err();
    assert!(
        matches!(error, PayloadError::Truncated { missing } if missing.get() == 3),
        "{error:?}"
    );
    let error = results.next().unwrap().unwrap_err();
    assert!(matches!(error, PayloadError::Failed), "{error:?}");
    assert_eq!(remaining, 3);
}

#[test]
fn a_stream_that_ends_at_the_start_of_a_payload_is_truncated() {
    let mut input = &[0x00, 1][..];
    let script = input.sync_script_unpin(&[Step::All]);
    let error = script.steps.into_iter().next().unwrap().unwrap_err();
    assert!(
        matches!(error, PayloadError::Truncated { missing } if missing.get() == 1),
        "{error:?}"
    );
}

#[test]
fn skipping_takes_the_unread_rest_of_the_payload() {
    let wire = [data(&[1, 2, 3, 4]), vec![5]].concat();
    let mut input = &wire[..];
    let script = input.sync_script_unpin(&[Step::Some(3), Step::Skip, Step::Skip]);
    assert_eq!(script.start, 4);
    assert_eq!(script.after, [1, 0, 0]);
    // Nothing is left to skip, and the stream is not touched.
    assert_eq!(input, [5]);
}

#[test]
fn the_exact_length_is_the_remaining_payload() {
    let wire = [data(&[1, 2, 3, 4, 5]), vec![6]].concat();
    let mut input = &wire[..];
    let script = input.sync_script_unpin(&[Step::Some(0), Step::Some(2), Step::Some(100)]);
    assert_eq!(script.start, 5);
    assert_eq!(script.exact, [5, 3, 0]);
    assert_eq!(script.exact, script.after);
}

#[test]
fn skipping_drops_the_rest_of_the_payload_only() {
    let wire = [data(&[1, 2, 3, 4, 5]), vec![6]].concat();
    let mut input = &wire[..];
    let script = input.sync_script_unpin(&[Step::Some(2), Step::Skip]);
    assert_eq!(input, [6]);
    assert_eq!(script.after, [3, 0]);

    let mut input = &[0x00, 5, 1, 2][..];
    let script = input.sync_script_unpin(&[Step::Skip]);
    let error = script.steps.into_iter().next().unwrap().unwrap_err();
    assert!(
        matches!(error, PayloadError::Truncated { missing } if missing.get() == 3),
        "{error:?}"
    );
    assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
}

#[test]
fn skipping_a_plain_stream_to_its_end_takes_every_byte() {
    let mut input = &[0; 1000][..];
    input.sync_skip_to_end_unpin().unwrap();
    assert!(input.is_empty());
    (&[][..]).sync_skip_to_end_unpin().unwrap();
}

#[test]
fn a_pending_between_every_byte_changes_nothing() {
    let wire = [data(&[1, 2, 3, 4]), vec![5, 6]].concat();
    let mut host = Dribble::new(&wire, 1);
    let (script, pending) = run(host.script_unpin(&[Step::All]));
    assert_eq!(
        script.steps.into_iter().next().unwrap().unwrap(),
        [1, 2, 3, 4]
    );
    assert!(pending >= 4, "{pending}");
    assert_eq!(host.rest(), [5, 6]);
    assert_eq!(script.after, [0]);

    let wire = [0x00, 4, 1, 2];
    let mut host = Dribble::new(&wire, 1);
    let (script, _) = run(host.script_unpin(&[Step::All]));
    assert!(matches!(
        script.steps.into_iter().next().unwrap(),
        Err(PayloadError::Truncated { missing }) if missing.get() == 2
    ));
}

#[test]
fn only_a_truncated_payload_calls_for_a_connection_error() {
    // The stream ended inside the payload: H3_FRAME_ERROR (RFC 9114 §7.1).
    let mut input = &[0x00, 5, 1, 2][..];
    let script = input.sync_script_unpin(&[Step::All, Step::All]);
    let mut steps = script.steps.into_iter();
    let error = steps.next().unwrap().unwrap_err();
    assert!(matches!(error, PayloadError::Truncated { .. }), "{error:?}");
    assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));

    // A read after that failure repeats it without a code of its own: the
    // first failure was the one to report.
    let error = steps.next().unwrap().unwrap_err();
    assert!(matches!(error, PayloadError::Failed), "{error:?}");
    assert_eq!(error.error_code(), None);

    // A failing stream is the stream's to report.
    let mut host = Failing::new(&[0x00, 5]);
    let (script, _) = run(host.script_unpin(&[Step::Some(4), Step::Some(4)]));
    let mut steps = script.steps.into_iter();
    let error = steps.next().unwrap().unwrap_err();
    assert!(
        matches!(error, PayloadError::Host { source: Boom }),
        "{error:?}"
    );
    assert_eq!(error.error_code(), None);
    assert_eq!(steps.next().unwrap().unwrap_err().error_code(), None);
}

#[test]
fn skipping_says_whether_the_payload_failed() {
    // Partly read: skipping takes the rest.
    let mut input = &[0x00, 4, 1, 2, 3, 4][..];
    let script = input.sync_script_unpin(&[Step::Some(1), Step::Skip]);
    assert_eq!(script.after, [3, 0]);

    // A failure of the stream: skipping is Failed, whatever was read
    // before it, with the length still unread.
    let mut host = Failing::new(&[0x00, 4]);
    let (script, _) = run(host.script_unpin(&[Step::Some(4), Step::Skip]));
    let mut steps = script.steps.into_iter();
    let _ = steps.next().unwrap();
    let error = steps.next().unwrap().unwrap_err();
    assert!(matches!(error, PayloadError::Failed), "{error:?}");
    assert_eq!(error.to_string(), "frame payload has already failed");
    assert_eq!(script.after, [4, 4]);

    // A failure of the stream met by the skip itself is the stream's to
    // report.
    let mut host = Failing::new(&[0x00, 4]);
    let (script, _) = run(host.script_unpin(&[Step::Skip]));
    assert!(matches!(
        script.steps.into_iter().next().unwrap(),
        Err(PayloadError::Host { source: Boom })
    ));

    // A payload whose bytes were all read has nothing left to fail on.
    let mut input = &[0x00, 1, 7][..];
    let script = input.sync_script_unpin(&[Step::All, Step::Skip]);
    assert!(script.steps.into_iter().all(|step| step.is_ok()));
}

/// A stream that reports more skipped than it was allowed breaks the
/// contract with the payload, as one that reads more than it was given
/// does; the payload does not silently cut the count.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "skipped more than the rest of the payload")]
fn a_skip_that_passes_the_rest_of_the_payload_is_caught() {
    let mut host = Overskip::new(&[0x00, 4]);
    let _ = run(host.script_unpin(&[Step::Skip]));
}

/// Polls `future` `polls` times, which leaves it pending, and drops it.
fn drop_after<F: Future>(future: F, polls: usize) {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..polls {
        assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
    }
}

/// What a value dropped inside the payload leaves: the payload is opened, a
/// read of a two-byte integer is dropped after `polls` polls of a stream that
/// answers Pending before every byte, and then the integer is read again.
#[call(sync)]
async fn drop_a_value<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    polls: usize,
) -> (
    Result<VarIntField<VarInt>, sakuya_var_int::stream::ReadVarIntError<PayloadError<F::Error>>>,
    u64,
)
where
    <F as Read>::Error: core::fmt::Debug,
{
    let mut payload = open(io).await;
    drop_after(payload.decode::<VarIntField<VarInt>, _>(), polls);
    let result = payload.decode::<VarIntField<VarInt>, _>().await;
    (result, payload.remaining())
}

#[test]
fn a_value_dropped_before_its_first_byte_is_read_again() {
    // The first poll of the value is Pending without having read anything.
    let wire = [data(&[0x40, 0x07, 0xaa]), vec![0x11]].concat();
    let mut host = Dribble::new(&wire, 1);
    let (result, _) = run(host.drop_a_value_unpin(1));
    let (value, remaining) = result;
    assert_eq!(value.unwrap().get().get(), 7);
    assert_eq!(remaining, 1);
}

#[test]
fn a_value_dropped_after_some_of_its_bytes_interrupts_the_payload() {
    let wire = [data(&[0x40, 0x07, 0xaa]), vec![0x11]].concat();
    let mut host = Dribble::new(&wire, 1);
    let (result, _) = run(host.drop_a_value_unpin(2));
    let (value, remaining) = result;
    let error = value.unwrap_err();
    assert!(
        matches!(error.host_error(), Some(PayloadError::Interrupted)),
        "{error:?}"
    );
    assert_eq!(error.error_code(), None);
    // What the dropped read took is gone, and the rest is still to skip.
    assert_eq!(remaining, 2);
}

/// Opens the payload, reads an integer and drops the read after `polls`
/// polls, and then skips the rest with `finish`, which gives the stream back
/// at the end of the frame.
#[call(sync)]
async fn finish_after_a_drop<F: Skip<Count = usize, Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    polls: usize,
) -> u8
where
    <F as Read>::Error: core::fmt::Debug,
{
    let mut payload = open(io).await;
    drop_after(payload.decode::<VarIntField<VarInt>, _>(), polls);
    let io = payload.finish().await.unwrap();
    let [next] = io.read_array::<1>().await.unwrap().value;
    next
}

#[test]
fn a_payload_left_inside_a_value_can_still_be_skipped() {
    let wire = [data(&[0x40, 0x07, 0xaa]), vec![0x11]].concat();
    for polls in [0, 1, 2] {
        let mut host = Dribble::new(&wire, 1);
        let (next, _) = run(host.finish_after_a_drop_unpin(polls));
        assert_eq!(next, 0x11, "{polls}");
    }
}

/// `finish` and `into_source` on payloads in each state.
#[call(sync)]
async fn give_back<F: Skip<Count = usize, Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> [(bool, u64); 3]
where
    <F as Read>::Error: core::fmt::Debug,
{
    // Nothing read: `into_source` gives the payload back, `finish` skips it.
    let payload = open(io).await;
    let one = match payload.into_source() {
        Ok(_) => (true, 0),
        Err(payload) => {
            let remaining = payload.remaining();
            payload.finish().await.unwrap();
            (false, remaining)
        }
    };
    // The next payload, read whole: its source is given back.
    let mut payload = open(io).await;
    payload.access().read_array::<2>().await.unwrap();
    let two = match payload.into_source() {
        Ok(_) => (true, 0),
        Err(payload) => (false, payload.remaining()),
    };
    // The third: read to its end.
    let mut payload = open(io).await;
    payload.access().read_array::<1>().await.unwrap();
    let three = match payload.into_source() {
        Ok(_) => (true, 0),
        Err(payload) => (false, payload.remaining()),
    };
    [one, two, three]
}

#[test]
fn the_source_is_given_back_at_a_frame_boundary() {
    let wire = [data(&[1, 2, 3]), data(&[4, 5]), data(&[6])].concat();
    let mut input = &wire[..];
    assert_eq!(
        input.sync_give_back_unpin(),
        // The first had three bytes left and was finished; the second was
        // read whole; the third too.
        [(false, 3), (true, 0), (true, 0)]
    );
    assert!(input.is_empty());
}

/// Decodes the head of a frame as a frame of the type `T`.
#[call(sync)]
async fn staged<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> Result<u64, DecodeFrameError<F::Error, hatate_wire::frame::FrameTypeMismatchError>> {
    let frame = Frame::<HeadersFrameType, FramePayload<_>, ()>::decode_from(&mut *io).await?;
    Ok(frame.length().get().get())
}

#[test]
fn a_frame_in_stages_is_of_its_type() {
    assert_eq!((&[0x01, 0x03, 1, 2, 3][..]).sync_staged_unpin().unwrap(), 3);
    // A DATA frame is not a HEADERS frame; an HTTP/2 type is neither.
    let error = (&[0x00, 0x00][..]).sync_staged_unpin().unwrap_err();
    assert!(matches!(error, DecodeFrameError::Type { .. }), "{error:?}");
    assert_eq!(error.error_code(), None);
    let error = (&[0x06, 0x00][..]).sync_staged_unpin().unwrap_err();
    assert!(
        matches!(error, DecodeFrameError::Http2Type { .. }),
        "{error:?}"
    );
    assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_UNEXPECTED));
}

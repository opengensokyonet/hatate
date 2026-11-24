#![feature(impl_trait_in_assoc_type)]
//! FramePayload: the delimited payload of a frame (RFC 9114 §7.1).
mod common;

use bytes::{Buf, Bytes};
use common::{Boom, Broken, Dribble, run};
use core::{future::poll_fn, num::NonZeroUsize, task::Poll};
use hatate_wire::{
    error_code::{ErrorCode, ErrorCodeOf as _},
    frame::payload::{FramePayload, PayloadError},
};
use nitori_call::{ReceiverAccess, call};
use nitori_io::{Read, ReadChunk, Skip, prelude::*};

/// One read of at most `size` bytes from the payload.
#[call(sync)]
async fn read_some<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    payload: &mut FramePayload,
    size: usize,
) -> Result<Vec<u8>, PayloadError<F::Error>> {
    let mut source = io.compose(payload);
    let mut buffer = vec![0; size];
    let count = source.read(&mut &mut buffer[..]).await?;
    buffer.truncate(count);
    Ok(buffer)
}

/// Reads the payload to its end, three bytes at a time.
#[call(sync)]
async fn read_all<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    payload: &mut FramePayload,
) -> Result<Vec<u8>, PayloadError<F::Error>> {
    let mut source = io.compose(payload);
    let mut all = Vec::new();
    loop {
        let mut buffer = [0; 3];
        let count = source.read(&mut &mut buffer[..]).await?;
        if count == 0 {
            return Ok(all);
        }
        all.extend_from_slice(&buffer[..count]);
    }
}

/// Reads the payload to its end in chunks of at most `maximum` bytes.
#[call(sync)]
async fn read_chunks_all<F: ReadChunk, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    payload: &mut FramePayload,
    maximum: usize,
) -> Result<Vec<Vec<u8>>, PayloadError<<F as Read>::Error>> {
    let mut source = io.compose(payload);
    let mut chunks = Vec::new();
    while let Some(mut chunk) = source
        .read_chunk(NonZeroUsize::new(maximum).unwrap())
        .await?
    {
        chunks.push(chunk.copy_to_bytes(chunk.remaining()).to_vec());
    }
    Ok(chunks)
}

/// The remaining length before reading, after two bytes, and at the end.
#[call(sync)]
async fn lengths<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    payload: &mut FramePayload,
) -> Vec<u64> {
    let mut source = io.compose(payload);
    let mut lengths = Vec::new();
    for size in [0, 2, 100] {
        let mut buffer = vec![0; size];
        let _ = source.read(&mut &mut buffer[..]).await;
        lengths.push(
            poll_fn(|cx| source.poll_access(cx, |mut view, _| Poll::Ready(view.remaining_len())))
                .await,
        );
    }
    lengths
}

/// Skips the rest of the payload.
#[call(sync)]
async fn skip_payload<F: Skip<Count = usize>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    payload: &mut FramePayload,
) -> Result<(), PayloadError<F::Error>> {
    let mut source = io.compose(payload);
    source.skip_to_end().await
}

#[test]
fn the_payload_ends_where_its_length_ends() {
    let mut input = &[1, 2, 3, 4, 5, 6][..];
    let mut payload = FramePayload::new(3);
    assert_eq!(input.sync_read_all_unpin(&mut payload).unwrap(), [1, 2, 3]);
    assert_eq!(input, [4, 5, 6]);
    assert_eq!(payload.remaining(), 0);
}

#[test]
fn an_empty_payload_reads_nothing_and_is_finished() {
    let mut input = &[9, 9][..];
    let mut payload = FramePayload::new(0);
    assert_eq!(payload.remaining(), 0);
    assert!(input.sync_read_all_unpin(&mut payload).unwrap().is_empty());
    assert_eq!(input, [9, 9]);
}

#[test]
fn a_single_read_never_passes_the_length() {
    let mut input = &[1, 2, 3, 4, 5, 6][..];
    let mut payload = FramePayload::new(4);
    assert_eq!(
        input.sync_read_some_unpin(&mut payload, 100).unwrap(),
        [1, 2, 3, 4]
    );
    assert!(
        input
            .sync_read_some_unpin(&mut payload, 100)
            .unwrap()
            .is_empty()
    );
    assert_eq!(input, [5, 6]);
}

#[test]
fn chunks_are_cut_at_the_length_and_the_maximum() {
    let mut input = Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7]);
    let mut payload = FramePayload::new(5);
    assert_eq!(
        input.sync_read_chunks_all_unpin(&mut payload, 2).unwrap(),
        [vec![1, 2], vec![3, 4], vec![5]]
    );
    assert_eq!(input, [6, 7][..]);
    assert_eq!(payload.remaining(), 0);

    let mut input = Bytes::from_static(&[1, 2, 3, 4]);
    let mut payload = FramePayload::new(3);
    assert_eq!(
        input.sync_read_chunks_all_unpin(&mut payload, 100).unwrap(),
        [vec![1, 2, 3]]
    );
    assert_eq!(input, [4][..]);
}

#[test]
fn the_byte_host_reads_the_same_through_read() {
    let mut input = Bytes::from_static(&[1, 2, 3, 4, 5]);
    let mut payload = FramePayload::new(4);
    assert_eq!(
        input.sync_read_all_unpin(&mut payload).unwrap(),
        [1, 2, 3, 4]
    );
    assert_eq!(input, [5][..]);
}

#[test]
fn a_stream_that_ends_inside_the_payload_is_truncated_and_then_failed() {
    let mut input = &[1, 2][..];
    let mut payload = FramePayload::new(5);
    assert_eq!(input.sync_read_some_unpin(&mut payload, 8).unwrap(), [1, 2]);
    let error = input.sync_read_some_unpin(&mut payload, 8).unwrap_err();
    assert!(
        matches!(error, PayloadError::Truncated { missing } if missing.get() == 3),
        "{error:?}"
    );
    let error = input.sync_read_some_unpin(&mut payload, 8).unwrap_err();
    assert!(matches!(error, PayloadError::Failed), "{error:?}");
    // Skipping the rest of a failed payload is the same failure, with the
    // missing bytes still unconsumed.
    let error = input.sync_skip_payload_unpin(&mut payload).unwrap_err();
    assert!(matches!(error, PayloadError::Failed), "{error:?}");
    assert_eq!(payload.remaining(), 3);
}

#[test]
fn truncation_is_reported_for_chunks_with_the_missing_count() {
    let mut input = Bytes::from_static(&[1, 2]);
    let mut payload = FramePayload::new(5);
    let error = input
        .sync_read_chunks_all_unpin(&mut payload, 8)
        .unwrap_err();
    assert!(
        matches!(error, PayloadError::Truncated { missing } if missing.get() == 3),
        "{error:?}"
    );
    let error = input
        .sync_read_chunks_all_unpin(&mut payload, 8)
        .unwrap_err();
    assert!(matches!(error, PayloadError::Failed), "{error:?}");
    assert!(matches!(
        input.sync_skip_payload_unpin(&mut payload).unwrap_err(),
        PayloadError::Failed
    ));
    assert_eq!(payload.remaining(), 3);
}

#[test]
fn a_stream_that_ends_at_the_start_of_a_payload_is_truncated() {
    let mut input = &[][..];
    let mut payload = FramePayload::new(1);
    let error = input.sync_read_all_unpin(&mut payload).unwrap_err();
    assert!(
        matches!(error, PayloadError::Truncated { missing } if missing.get() == 1),
        "{error:?}"
    );
}

#[test]
fn skipping_takes_the_unread_rest_of_the_payload() {
    let mut input = &[1, 2, 3, 4, 5][..];
    let mut payload = FramePayload::new(4);
    assert_eq!(payload.remaining(), 4);
    input.sync_read_some_unpin(&mut payload, 3).unwrap();
    assert_eq!(payload.remaining(), 1);
    input.sync_skip_payload_unpin(&mut payload).unwrap();
    assert_eq!(payload.remaining(), 0);
    assert_eq!(input, [5]);
    // Nothing is left to skip, and the stream is not touched.
    input.sync_skip_payload_unpin(&mut payload).unwrap();
    assert_eq!(input, [5]);
}

#[test]
fn the_exact_length_is_the_remaining_payload() {
    let mut input = &[1, 2, 3, 4, 5, 6][..];
    let mut payload = FramePayload::new(5);
    assert_eq!(input.sync_lengths_unpin(&mut payload), [5, 3, 0]);
}

#[test]
fn skipping_drops_the_rest_of_the_payload_only() {
    let mut input = &[1, 2, 3, 4, 5, 6][..];
    let mut payload = FramePayload::new(5);
    input.sync_read_some_unpin(&mut payload, 2).unwrap();
    input.sync_skip_payload_unpin(&mut payload).unwrap();
    assert_eq!(input, [6]);
    assert_eq!(payload.remaining(), 0);

    let mut input = &[1, 2][..];
    let mut payload = FramePayload::new(5);
    let error = input.sync_skip_payload_unpin(&mut payload).unwrap_err();
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
    let wire = [1, 2, 3, 4, 5, 6];
    let mut host = Dribble::new(&wire, 1);
    let mut payload = FramePayload::new(4);
    let (result, pending) = run(host.read_all_unpin(&mut payload));
    assert_eq!(result.unwrap(), [1, 2, 3, 4]);
    assert!(pending >= 4, "{pending}");
    assert_eq!(host.rest(), [5, 6]);
    assert_eq!(payload.remaining(), 0);

    let mut host = Dribble::new(&wire[..2], 1);
    let mut payload = FramePayload::new(4);
    let (result, _) = run(host.read_all_unpin(&mut payload));
    assert!(matches!(
        result,
        Err(PayloadError::Truncated { missing }) if missing.get() == 2
    ));
}

#[test]
fn only_a_truncated_payload_calls_for_a_connection_error() {
    // The stream ended inside the payload: H3_FRAME_ERROR (RFC 9114 §7.1).
    let mut input = &[1, 2][..];
    let mut payload = FramePayload::new(5);
    let error = input.sync_read_all_unpin(&mut payload).unwrap_err();
    assert!(matches!(error, PayloadError::Truncated { .. }), "{error:?}");
    assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));

    // A read after that failure repeats it without a code of its own: the
    // first failure was the one to report.
    let error = input.sync_read_all_unpin(&mut payload).unwrap_err();
    assert!(matches!(error, PayloadError::Failed), "{error:?}");
    assert_eq!(error.error_code(), None);

    // A failing stream is the stream's to report.
    let mut payload = FramePayload::new(5);
    let mut host = Broken;
    let (result, _) = run(host.read_some_unpin(&mut payload, 4));
    let error = result.unwrap_err();
    assert!(
        matches!(error, PayloadError::Host { source: Boom }),
        "{error:?}"
    );
    assert_eq!(error.error_code(), None);
    let (result, _) = run(host.read_some_unpin(&mut payload, 4));
    assert_eq!(result.unwrap_err().error_code(), None);
}

#[test]
fn skipping_says_whether_the_payload_failed() {
    // Partly read: skipping takes the rest.
    let mut input = &[1, 2, 3, 4][..];
    let mut payload = FramePayload::new(4);
    input.sync_read_some_unpin(&mut payload, 1).unwrap();
    assert_eq!(payload.remaining(), 3);
    input.sync_skip_payload_unpin(&mut payload).unwrap();
    assert_eq!(payload.remaining(), 0);

    // A failure of the stream: skipping is Failed, whatever was read
    // before it, with the length still unread.
    let mut host = Broken;
    let mut payload = FramePayload::new(4);
    let _ = run(host.read_some_unpin(&mut payload, 4));
    let (result, _) = run(host.skip_payload_unpin(&mut payload));
    let error = result.unwrap_err();
    assert!(matches!(error, PayloadError::Failed), "{error:?}");
    assert_eq!(error.to_string(), "frame payload has already failed");
    assert_eq!(payload.remaining(), 4);

    // A failure of the stream met by the skip itself is the stream's to
    // report.
    let mut host = Broken;
    let mut payload = FramePayload::new(4);
    let (result, _) = run(host.skip_payload_unpin(&mut payload));
    assert!(matches!(result, Err(PayloadError::Host { source: Boom })));

    // A payload whose bytes were all read has nothing left to fail on.
    let mut input = &[1][..];
    let mut payload = FramePayload::new(1);
    input.sync_read_all_unpin(&mut payload).unwrap();
    input.sync_skip_payload_unpin(&mut payload).unwrap();
}

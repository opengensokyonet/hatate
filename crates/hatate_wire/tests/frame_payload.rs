#![feature(impl_trait_in_assoc_type)]
//! FramePayload: the delimited payload of a frame (RFC 9114 §7.1).
mod common;

use bytes::{Buf, Bytes};
use common::{Boom, Broken, Dribble, run};
use core::{future::poll_fn, num::NonZeroUsize, task::Poll};
use hatate_wire::{
    error_code::{ErrorCode, ErrorCodeOf as _},
    frame::{
        codec::{DiscardExt as _, DiscardHostExt as _},
        payload::{FramePayload, PayloadError, UnfinishedPayloadError},
    },
};
use nitori_call::{ReceiverAccess, call};
use nitori_io::{Read, ReadChunk, prelude::*};

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

/// Discards the rest of the payload.
#[call(sync)]
async fn discard_payload<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    payload: &mut FramePayload,
) -> Result<u64, PayloadError<F::Error>> {
    let mut source = io.compose(payload);
    source.discard().await
}

#[test]
fn the_payload_ends_where_its_length_ends() {
    let mut input = &[1, 2, 3, 4, 5, 6][..];
    let mut payload = FramePayload::new(3);
    assert_eq!(input.sync_read_all_unpin(&mut payload).unwrap(), [1, 2, 3]);
    assert_eq!(input, [4, 5, 6]);
    assert_eq!(payload.remaining(), 0);
    payload.finish().unwrap();
}

#[test]
fn an_empty_payload_reads_nothing_and_is_finished() {
    let mut input = &[9, 9][..];
    let mut payload = FramePayload::new(0);
    payload.finish().unwrap();
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
    payload.finish().unwrap();

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
    let unfinished = payload.finish().unwrap_err();
    assert!(
        matches!(unfinished, UnfinishedPayloadError::Failed { remaining } if remaining.get() == 3),
        "{unfinished:?}"
    );
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
        payload.finish().unwrap_err(),
        UnfinishedPayloadError::Failed { .. }
    ));
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
fn finish_checks_that_the_payload_was_read_to_its_end() {
    let mut input = &[1, 2, 3, 4][..];
    let mut payload = FramePayload::new(4);
    let error = payload.finish().unwrap_err();
    assert!(
        matches!(error, UnfinishedPayloadError::Unconsumed { remaining } if remaining.get() == 4)
    );
    assert_eq!(error.remaining().get(), 4);
    input.sync_read_some_unpin(&mut payload, 3).unwrap();
    let error = payload.finish().unwrap_err();
    assert!(
        matches!(error, UnfinishedPayloadError::Unconsumed { remaining } if remaining.get() == 1)
    );
    assert_eq!(error.remaining().get(), 1);
    input.sync_read_some_unpin(&mut payload, 3).unwrap();
    payload.finish().unwrap();
}

#[test]
fn the_exact_length_is_the_remaining_payload() {
    let mut input = &[1, 2, 3, 4, 5, 6][..];
    let mut payload = FramePayload::new(5);
    assert_eq!(input.sync_lengths_unpin(&mut payload), [5, 3, 0]);
}

#[test]
fn discard_drops_the_rest_of_the_payload_only() {
    let mut input = &[1, 2, 3, 4, 5, 6][..];
    let mut payload = FramePayload::new(5);
    input.sync_read_some_unpin(&mut payload, 2).unwrap();
    assert_eq!(input.sync_discard_payload_unpin(&mut payload).unwrap(), 3);
    assert_eq!(input, [6]);
    payload.finish().unwrap();

    let mut input = &[1, 2][..];
    let mut payload = FramePayload::new(5);
    let error = input.sync_discard_payload_unpin(&mut payload).unwrap_err();
    assert!(matches!(error, PayloadError::Truncated { .. }), "{error:?}");
}

#[test]
fn discard_on_a_plain_stream_counts_every_byte() {
    let mut input = &[0; 1000][..];
    assert_eq!(input.sync_discard_unpin().unwrap(), 1000);
    assert!(input.is_empty());
    assert_eq!((&[][..]).sync_discard_unpin().unwrap(), 0);
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
    payload.finish().unwrap();

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
fn an_unfinished_payload_says_whether_it_failed() {
    // Not read: Unconsumed, with the length.
    let mut input = &[1, 2, 3, 4][..];
    let mut payload = FramePayload::new(4);
    input.sync_read_some_unpin(&mut payload, 1).unwrap();
    let error = payload.finish().unwrap_err();
    assert_eq!(
        error,
        UnfinishedPayloadError::Unconsumed {
            remaining: 3.try_into().unwrap()
        }
    );
    assert_eq!(error.remaining().get(), 3);
    assert_eq!(
        error.to_string(),
        "frame payload left with 3 bytes unconsumed"
    );

    // A failure of the stream: Failed, whatever was read before it.
    let mut host = Broken;
    let mut payload = FramePayload::new(4);
    let _ = run(host.read_some_unpin(&mut payload, 4));
    let error = payload.finish().unwrap_err();
    assert_eq!(
        error,
        UnfinishedPayloadError::Failed {
            remaining: 4.try_into().unwrap()
        }
    );
    assert_eq!(error.remaining().get(), 4);
    assert_eq!(
        error.to_string(),
        "frame payload failed with 4 bytes unread"
    );

    // A failure after the payload's bytes were all read does not exist, so
    // a finished payload is Ok.
    let mut input = &[1][..];
    let mut payload = FramePayload::new(1);
    input.sync_read_all_unpin(&mut payload).unwrap();
    payload.finish().unwrap();
}

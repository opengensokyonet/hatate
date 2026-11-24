#![feature(impl_trait_in_assoc_type)]
//! Streams that only read, made to skip with `ReadSkip` and
//! `ReadChunkSkip`, and composed with a `FrameStream` on either side of
//! them: frames are finished and moved past, and the results agree with a
//! stream that skips natively.
mod common;

use common::{ReadOnly, run};
use core::convert::Infallible;
use frunk_core::{HList, coproduct::Coproduct};
use hatate_wire::{
    Role,
    frame::{FrameType, Http3FrameType, codec::read_received_frame, set::FrameSet},
    stream::{
        FrameStream, FrameStreamInfo, UnidirectionalStream, codec::read_unidirectional_stream,
    },
};
use nitori_call::{ComposedReceiver, ReceiverAccess, call};
use nitori_io::{
    Read, ReadChunk, Skip,
    adapters::{ReadChunkSkip, ReadSkip},
    prelude::*,
};
use sakuya_var_int::VarInt;

type Parts = HList![hatate_wire::Part];
type Value = <Parts as FrameSet>::TypeValue;

/// A frame type and the payload bytes read from the frame.
type Seen = (FrameType<Value>, Vec<u8>);

/// Reads at most `take` bytes from `io`, stopping at EOF.
async fn read_some<A: ReceiverAccess<Family: Read>>(io: &mut A, take: usize) -> Vec<u8>
where
    <A::Family as Read>::Error: core::fmt::Debug,
{
    let mut bytes = Vec::new();
    let mut buffer = [0; 7];
    while bytes.len() < take {
        let want = (take - bytes.len()).min(buffer.len());
        let count = io.read(&mut &mut buffer[..want]).await.unwrap();
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    bytes
}

/// Reads every frame of a stream that carries frames: of each, at most
/// `take` bytes of its payload, then on to the next frame.
#[call(sync)]
async fn walk<F>(io: &mut impl ReceiverAccess<Family = F>, take: usize) -> Vec<Seen>
where
    F: Skip<Count = usize> + Read<Error = Infallible> + FrameStreamInfo<Parts = Parts>,
{
    let mut seen = Vec::new();
    let mut next = read_received_frame(&mut *io).await.unwrap();
    while let Some(mut frame) = next {
        let payload = read_some(frame.payload(), take).await;
        seen.push((frame.frame_type(), payload));
        next = frame.next().await.unwrap();
    }
    seen
}

fn request() -> FrameStream<Parts> {
    FrameStream::request(Role::Server)
}

/// `ReadSkip` above the frame stream.
#[call(sync)]
async fn read_skip_above<F: Read<Error = Infallible>>(
    io: &mut impl ReceiverAccess<Family = F>,
    take: usize,
) -> Vec<Seen> {
    let mut inner = io.compose(request());
    let mut stream = inner.compose(ReadSkip);
    stream.walk(take).await
}

/// `ReadSkip` below the frame stream.
#[call(sync)]
async fn read_skip_below<F: Read<Error = Infallible>>(
    io: &mut impl ReceiverAccess<Family = F>,
    take: usize,
) -> Vec<Seen> {
    let mut inner = io.compose(ReadSkip);
    let mut stream = inner.compose(request());
    stream.walk(take).await
}

/// `ReadChunkSkip` above the frame stream.
#[call(sync)]
async fn read_chunk_skip_above<F: ReadChunk<Error = Infallible>>(
    io: &mut impl ReceiverAccess<Family = F>,
    take: usize,
) -> Vec<Seen> {
    let mut inner = io.compose(request());
    let mut stream = inner.compose(ReadChunkSkip);
    stream.walk(take).await
}

/// `ReadChunkSkip` below the frame stream.
#[call(sync)]
async fn read_chunk_skip_below<F: ReadChunk<Error = Infallible>>(
    io: &mut impl ReceiverAccess<Family = F>,
    take: usize,
) -> Vec<Seen> {
    let mut inner = io.compose(ReadChunkSkip);
    let mut stream = inner.compose(request());
    stream.walk(take).await
}

/// A control stream whose access skips by reading: the frames of the stream
/// that `read_unidirectional_stream` gives back are read too.
#[call(sync)]
async fn control_stream<F: Read<Error = Infallible>>(
    io: &mut impl ReceiverAccess<Family = F>,
    take: usize,
) -> Vec<Seen> {
    let mut io = io.compose(ReadSkip);
    let Ok(Some(UnidirectionalStream::Control { mut stream, .. })) =
        read_unidirectional_stream::<Parts, _>(&mut io, Role::Server).await
    else {
        panic!("not a control stream");
    };
    stream.walk(take).await
}

const fn h3(frame_type: Http3FrameType) -> FrameType<Value> {
    FrameType::Known(Coproduct::Inl(frame_type))
}

/// HEADERS "abc"; a reserved type 0x21 with 4 bytes; DATA "hello".
fn wire() -> Vec<u8> {
    [
        &[0x01, 0x03][..],
        b"abc",
        &[0x40, 0x21, 0x04],
        b"wxyz",
        &[0x00, 0x05],
        b"hello",
    ]
    .concat()
}

/// The frames of [`wire`] when `take` bytes of each payload are read.
fn expected(take: usize) -> Vec<Seen> {
    let payloads: [(FrameType<Value>, &[u8]); 3] = [
        (h3(Http3FrameType::Headers), b"abc"),
        (FrameType::Unknown(VarInt::from_u32(0x21)), b"wxyz"),
        (h3(Http3FrameType::Data), b"hello"),
    ];
    payloads
        .map(|(frame_type, payload)| (frame_type, payload[..take.min(payload.len())].to_vec()))
        .to_vec()
}

#[test]
fn a_stream_that_only_reads_finishes_frames_with_read_skip() {
    let input = wire();
    for take in [0, 2, 100] {
        for chunk in [1, 3, 100] {
            let mut host = ReadOnly::new(&input, chunk);
            let (above, pending) = run(host.read_skip_above_unpin(take));
            assert_eq!(above, expected(take), "above, take {take}, chunk {chunk}");
            assert!(pending > 0);
            assert!(host.rest().is_empty());

            let mut host = ReadOnly::new(&input, chunk);
            let (below, _) = run(host.read_skip_below_unpin(take));
            assert_eq!(below, expected(take), "below, take {take}, chunk {chunk}");
            assert!(host.rest().is_empty());
        }
    }
}

#[test]
fn a_stream_that_only_reads_finishes_frames_with_read_chunk_skip() {
    let input = wire();
    for take in [0, 2, 100] {
        for chunk in [1, 3, 100] {
            let mut host = ReadOnly::new(&input, chunk);
            let (above, pending) = run(host.read_chunk_skip_above_unpin(take));
            assert_eq!(above, expected(take), "above, take {take}, chunk {chunk}");
            assert!(pending > 0);
            assert!(host.rest().is_empty());

            let mut host = ReadOnly::new(&input, chunk);
            let (below, _) = run(host.read_chunk_skip_below_unpin(take));
            assert_eq!(below, expected(take), "below, take {take}, chunk {chunk}");
            assert!(host.rest().is_empty());
        }
    }
}

#[test]
fn the_skipping_view_composes_on_a_receiver_that_carries_frames() {
    let input = wire();
    let receiver = ComposedReceiver::new(ReadOnly::new(&input, 2), request());
    let mut receiver = ComposedReceiver::new(receiver, ReadSkip);
    let (seen, _) = run(receiver.walk_unpin(2));
    assert_eq!(seen, expected(2));
}

#[test]
fn the_stream_a_unidirectional_read_gives_back_finishes_frames_by_reading() {
    // A control stream: its type in two bytes, a SETTINGS frame of one
    // setting, a GOAWAY frame, of which one byte is read.
    let input = [0x40, 0x00, 0x04, 0x03, 0x01, 0x40, 0x40, 0x07, 0x01, 0x04];
    let mut host = ReadOnly::new(&input, 1);
    let (seen, _) = run(host.control_stream_unpin(1));
    assert_eq!(
        seen,
        [
            (h3(Http3FrameType::Settings), vec![0x01]),
            (h3(Http3FrameType::Goaway), vec![0x04]),
        ]
    );
    assert!(host.rest().is_empty());
}

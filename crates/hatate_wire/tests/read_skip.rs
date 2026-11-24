#![feature(impl_trait_in_assoc_type)]
//! Streams that only read, made to skip with `ReadSkip` and
//! `ReadChunkSkip`, and read with a `FrameStream` on them: frames are moved
//! past, and the results agree with a stream that skips natively.
mod common;

use common::{ReadOnly, Ty, known, read_some, run, ty};
use core::convert::Infallible;
use frunk_core::HList;
use hatate_wire::{
    Role,
    frame::{Http3FrameType, set::FrameSetOn},
    stream::{
        FrameStream,
        kind::{ControlStreamKind, RequestStreamKind, StreamKind},
    },
};
use nitori_call::{ReceiverAccess, call};
use nitori_io::{
    Read, ReadChunk, Skip,
    adapters::{ReadChunkSkip, ReadSkip},
};

type Parts = HList![hatate_wire::Part];

/// A frame type and the payload bytes read from the frame.
type Seen = (Ty, Vec<u8>);

/// Reads every frame of a stream of kind `K` that carries frames: of each, at
/// most `take` bytes of its payload, then on to the next frame.
#[call(sync)]
async fn walk<K: StreamKind, F>(
    io: &mut impl ReceiverAccess<Family = F>,
    _kind: K,
    take: usize,
) -> Vec<Seen>
where
    F: Skip<Count = usize> + Read<Error = Infallible>,
    Parts: FrameSetOn<K>,
{
    let mut seen = Vec::new();
    let Some(mut stream) = FrameStream::<Parts, K, _>::read(&mut *io, Role::Server)
        .await
        .unwrap()
    else {
        return seen;
    };
    loop {
        let mut frame = stream.frame();
        let payload = read_some(frame.payload(), take).await.unwrap();
        seen.push((ty(frame.frame_type()), payload));
        if stream.next_frame().await.unwrap().is_none() {
            return seen;
        }
    }
}

/// `ReadSkip` below the frame stream.
#[call(sync)]
async fn below_read_skip<K: StreamKind, F: Read<Error = Infallible>>(
    io: &mut impl ReceiverAccess<Family = F>,
    kind: K,
    take: usize,
) -> Vec<Seen>
where
    Parts: FrameSetOn<K>,
{
    let mut stream = io.compose(ReadSkip);
    stream.walk(kind, take).await
}

/// `ReadChunkSkip` below the frame stream.
#[call(sync)]
async fn below_read_chunk_skip<K: StreamKind, F: ReadChunk<Error = Infallible>>(
    io: &mut impl ReceiverAccess<Family = F>,
    kind: K,
    take: usize,
) -> Vec<Seen>
where
    Parts: FrameSetOn<K>,
{
    let mut stream = io.compose(ReadChunkSkip);
    stream.walk(kind, take).await
}

const fn h3(frame_type: Http3FrameType) -> Ty {
    known(frame_type)
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
    let payloads: [(Ty, &[u8]); 3] = [
        (h3(Http3FrameType::Headers), b"abc"),
        (Ty::Reserved(0x21), b"wxyz"),
        (h3(Http3FrameType::Data), b"hello"),
    ];
    payloads
        .map(|(frame_type, payload)| (frame_type, payload[..take.min(payload.len())].to_vec()))
        .to_vec()
}

#[test]
fn a_stream_that_only_reads_moves_past_frames_with_read_skip() {
    let input = wire();
    for take in [0, 2, 100] {
        for chunk in [1, 3, 100] {
            let mut host = ReadOnly::new(&input, chunk);
            let (seen, pending) = run(host.below_read_skip_unpin(RequestStreamKind, take));
            assert_eq!(seen, expected(take), "take {take}, chunk {chunk}");
            assert!(pending > 0);
            assert!(host.rest().is_empty());
        }
    }
}

#[test]
fn a_stream_that_only_reads_moves_past_frames_with_read_chunk_skip() {
    let input = wire();
    for take in [0, 2, 100] {
        for chunk in [1, 3, 100] {
            let mut host = ReadOnly::new(&input, chunk);
            let (seen, pending) = run(host.below_read_chunk_skip_unpin(RequestStreamKind, take));
            assert_eq!(seen, expected(take), "take {take}, chunk {chunk}");
            assert!(pending > 0);
            assert!(host.rest().is_empty());
        }
    }
}

#[test]
fn a_stream_that_skips_by_itself_gives_the_same_frames() {
    let input = wire();
    for take in [0, 2, 100] {
        let mut access = &input[..];
        assert_eq!(
            access.sync_walk_unpin(RequestStreamKind, take),
            expected(take)
        );
    }
}

#[test]
fn the_frames_of_a_control_stream_are_moved_past_by_reading() {
    // A SETTINGS frame of one setting, a GOAWAY frame, of which one byte is
    // read.
    let input = [0x04, 0x03, 0x01, 0x40, 0x40, 0x07, 0x01, 0x04];
    let mut host = ReadOnly::new(&input, 1);
    let (seen, _) = run(host.below_read_skip_unpin(ControlStreamKind, 1));
    assert_eq!(
        seen,
        [
            (h3(Http3FrameType::Settings), vec![0x01]),
            (h3(Http3FrameType::Goaway), vec![0x04]),
        ]
    );
    assert!(host.rest().is_empty());
    let mut host = ReadOnly::new(&input, 2);
    let (seen, _) = run(host.below_read_chunk_skip_unpin(ControlStreamKind, 1));
    assert_eq!(seen.len(), 2);
    assert!(host.rest().is_empty());
}

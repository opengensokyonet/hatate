#![feature(impl_trait_in_assoc_type)]
//! The frame streams that hold their access, on the two layers: inside an
//! operation, where the access is the operation's, and outside any
//! operation, where it is a `ConstructedAccess` on a receiver, held by value, by
//! `&mut` or pinned, and the stream is kept across any number of separate
//! polls. The same script runs on both, with every step its own poll loop on
//! the receiver layer, and what it sees must agree: frame streams of the three
//! kinds, and a read of the next frame dropped in the middle. The
//! constructors of the other streams are in `receiver_layer_streams.rs`.
#[macro_use]
mod common;

use common::{Dribble, Ty, read_some, receiver_layer::Outcome, run, ty};
use core::{
    convert::Infallible,
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use frunk_core::HList;
use hatate_wire::{
    Part, Role,
    error_code::ErrorCodeOf,
    frame::set::FrameSetOn,
    stream::{
        FrameStream,
        kind::{ControlStreamKind, PushStreamKind, RequestStreamKind, StreamKind},
    },
};
use nitori_call::{ConstructedAccess, ReceiverAccess, call};
use nitori_io::{Read, Skip};

type Parts = HList![Part];

macro_rules! walk_log {
    ($io:expr, $w:ident, $kind:ty, $role:expr, $take:expr, $known:expr, $stop:expr) => {{
        let mut log: Vec<String> = Vec::new();
        match $w!(FrameStream::<Parts, $kind, _>::read($io, $role)) {
            Ok(Some(mut stream)) => {
                walk_stream!($w, stream, log, $take, $known, $stop);
                (log, Some(stream.into_io()))
            }
            Ok(None) => {
                log.push("no frames".to_string());
                (log, None)
            }
            Err(error) => {
                log.push(format!("head error {:?}", error.error_code()));
                (log, None)
            }
        }
    }};
}

#[call(sync)]
async fn walk_in_call<K: StreamKind, F, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    _kind: K,
    role: Role,
    take: usize,
    known: bool,
    stop: usize,
) -> Outcome
where
    F: Skip<Count = usize, Metadata = ()> + Read<Error = Infallible, Metadata = ()>,
    Parts: FrameSetOn<K>,
{
    let (log, back) = walk_log!(&mut *io, aw, K, role, take, known, stop);
    match back {
        Some(mut back) => (log, Some(read_some(&mut back, 1000).await.unwrap())),
        None => (log, None),
    }
}

fn walk_on_receiver<K: StreamKind, F, I: ReceiverAccess<Family = F>>(
    io: I,
    _kind: K,
    role: Role,
    take: usize,
    known: bool,
    stop: usize,
) -> (Vec<String>, Option<I>)
where
    F: Skip<Count = usize, Metadata = ()> + Read<Error = Infallible, Metadata = ()>,
    Parts: FrameSetOn<K>,
{
    walk_log!(io, ru, K, role, take, known, stop)
}

fn walk<K: StreamKind + Copy>(kind: K, role: Role, input: &[u8]) -> Outcome
where
    Parts: FrameSetOn<K>,
{
    let mut first = None;
    for take in [0, 2, 100] {
        for known in [false, true] {
            for stop in [1, 2, usize::MAX] {
                let result = agree!(
                    sync_walk_in_call_unpin,
                    walk_in_call_unpin,
                    walk_on_receiver,
                    input,
                    kind,
                    role,
                    take,
                    known,
                    stop
                );
                if (take, known, stop) == (2, false, usize::MAX) {
                    first = Some(result);
                }
            }
        }
    }
    first.unwrap()
}

#[test]
fn a_request_stream_is_the_same_on_both_layers() {
    // HEADERS "abc"; an unknown type 0x33 with "d"; a reserved type 0x21;
    // DATA "hello".
    let input = [
        &[0x01, 0x03][..],
        b"abc",
        &[0x33, 0x01, b'd'],
        &[0x40, 0x21, 0x00],
        &[0x00, 0x05],
        b"hello",
    ]
    .concat();
    let (log, rest) = walk(RequestStreamKind, Role::Server, &input);
    assert_eq!(
        log,
        [
            format!("{:?} Ok({:?})", Ty::Known(1), b"ab"),
            format!("{:?} Ok({:?})", Ty::Unknown(0x33), b"d"),
            format!("{:?} Ok({:?})", Ty::Reserved(0x21), b""),
            format!("{:?} Ok({:?})", Ty::Known(0), b"he"),
            "end".to_string(),
            "again: end".to_string(),
        ]
    );
    // The stream ended at a frame boundary: nothing is left.
    assert_eq!(rest, Some(vec![]));
}

#[test]
fn a_control_stream_and_a_push_stream_are_the_same_on_both_layers() {
    // SETTINGS, a reserved frame, GOAWAY 4.
    let control = [0x04, 0x00, 0x21, 0x01, 0xaa, 0x07, 0x01, 0x04];
    let (log, rest) = walk(ControlStreamKind, Role::Client, &control);
    assert_eq!(log.last().unwrap(), "again: end");
    assert_eq!(rest, Some(vec![]));
    // HEADERS "ab", DATA "c".
    let push = [0x01, 0x02, b'a', b'b', 0x00, 0x01, b'c'];
    let (log, rest) = walk(PushStreamKind, Role::Client, &push);
    assert_eq!(log.last().unwrap(), "again: end");
    assert_eq!(rest, Some(vec![]));
}

#[test]
fn a_stream_that_is_not_read_to_its_end_gives_back_the_access_where_it_is() {
    // One payload byte of HEADERS "abcd" read, then the access is given
    // back: the rest of the payload and the next frame are still there.
    let input = [0x01, 0x04, b'a', b'b', b'c', b'd', 0x00, 0x00];
    let (log, rest) = agree!(
        sync_walk_in_call_unpin,
        walk_in_call_unpin,
        walk_on_receiver,
        &input,
        RequestStreamKind,
        Role::Server,
        1,
        false,
        1
    );
    assert_eq!(log, [format!("{:?} Ok({:?})", Ty::Known(1), b"a")]);
    assert_eq!(rest, Some(vec![b'b', b'c', b'd', 0x00, 0x00]));
}

#[test]
fn failures_are_the_same_on_both_layers() {
    for input in [
        // The payload cut while it is skipped.
        &[0x01, 0x03, b'a'][..],
        // The head of the next frame cut.
        &[0x01, 0x00, 0x40],
        // A type of HTTP/2.
        &[0x01, 0x00, 0x06],
        // SETTINGS, which a request stream does not have.
        &[0x01, 0x00, 0x04, 0x00],
        // The head of the first frame cut, and no frame.
        &[0x40],
        &[],
    ] {
        let (log, _) = walk(RequestStreamKind, Role::Server, input);
        assert!(!log.is_empty(), "{input:?}");
    }
    let (log, _) = walk(RequestStreamKind, Role::Server, &[0x01, 0x00, 0x06]);
    assert!(
        log.iter()
            .any(|line| line.contains("H3_FRAME_UNEXPECTED") || line.contains("Some(")),
        "{log:?}"
    );
}

// A read of the next frame dropped in the middle.

/// DATA with a payload of six bytes, then HEADERS with a Type of two bytes
/// and a payload of one, then a byte that no frame owns.
const FRAMES: [u8; 13] = [0x00, 0x06, 1, 2, 3, 4, 5, 6, 0x40, 0x01, 0x01, 0xaa, 0xbb];

fn poll_then_drop_frame<T, E>(
    future: impl Future<Output = Result<Option<T>, E>>,
    polls: usize,
) -> bool {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..polls {
        if let Poll::Ready(result) = future.as_mut().poll(&mut cx) {
            return matches!(result, Ok(Some(_)));
        }
    }
    false
}

macro_rules! dropped_log {
    ($io:expr, $w:ident, $drops:expr) => {{
        let mut log: Vec<String> = Vec::new();
        let mut stream = $w!(FrameStream::<Parts, RequestStreamKind, _>::read(
            $io,
            Role::Server
        ))
        .unwrap()
        .unwrap();
        let mut completed = false;
        for polls in $drops {
            if poll_then_drop_frame(stream.next_frame(), polls) {
                completed = true;
                break;
            }
        }
        let left = stream.frame().into_payload().remaining();
        log.push(format!("completed {completed}, payload left {left}"));
        let step = if completed {
            format!("reached {:?}", ty(stream.frame().frame_type()))
        } else {
            match $w!(stream.next_frame()) {
                Ok(Some(frame)) => format!("frame {:?}", ty(frame.frame_type())),
                Ok(None) => "end".to_string(),
                Err(error) => format!("error {:?} {error:?}", error.error_code()),
            }
        };
        log.push(step);
        (log, Some(stream.into_io()))
    }};
}

#[call(sync)]
async fn dropped_in_call<F, A: ReceiverAccess<Family = F>>(io: &mut A, drops: Vec<usize>) -> Outcome
where
    F: Skip<Count = usize, Metadata = ()> + Read<Error = Infallible, Metadata = ()>,
{
    let (log, back) = dropped_log!(&mut *io, aw, drops);
    let mut back = back.unwrap();
    (log, Some(read_some(&mut back, 1000).await.unwrap()))
}

fn dropped_on_receiver<F, I: ReceiverAccess<Family = F>>(
    io: I,
    drops: Vec<usize>,
) -> (Vec<String>, Option<I>)
where
    F: Skip<Count = usize, Metadata = ()> + Read<Error = Infallible, Metadata = ()>,
{
    dropped_log!(io, ru, drops)
}

#[test]
fn next_frame_dropped_in_the_middle_behaves_as_in_a_call() {
    let mut interrupted = 0;
    let mut resumed = 0;
    for first in 0..14 {
        for drops in [vec![first], vec![first, 3]] {
            // Only hosts that suspend, since a drop is a number of polls.
            let mut host = Dribble::new(&FRAMES, 1);
            let expected = run(host.dropped_in_call_unpin(drops.clone())).0;
            let (log, io) = dropped_on_receiver(
                ConstructedAccess::new(Dribble::new(&FRAMES, 1)),
                drops.clone(),
            );
            let rest = io.map(|io| io.into_inner().rest().to_vec());
            assert_eq!((log, rest), expected, "{drops:?}");
            let mut borrowed = Dribble::new(&FRAMES, 1);
            let (log, _) =
                dropped_on_receiver(ConstructedAccess::new(&mut borrowed), drops.clone());

            assert_eq!(log, expected.0, "{drops:?}");
            assert_eq!(Some(borrowed.rest().to_vec()), expected.1, "{drops:?}");
            let log = expected.0;
            if log[1].contains("Interrupted") {
                interrupted += 1;
            } else if log[1].starts_with("frame") || log[1].starts_with("reached") {
                resumed += 1;
            }
        }
    }
    // Both outcomes occur: dropped before the first byte of a head (or while
    // skipping), where the next call goes on, and after it, where the
    // stream is interrupted.
    assert!(interrupted > 0 && resumed > 0, "{interrupted} {resumed}");
}

#![feature(impl_trait_in_assoc_type)]
//! Dropping a read in the middle: what the stream and the payload keep.
//!
//! A read future that is dropped while the host is pending keeps nothing of
//! what it had read: the bytes the host handed over are consumed from the
//! stream, and the integer or setting they began is lost. `FramePayload`
//! counts the bytes the host handed over, so its remaining length stays
//! equal to the unread bytes of the payload; what a new read makes of the
//! rest is the subject of the tests below.
//!
//! A `FrameStream` is kept inside a call, so each test drops a future in the
//! call, after a number of polls, and goes on in the same call. Every host
//! gives one byte at a time, after a suspension before each.
mod common;

use common::{Dribble, Ty, known, read_some, run, ty};
use core::{
    convert::Infallible,
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use frunk_core::HList;
use hatate_wire::{
    Role,
    error_code::{ErrorCode, ErrorCodeOf as _},
    frame::{FrameWidths, Http3FrameType, control::codec::*},
    settings::{
        Setting,
        codec::ReadSettingExt as _,
        set::{Settings, SettingsOf},
    },
    stream::{
        FrameStream, NextFrameError,
        kind::{ControlStreamKind, RequestStreamKind},
    },
};
use nitori_call::{ReceiverAccess, call};
use nitori_io::{ExactLen, Read, Skip, prelude::*};
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};

type Parts = HList![hatate_wire::Part];

/// Polls `future` `polls` times and drops it; `true` if it completed.
fn poll_then_drop<T>(future: impl Future<Output = T>, polls: usize) -> bool {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    (0..polls).any(|_| matches!(future.as_mut().poll(&mut cx), Poll::Ready(_)))
}

/// Polls `future` `polls` times and drops it; `true` if it completed by
/// reaching a frame.
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

/// The unread bytes of the payload of the current frame.
fn remaining<K: hatate_wire::stream::kind::StreamKind, I: ReceiverAccess<Family: Read>>(
    stream: &mut FrameStream<Parts, K, I>,
) -> u64
where
    Parts: hatate_wire::frame::set::FrameSetOn<K>,
{
    stream.frame().into_payload().into_parts().1.remaining()
}

/// What the GOAWAY read again made of the integer.
#[derive(Debug, PartialEq, Eq)]
enum Again {
    Id(u64),
    Trailing(Option<ErrorCode>),
    Other,
}

/// Reads the first frame of a control stream, a GOAWAY, and drops a read of
/// its integer after `polls` polls: if `again`, reads it again.
#[call(sync)]
async fn goaway_dropped<F: Read<Error = Infallible>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    polls: usize,
    again: bool,
) -> (bool, u64, Option<(Again, u64)>) {
    let mut stream = FrameStream::<Parts, ControlStreamKind, _>::read(&mut *io, Role::Client)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(remaining(&mut stream), 8);
    let done = poll_then_drop(
        stream
            .frame()
            .payload()
            .read_goaway_frame(FrameWidths::SHORTEST),
        polls,
    );
    let left = remaining(&mut stream);
    if !again {
        return (done, left, None);
    }
    let result = stream
        .frame()
        .payload()
        .read_goaway_frame(FrameWidths::SHORTEST)
        .await;
    let again = match result {
        Ok(frame) => Again::Id(frame.id().get().get().get()),
        Err(error @ ReadIntegerFrameError::Trailing { .. }) => Again::Trailing(error.error_code()),
        Err(_) => Again::Other,
    };
    (done, left, Some((again, remaining(&mut stream))))
}

fn field(value: u64, width: VarIntWidth) -> Vec<u8> {
    let (bytes, len) = VarIntField::new(VarInt::new(value).unwrap(), width)
        .unwrap()
        .to_encoding();
    bytes[..len].to_vec()
}

#[test]
fn a_goaway_dropped_in_the_middle_keeps_the_count_exact() {
    // GOAWAY whose integer takes eight bytes, then a MAX_PUSH_ID.
    let mut wire = [0x07, 0x08].to_vec();
    wire.extend(field(0x0102_0304, VarIntWidth::Eight));
    wire.extend([0x0d, 0x01, 0x09]);
    let payload_start = 2;
    for polls in 0..20 {
        let mut host = Dribble::new(&wire, 1);
        let (done, left, _) = run(host.goaway_dropped_unpin(polls, false)).0;
        let consumed = wire.len() - host.rest().len() - payload_start;
        // The payload counts every byte the host handed over.
        assert_eq!(left, 8 - consumed as u64, "polls {polls}");
        if done {
            // Read to its end before the drop: the payload is finished.
            assert_eq!(left, 0);
            continue;
        }
        // Continue with a new read, as a caller that treats the drop as
        // "not started" would.
        let mut host = Dribble::new(&wire, 1);
        let (_, _, again) = run(host.goaway_dropped_unpin(polls, true)).0;
        let (again, left) = again.unwrap();
        // Observed: nothing consumed means nothing lost, and the new read
        // gets the integer. Some of the integer's bytes consumed means the
        // new read starts in the middle of it: it reads a first byte as the
        // integer, and the bytes after it are a frame error (Trailing) --
        // except when only the last byte is left, which reads as a small
        // integer without any error.
        match (consumed, again) {
            (0, Again::Id(id)) => assert_eq!(id, 0x0102_0304),
            (1..=6, Again::Trailing(code)) => {
                assert_eq!(code, Some(ErrorCode::H3_FRAME_ERROR));
                assert_eq!(left, 7 - consumed as u64);
            }
            (7, Again::Id(id)) => {
                // The last byte of the integer, 0x04, read as an integer.
                assert_eq!(id, 0x04);
                assert_eq!(left, 0);
            }
            (consumed, again) => panic!("{consumed} bytes consumed: {again:?}"),
        }
    }
}

/// Reads one setting from the payload of the current frame.
async fn one_setting<S: ReceiverAccess<Family = F>, F: Read + ExactLen>(
    source: &mut S,
    settings: &mut Settings<<Parts as SettingsOf>::Settings>,
) -> String
where
    <F as ExactLen>::Length: TryInto<u64>,
    <F as Read>::Error: core::fmt::Debug,
{
    match source.read_setting(settings).await {
        Ok(Some(Setting::Known(setting))) => format!("known {setting:?}"),
        Ok(Some(Setting::Unknown(setting))) => format!(
            "unknown {:#x}={:#x}",
            setting.identifier().get().get(),
            setting.value().get().get()
        ),
        Ok(None) => "end".to_string(),
        Err(error) => format!("error {error:?}"),
    }
}

/// Reads the first frame of a control stream, a SETTINGS frame, and drops a
/// read of one setting after `polls` polls; if `again`, reads settings to
/// the end of the payload.
#[call(sync)]
async fn setting_dropped<F: Read<Error = Infallible>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    polls: usize,
    again: bool,
) -> (bool, u64, Vec<String>, u64) {
    let mut stream = FrameStream::<Parts, ControlStreamKind, _>::read(&mut *io, Role::Client)
        .await
        .unwrap()
        .unwrap();
    let mut settings = Settings::<<Parts as SettingsOf>::Settings>::new();
    let done = poll_then_drop(one_setting(stream.frame().payload(), &mut settings), polls);
    let left = remaining(&mut stream);
    let mut results = Vec::new();
    if again {
        // Continue with new reads to the end of the payload: they never
        // panic and never pass its end.
        for _ in 0..6 {
            let text = one_setting(stream.frame().payload(), &mut settings).await;
            let end = text == "end" || text.starts_with("error");
            results.push(text);
            if end {
                break;
            }
        }
    }
    let end = remaining(&mut stream);
    (done, left, results, end)
}

#[test]
fn a_settings_frame_dropped_in_the_middle_keeps_the_count_exact() {
    // Three settings: 0x21=1, 0x0a (two-byte identifier) = 0x0102, 0x22=3.
    let settings = [0x21, 0x01, 0x40, 0x0a, 0x41, 0x02, 0x22, 0x03];
    let wire = [
        &[0x04, settings.len() as u8][..],
        &settings,
        &[0x0d, 0x01, 0x09],
    ]
    .concat();
    for polls in 0..24 {
        let mut host = Dribble::new(&wire, 1);
        let (done, left, _, _) = run(host.setting_dropped_unpin(polls, false)).0;
        let consumed = wire.len() - host.rest().len() - 2;
        assert_eq!(
            left,
            settings.len() as u64 - consumed as u64,
            "polls {polls}"
        );

        let mut host = Dribble::new(&wire, 1);
        let (_, _, results, end) = run(host.setting_dropped_unpin(polls, true)).0;
        if consumed == 0 {
            // Nothing consumed, nothing lost: the whole frame reads.
            assert_eq!(
                results,
                [
                    "unknown 0x21=0x1",
                    "unknown 0xa=0x102",
                    "unknown 0x22=0x3",
                    "end"
                ]
            );
        } else if !done {
            // Observed: bytes consumed by the dropped read are lost, and the
            // new read starts in the middle of a setting, so what it reads is
            // a misparse (here, after 0x21 is lost, 0x01 reads as
            // QPACK_MAX_TABLE_CAPACITY with the value 0x400a).
            assert_ne!(
                results,
                ["unknown 0xa=0x102", "unknown 0x22=0x3", "end"],
                "polls {polls}"
            );
        }
        assert_eq!(end, 0, "{results:?}");
    }
}

/// DATA with a payload of six bytes, then HEADERS with a Type of two bytes
/// and a payload of one, then a byte that no frame owns.
const FRAMES: [u8; 13] = [0x00, 0x06, 1, 2, 3, 4, 5, 6, 0x40, 0x01, 0x01, 0xaa, 0xbb];
/// The bytes up to the end of the first frame, and up to the end of the
/// head of the second.
const FIRST_END: usize = 8;
const SECOND_HEAD_END: usize = 11;
/// The bytes up to the end of the head of the first.
const FIRST_HEAD_END: usize = 2;

/// What `next_frame` made of the stream after the drops.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    Frame(Ty, u64),
    End,
    Interrupted,
    Failed(Option<ErrorCode>),
}

/// The result of dropping `next_frame` after each number of polls in
/// `drops` (stopping if one completes), and with `resume`, of calling it
/// once more, and of the bytes the access has left.
#[derive(Debug, PartialEq, Eq)]
struct Dropped {
    /// A dropped call completed.
    completed: bool,
    /// The unread bytes of the payload of the current frame after the drops.
    remaining: u64,
    /// The call after the drops.
    step: Option<Step>,
    /// What the access gives back, after the call.
    rest: Vec<u8>,
}

#[call(sync)]
async fn drop_next<
    F: Skip<Count = usize> + Read<Error = Infallible>,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
    drops: Vec<usize>,
    resume: bool,
) -> Dropped {
    let mut stream = FrameStream::<Parts, RequestStreamKind, _>::read(&mut *io, Role::Server)
        .await
        .unwrap()
        .unwrap();
    let mut completed = false;
    for polls in drops {
        if poll_then_drop_frame(stream.next_frame(), polls) {
            completed = true;
            break;
        }
    }
    let left = remaining(&mut stream);
    if !resume {
        return Dropped {
            completed,
            remaining: left,
            step: None,
            rest: Vec::new(),
        };
    }
    let step = if completed {
        Step::Frame(ty(stream.frame().frame_type()), left)
    } else {
        match stream.next_frame().await {
            Ok(Some(frame)) => Step::Frame(
                ty(frame.frame_type()),
                frame.into_payload().into_parts().1.remaining(),
            ),
            Ok(None) => Step::End,
            Err(NextFrameError::Interrupted) => Step::Interrupted,
            Err(error) => Step::Failed(error.error_code()),
        }
    };
    let mut io = stream.into_io();
    let rest = read_some(&mut io, 100).await.unwrap();
    Dropped {
        completed,
        remaining: left,
        step: Some(step),
        rest,
    }
}

fn consumed(host: &Dribble<'_>) -> usize {
    FRAMES.len() - host.rest().len()
}

#[test]
fn next_frame_dropped_in_the_middle_never_passes_what_it_reached() {
    let mut consumed_before = 0;
    for polls in 0..60 {
        let mut host = Dribble::new(&FRAMES, 1);
        let (dropped, _) = run(host.drop_next_unpin(vec![polls], false));
        let consumed = consumed(&host);
        // The first head was read when the stream was made.
        assert!(
            (FIRST_HEAD_END..=SECOND_HEAD_END).contains(&consumed),
            "polls {polls}: {consumed}"
        );
        assert!(
            consumed - FIRST_HEAD_END <= polls,
            "polls {polls}: {consumed}"
        );
        assert!(consumed >= consumed_before, "polls {polls}");
        consumed_before = consumed;
        // The call is done exactly when the head of the second frame is
        // read.
        assert_eq!(
            dropped.completed,
            consumed == SECOND_HEAD_END,
            "polls {polls}"
        );
        // The payload counts every byte skipped; once the call completed,
        // the current frame is the second, whose payload is one byte.
        let expected = if dropped.completed {
            1
        } else {
            FIRST_END.saturating_sub(consumed) as u64
        };
        assert_eq!(dropped.remaining, expected, "polls {polls}");
    }
    assert_eq!(consumed_before, SECOND_HEAD_END);
}

#[test]
fn next_frame_dropped_while_skipping_resumes_and_while_reading_a_head_is_interrupted() {
    for polls in 0..60 {
        let mut host = Dribble::new(&FRAMES, 1);
        let (dropped, _) = run(host.drop_next_unpin(vec![polls], false));
        let consumed = consumed(&host);

        let mut host = Dribble::new(&FRAMES, 1);
        let (resumed, _) = run(host.drop_next_unpin(vec![polls], true));
        let step = resumed.step.as_ref().unwrap();
        if dropped.completed {
            // The second frame was reached before the drop.
            assert_eq!(*step, Step::Frame(known(Http3FrameType::Headers), 1));
            assert_eq!(resumed.rest, [0xaa, 0xbb]);
        } else if consumed < FIRST_END {
            // The drop was in the middle of skipping the first payload: the
            // next call skips what is left, and reads the second frame.
            assert_eq!(
                *step,
                Step::Frame(known(Http3FrameType::Headers), 1),
                "polls {polls}"
            );
            assert_eq!(resumed.rest, [0xaa, 0xbb]);
        } else {
            // The drop was in the head of the second frame, even before its
            // first byte: the stream is abandoned, and the access is where
            // the dropped call left it.
            assert_eq!(
                *step,
                Step::Interrupted,
                "polls {polls}, consumed {consumed}"
            );
            assert_eq!(resumed.rest, &FRAMES[consumed..], "polls {polls}");
        }
    }
}

#[test]
fn next_frame_dropped_twice_in_the_middle_of_skipping_still_resumes() {
    for first in 0..14 {
        for second in 0..14 {
            let drops = vec![first, second];
            let mut host = Dribble::new(&FRAMES, 1);
            let (dropped, _) = run(host.drop_next_unpin(drops.clone(), false));
            let consumed = consumed(&host);
            let mut host = Dribble::new(&FRAMES, 1);
            let (resumed, _) = run(host.drop_next_unpin(drops, true));
            let step = resumed.step.unwrap();
            let expected = if dropped.completed {
                1
            } else {
                FIRST_END.saturating_sub(consumed) as u64
            };
            assert_eq!(dropped.remaining, expected, "{first} {second}");
            if dropped.completed || consumed < FIRST_END {
                assert_eq!(
                    step,
                    Step::Frame(known(Http3FrameType::Headers), 1),
                    "{first} {second}"
                );
            } else {
                assert_eq!(step, Step::Interrupted, "{first} {second}");
                assert_eq!(resumed.rest, &FRAMES[consumed..]);
            }
        }
    }
}

/// Skips the rest of the payload of the first frame, dropping the skip
/// after `polls` polls, and again if `again`.
#[call(sync)]
async fn skip_dropped<
    F: Skip<Count = usize> + Read<Error = Infallible>,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
    polls: usize,
    again: bool,
) -> (bool, u64, u64) {
    let mut stream = FrameStream::<Parts, RequestStreamKind, _>::read(&mut *io, Role::Server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(remaining(&mut stream), 6);
    let done = poll_then_drop(stream.frame().payload().skip_to_end(), polls);
    let left = remaining(&mut stream);
    if again {
        stream.frame().payload().skip_to_end().await.unwrap();
    }
    (done, left, remaining(&mut stream))
}

#[test]
fn a_payload_skipped_in_part_and_dropped_keeps_the_count_exact() {
    for polls in 0..20 {
        let mut host = Dribble::new(&FRAMES, 1);
        let ((done, left, _), _) = run(host.skip_dropped_unpin(polls, false));
        let consumed = consumed(&host);
        // The payload counts every byte skipped, so skipping again takes
        // exactly what is left and stops at the end of the frame.
        assert_eq!(left, (FIRST_END - consumed) as u64, "polls {polls}");
        assert_eq!(done, left == 0, "polls {polls}");
        let mut host = Dribble::new(&FRAMES, 1);
        let ((_, _, end), _) = run(host.skip_dropped_unpin(polls, true));
        assert_eq!(end, 0);
        assert_eq!(host.rest(), &FRAMES[FIRST_END..], "polls {polls}");
    }
}

/// Makes the stream of a first frame, dropping the read after `polls`
/// polls.
#[call(sync)]
async fn first_frame_dropped<
    F: Skip<Count = usize> + Read<Error = Infallible>,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
    polls: usize,
) -> bool {
    poll_then_drop(
        FrameStream::<Parts, RequestStreamKind, _>::read(&mut *io, Role::Server),
        polls,
    )
}

#[test]
fn the_first_frame_dropped_while_read_consumes_only_what_it_reached() {
    // A Type of two bytes and a Length of four.
    let wire = [0x40, 0x00, 0x80, 0x00, 0x00, 0x03, b'a', b'b', b'c'];
    let head = 6;
    for polls in 0..20 {
        let mut host = Dribble::new(&wire, 1);
        let (done, _) = run(host.first_frame_dropped_unpin(polls));
        let consumed = wire.len() - host.rest().len();
        assert!(
            consumed <= polls && consumed <= head,
            "polls {polls}: {consumed}"
        );
        assert_eq!(done, consumed == head, "polls {polls}");
    }
}

/// A frame head that was rejected, and then another call.
#[call(sync)]
async fn after_a_rejected_head<
    F: Skip<Count = usize> + Read<Error = Infallible>,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
) -> (Option<ErrorCode>, Option<ErrorCode>, bool, Vec<u8>) {
    let mut stream = FrameStream::<Parts, RequestStreamKind, _>::read(&mut *io, Role::Server)
        .await
        .unwrap()
        .unwrap();
    // The first frame is DATA; the next head is PING of HTTP/2.
    let first = match stream.next_frame().await {
        Err(error @ NextFrameError::Head { .. }) => error.error_code(),
        other => panic!("{:?}", other.map(|frame| frame.is_some())),
    };
    // The stream is inside the head: it is abandoned, without a code of its
    // own, and stays so.
    let second = match stream.next_frame().await {
        Err(error @ NextFrameError::Interrupted) => error.error_code(),
        other => panic!("{:?}", other.map(|frame| frame.is_some())),
    };
    let interrupted_again = matches!(
        stream.next_known_frame().await,
        Err(NextFrameError::Interrupted)
    );
    let mut io = stream.into_io();
    let rest = read_some(&mut io, 100).await.unwrap();
    (first, second, interrupted_again, rest)
}

#[test]
fn a_head_that_was_rejected_leaves_the_stream_interrupted() {
    // DATA, then PING with a Length that is not read.
    let wire = [0x00, 0x00, 0x06, 0x01, 0xaa];
    let mut host = Dribble::new(&wire, 1);
    let ((first, second, again, rest), _) = run(host.after_a_rejected_head_unpin());
    assert_eq!(first, Some(ErrorCode::H3_FRAME_UNEXPECTED));
    assert_eq!(second, None);
    assert!(again);
    assert_eq!(rest, [0x01, 0xaa]);
}

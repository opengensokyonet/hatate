#![feature(impl_trait_in_assoc_type)]
//! Dropping a read in the middle: what the stream and the payload keep.
//!
//! A read future that is dropped while the host is pending keeps nothing of
//! what it had read: the bytes the host handed over are consumed from the
//! stream, and the integer or setting they began is lost. `FramePayload`
//! counts the bytes the host handed over, so its remaining length stays
//! equal to the unread bytes of the payload; what a new read makes of the
//! rest is the subject of the tests below.
mod common;

use common::Dribble;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use frunk_core::HList;
use hatate_wire::stream::FrameStream;
use hatate_wire::{
    Role,
    error_code::{ErrorCode, ErrorCodeOf as _},
    frame::{
        FrameWidths,
        codec::{read_frame, read_received_frame},
        control::{GoawayFrame, codec::*},
        payload::{FramePayload, PayloadError},
    },
    settings::{
        Setting,
        codec::ReadSettingExt as _,
        set::{Settings, SettingsOf},
    },
};
use nitori_call::{ReceiverAccess, call};
use nitori_io::{Read, Skip, prelude::*};
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};

type Parts = HList![hatate_wire::Part];

/// Polls `future` `polls` times and drops it; `true` if it completed.
fn poll_then_drop<T>(future: impl Future<Output = T>, polls: usize) -> bool {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    (0..polls).any(|_| matches!(future.as_mut().poll(&mut cx), Poll::Ready(_)))
}

/// Reads the head of a frame and returns its payload.
#[call(sync)]
async fn payload_of<F: Read, A: ReceiverAccess<Family = F>>(io: &mut A) -> FramePayload
where
    <F as Read>::Error: core::fmt::Debug,
{
    read_frame(&mut *io)
        .await
        .unwrap()
        .unwrap()
        .into_payload()
        .into_parts()
        .1
}

/// Reads the GOAWAY integer from the payload.
#[call(sync)]
async fn goaway_of<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    payload: &mut FramePayload,
) -> Result<GoawayFrame, ReadIntegerFrameError<PayloadError<F::Error>>>
where
    <F as Read>::Error: core::fmt::Debug,
{
    let mut source = io.compose(payload);
    source.read_goaway_frame(FrameWidths::SHORTEST).await
}

/// Reads one setting from the payload.
#[call(sync)]
async fn one_setting<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    payload: &mut FramePayload,
) -> String
where
    <F as Read>::Error: core::fmt::Debug,
{
    let mut source = io.compose(payload);
    let mut settings = Settings::<<Parts as SettingsOf>::Settings>::new();
    match source.read_setting(&mut settings).await {
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
        let mut payload = {
            let mut future = pin!(host.payload_of_unpin());
            let mut cx = Context::from_waker(Waker::noop());
            loop {
                if let Poll::Ready(payload) = future.as_mut().poll(&mut cx) {
                    break payload;
                }
            }
        };
        assert_eq!(payload.remaining(), 8);
        let done = poll_then_drop(host.goaway_of_unpin(&mut payload), polls);
        let consumed = wire.len() - host.rest().len() - payload_start;
        // The payload counts every byte the host handed over.
        assert_eq!(payload.remaining(), 8 - consumed as u64, "polls {polls}");
        if done {
            // Read to its end before the drop: the payload is finished.
            assert_eq!(payload.remaining(), 0);
            continue;
        }
        // Continue with a new read, as a caller that treats the drop as
        // "not started" would.
        let again = common::run(host.goaway_of_unpin(&mut payload)).0;
        // Observed: nothing consumed means nothing lost, and the new read
        // gets the integer. Some of the integer's bytes consumed means the
        // new read starts in the middle of it: it reads a first byte as the
        // integer, and the bytes after it are a frame error (Trailing) --
        // except when only the last byte is left, which reads as a small
        // integer without any error.
        match (consumed, again) {
            (0, Ok(frame)) => assert_eq!(frame.id().get().get().get(), 0x0102_0304),
            (1..=6, Err(error)) => {
                assert!(
                    matches!(error, ReadIntegerFrameError::Trailing { .. }),
                    "{error:?}"
                );
                assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
                assert_eq!(payload.remaining(), 7 - consumed as u64);
            }
            (7, Ok(frame)) => {
                // The last byte of the integer, 0x04, read as an integer.
                assert_eq!(frame.id().get().get().get(), 0x04);
                assert_eq!(payload.remaining(), 0);
            }
            (consumed, again) => panic!("{consumed} bytes consumed: {again:?}"),
        }
    }
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
        let mut payload = {
            let mut future = pin!(host.payload_of_unpin());
            let mut cx = Context::from_waker(Waker::noop());
            loop {
                if let Poll::Ready(payload) = future.as_mut().poll(&mut cx) {
                    break payload;
                }
            }
        };
        let done = poll_then_drop(host.one_setting_unpin(&mut payload), polls);
        let consumed = wire.len() - host.rest().len() - 2;
        assert_eq!(
            payload.remaining(),
            settings.len() as u64 - consumed as u64,
            "polls {polls}"
        );
        // Continue with new reads to the end of the payload: they never
        // panic and never pass its end.
        let mut results = Vec::new();
        for _ in 0..6 {
            let (text, _) = common::run(host.one_setting_unpin(&mut payload));
            let end = text == "end" || text.starts_with("error");
            results.push(text);
            if end {
                break;
            }
        }
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
        assert_eq!(payload.remaining(), 0, "{results:?}");
    }
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

/// DATA with a payload of six bytes, then HEADERS with two, then a byte
/// that no frame owns.
const FRAMES: [u8; 13] = [0x00, 0x06, 1, 2, 3, 4, 5, 6, 0x01, 0x02, 0xaa, 0xbb, 0xcc];
/// The bytes up to the end of the first frame, and up to the end of the
/// head of the second.
const FIRST_END: usize = 8;
const SECOND_HEAD_END: usize = 10;

/// Reads the head of the first frame and finishes it.
#[call(sync)]
async fn finish_first<
    F: Skip<Count = usize> + Read<Error = core::convert::Infallible>,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
) {
    let frame = read_frame(&mut *io).await.unwrap().unwrap();
    let _ = frame.finish().await.unwrap();
}

/// Reads the head of the first frame, finishes it, and reads the next.
#[call(sync)]
async fn next_first<
    F: Skip<Count = usize> + Read<Error = core::convert::Infallible>,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
) -> u64 {
    let frame = read_frame(&mut *io).await.unwrap().unwrap();
    let next = frame.next().await.unwrap().unwrap();
    next.r#type().get().get()
}

/// [`finish_first`] for a frame of a stream that carries frames.
#[call(sync)]
async fn finish_first_received<
    F: Skip<Count = usize> + Read<Error = core::convert::Infallible>,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
) {
    let mut stream = io.compose(FrameStream::<Parts>::request(Role::Server));
    let frame = read_received_frame(&mut stream).await.unwrap().unwrap();
    let _ = frame.finish().await.unwrap();
}

/// [`next_first`] for a frame of a stream that carries frames.
#[call(sync)]
async fn next_first_received<
    F: Skip<Count = usize> + Read<Error = core::convert::Infallible>,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
) -> u64 {
    let mut stream = io.compose(FrameStream::<Parts>::request(Role::Server));
    let frame = read_received_frame(&mut stream).await.unwrap().unwrap();
    let next = frame.next().await.unwrap().unwrap();
    next.frame().r#type().get().get()
}

/// Drops `finish` and `next` after every number of polls: the stream is
/// never read past what the call had reached, which is inside the first
/// frame while finishing, and inside the head of the second while reading
/// it; and a call that completes leaves the stream at the next frame, or
/// after its head.
macro_rules! drop_in_the_middle {
    ($name:ident, $finish:ident, $next:ident) => {
        #[test]
        fn $name() {
            let mut consumed_before = 0;
            for polls in 0..40 {
                let mut host = Dribble::new(&FRAMES, 1);
                let done = poll_then_drop(host.$finish(), polls);
                let consumed = FRAMES.len() - host.rest().len();
                assert!(consumed <= FIRST_END, "polls {polls}: {consumed}");
                assert!(consumed <= polls, "polls {polls}: {consumed}");
                assert!(consumed >= consumed_before, "polls {polls}");
                consumed_before = consumed;
                // The last skip completes the call: it is done exactly
                // when the first frame is, and then the stream is at the
                // second.
                assert_eq!(done, consumed == FIRST_END, "polls {polls}");
                if done {
                    assert_eq!(host.rest(), &FRAMES[FIRST_END..]);
                }
            }
            assert_eq!(consumed_before, FIRST_END);

            let mut consumed_before = 0;
            for polls in 0..40 {
                let mut host = Dribble::new(&FRAMES, 1);
                let done = poll_then_drop(host.$next(), polls);
                let consumed = FRAMES.len() - host.rest().len();
                assert!(consumed <= SECOND_HEAD_END, "polls {polls}: {consumed}");
                assert!(consumed >= consumed_before, "polls {polls}");
                consumed_before = consumed;
                assert_eq!(done, consumed == SECOND_HEAD_END, "polls {polls}");
                if done {
                    // The head of the second frame is read, and its
                    // payload is next on the stream.
                    assert_eq!(host.rest(), &FRAMES[SECOND_HEAD_END..]);
                }
            }
            assert_eq!(consumed_before, SECOND_HEAD_END);
        }
    };
}

drop_in_the_middle!(
    a_frame_finished_or_moved_past_and_dropped_never_passes_what_it_reached,
    finish_first_unpin,
    next_first_unpin
);
drop_in_the_middle!(
    a_received_frame_finished_or_moved_past_and_dropped_never_passes_what_it_reached,
    finish_first_received_unpin,
    next_first_received_unpin
);

#[test]
fn a_payload_skipped_in_part_and_dropped_keeps_the_count_exact() {
    for polls in 0..20 {
        let mut host = Dribble::new(&FRAMES, 1);
        let mut payload = {
            let mut future = pin!(host.payload_of_unpin());
            let mut cx = Context::from_waker(Waker::noop());
            loop {
                if let Poll::Ready(payload) = future.as_mut().poll(&mut cx) {
                    break payload;
                }
            }
        };
        assert_eq!(payload.remaining(), 6);
        let done = poll_then_drop(host.skip_payload_unpin(&mut payload), polls);
        let consumed = FRAMES.len() - host.rest().len() - 2;
        // The payload counts every byte skipped, so skipping again takes
        // exactly what is left and stops at the end of the frame.
        assert_eq!(payload.remaining(), 6 - consumed as u64, "polls {polls}");
        assert_eq!(done, payload.remaining() == 0, "polls {polls}");
        common::run(host.skip_payload_unpin(&mut payload))
            .0
            .unwrap();
        assert_eq!(payload.remaining(), 0);
        assert_eq!(host.rest(), &FRAMES[FIRST_END..], "polls {polls}");
    }
}

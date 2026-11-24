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
    marker::PhantomData,
    pin::pin,
    task::{Context, Poll, Waker},
};
use frunk_core::HList;
use hatate_wire::{
    defaults::RejectKnownDuplicates,
    error_code::ErrorCode,
    frame::{
        FrameWidths,
        codec::ReadFrameHeadExt as _,
        control::{GoawayFrame, codec::*},
        payload::{FramePayload, PayloadError},
    },
    settings::{Setting, codec::ReadSettingExt as _},
};
use nitori_call::{ReceiverAccess, call};
use nitori_io::Read;
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
    io.read_frame_head(PhantomData::<Parts>)
        .await
        .unwrap()
        .unwrap()
        .payload()
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
    let mut policy = RejectKnownDuplicates::<Parts>::new();
    match source.read_setting(&mut policy).await {
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
            payload.finish().unwrap();
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
            (0, Ok(frame)) => assert_eq!(frame.id().get().get(), 0x0102_0304),
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
                assert_eq!(frame.id().get().get(), 0x04);
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

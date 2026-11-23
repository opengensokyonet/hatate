//! Walk a stream of HTTP/3 frames with the parts of HTTP/3, HTTP Datagrams and
//! Extended CONNECT: heads, SETTINGS, the integer frames, and the rest
//! discarded. Every frame read whole is written back and must equal its bytes.
//!
//! The first byte sets how the stream arrives: its low four bits plus one are
//! the bytes given per read, and its high four bits the period of a
//! `Pending` (0 for none).
#![no_main]
#![feature(impl_trait_in_assoc_type)]
use bytes::BufMut;
use core::{
    convert::Infallible,
    future::{Future, poll_fn},
    marker::PhantomData,
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
};
use frunk_core::{HList, coproduct::Coproduct};
use hatate_wire::{
    defaults::RejectKnownDuplicates,
    frame::{
        FrameType, Http3FrameType,
        codec::ReadFrameHeadExt as _,
        control::{
            ReadCancelPushFrameExt as _, ReadGoawayFrameExt as _, ReadMaxPushIdFrameExt as _,
            WriteCancelPushFrameExt as _, WriteGoawayFrameExt as _, WriteMaxPushIdFrameExt as _,
        },
        payload::DiscardExt as _,
    },
    settings::codec::{
        ReadSettingExt as _, SettingsFrame, SettingsFrameError, WriteSettingsFrameExt as _,
    },
};
use libfuzzer_sys::fuzz_target;
use nitori_call::{ReceiverAccess, call};
use nitori_io::{ExactLen, Read, Write, prelude::*};

type Parts = HList![
    hatate_wire::Part,
    hatate_wire_datagram::Part,
    hatate_wire_extended_connect::Part
];

/// A stream that gives `chunk` bytes at most per read and is pending on every
/// `period`-th read.
struct Arrival<'a> {
    input: &'a [u8],
    chunk: usize,
    period: usize,
    reads: usize,
    woken: bool,
}

nitori_call::family_receiver!(impl ['a] for Arrival<'a>);

impl Read for Arrival<'_> {
    type Error = Infallible;
    fn poll_read<'visit, B: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        cx: &mut Context<'_>,
        dst: &mut B,
    ) -> Poll<Result<usize, Self::Error>>
    where
        Self: 'visit,
    {
        let this = host.get_pin_mut().get_mut();
        if this.period != 0 && !this.woken && this.reads % this.period == 0 {
            this.woken = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        this.woken = false;
        this.reads += 1;
        let count = this.chunk.min(this.input.len()).min(dst.remaining_mut());
        let (head, tail) = this.input.split_at(count);
        dst.put_slice(head);
        this.input = tail;
        Poll::Ready(Ok(count))
    }
}

impl ExactLen for Arrival<'_> {
    type Length = usize;
    fn remaining_len<'visit>(host: Pin<&mut Self::ReceiverView<'visit>>) -> usize
    where
        Self: 'visit,
    {
        host.get_pin_mut().get_mut().input.len()
    }
}

macro_rules! position {
    ($io:expr, $wire:expr) => {{
        let remaining =
            poll_fn(|cx| $io.poll_access(cx, |mut view, _| Poll::Ready(view.remaining_len())))
                .await;
        $wire.len() - remaining.try_into().unwrap_or(0)
    }};
}

/// Reads every frame of `wire` from `io`, writes each one it read whole to
/// `out`, and puts the bytes it expects there in `expected`.
#[call(sync)]
async fn walk<
    F: Read + ExactLen,
    A: ReceiverAccess<Family = F>,
    W: Write,
    B: ReceiverAccess<Family = W>,
>(
    io: &mut A,
    out: &mut B,
    wire: &[u8],
    expected: &mut Vec<u8>,
) where
    <F as ExactLen>::Length: TryInto<usize>,
{
    loop {
        let start = position!(io, wire);
        let head = match io.read_frame_head(PhantomData::<Parts>).await {
            Ok(Some(head)) => head,
            _ => return,
        };
        let widths = head.widths();
        let mut payload = head.payload();
        let length = head.length().get().get();
        let mut whole = false;
        match head.frame_type() {
            FrameType::Known(Coproduct::Inl(Http3FrameType::Settings)) => {
                let mut policy = RejectKnownDuplicates::<Parts>::new();
                let mut settings = Vec::new();
                {
                    let mut source = io.compose(&mut payload);
                    loop {
                        match source.read_setting(&mut policy).await {
                            Ok(Some(setting)) => settings.push(setting),
                            Ok(None) => break,
                            Err(_) => return,
                        }
                    }
                }
                match SettingsFrame::new::<Parts>(settings, widths) {
                    Ok(frame) => {
                        assert_eq!(frame.payload_len(), length);
                        let Ok(()) = out.write_settings_frame(&frame, PhantomData::<Parts>).await
                        else {
                            panic!("a SETTINGS frame was not written");
                        };
                        whole = true;
                    }
                    // Unknown identifiers may repeat on the wire; a frame may not.
                    Err(SettingsFrameError::Duplicate { .. }) => {}
                    Err(error) => panic!("a SETTINGS frame that was read cannot be built: {error}"),
                }
            }
            FrameType::Known(Coproduct::Inl(Http3FrameType::CancelPush)) => {
                let frame = {
                    let mut source = io.compose(&mut payload);
                    match source.read_cancel_push_frame(widths).await {
                        Ok(frame) => frame,
                        Err(_) => return,
                    }
                };
                let Ok(()) = out.write_cancel_push_frame(frame).await else {
                    panic!("a CANCEL_PUSH frame was not written");
                };
                whole = true;
            }
            FrameType::Known(Coproduct::Inl(Http3FrameType::Goaway)) => {
                let frame = {
                    let mut source = io.compose(&mut payload);
                    match source.read_goaway_frame(widths).await {
                        Ok(frame) => frame,
                        Err(_) => return,
                    }
                };
                let Ok(()) = out.write_goaway_frame(frame).await else {
                    panic!("a GOAWAY frame was not written");
                };
                whole = true;
            }
            FrameType::Known(Coproduct::Inl(Http3FrameType::MaxPushId)) => {
                let frame = {
                    let mut source = io.compose(&mut payload);
                    match source.read_max_push_id_frame(widths).await {
                        Ok(frame) => frame,
                        Err(_) => return,
                    }
                };
                let Ok(()) = out.write_max_push_id_frame(frame).await else {
                    panic!("a MAX_PUSH_ID frame was not written");
                };
                whole = true;
            }
            _ => {
                let mut source = io.compose(&mut payload);
                match source.discard().await {
                    Ok(discarded) => assert_eq!(discarded, length),
                    Err(_) => return,
                }
            }
        }
        if payload.finish().is_err() {
            return;
        }
        if whole {
            let end = position!(io, wire);
            expected.extend_from_slice(&wire[start..end]);
        }
    }
}

fn complete<T>(future: impl Future<Output = T>) -> T {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&control, wire)) = data.split_first() else {
        return;
    };
    let arrival = Arrival {
        input: wire,
        chunk: usize::from(control & 0x0f) + 1,
        period: usize::from(control >> 4),
        reads: 0,
        woken: false,
    };
    let mut hosts = (arrival, Vec::<u8>::new());
    let mut expected = Vec::new();
    complete(hosts.walk_unpin(wire, &mut expected));
    assert_eq!(hosts.1, expected);
});

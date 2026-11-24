//! Walk a stream of HTTP/3 frames with the parts of HTTP/3, HTTP Datagrams and
//! Extended CONNECT: heads, SETTINGS, the integer frames, PUSH_PROMISE (its
//! Push ID, then the rest of the payload), and the payload of every other
//! frame, which is collected. Every frame read whole is written back (the
//! collected ones through `write_payload_frame` and
//! `write_push_promise_frame`) and must equal its bytes.
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
        codec::{
            ReadPushPromisePushIdExt as _, WritePayloadFrameHostExt as _,
            WritePushPromiseFrameHostExt as _,
        },
        control::codec::{
            ReadCancelPushFrameExt as _, ReadGoawayFrameExt as _, ReadMaxPushIdFrameExt as _,
            WriteCancelPushFrameExt as _, WriteGoawayFrameExt as _, WriteMaxPushIdFrameExt as _,
        },
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

/// The rest of `payload`, read from the stream `io`; `None` if reading failed.
async fn collect<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    payload: &mut hatate_wire::frame::payload::FramePayload,
) -> Option<Vec<u8>> {
    let mut source = io.compose(payload);
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0; 64];
        match source.read(&mut &mut buffer[..]).await {
            Ok(0) => return Some(bytes),
            Ok(count) => bytes.extend_from_slice(&buffer[..count]),
            Err(_) => return None,
        }
    }
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
            FrameType::Known(Coproduct::Inl(Http3FrameType::PushPromise)) => {
                let push_id = {
                    let mut source = io.compose(&mut payload);
                    match source.read_push_promise_push_id().await {
                        Ok(push_id) => push_id,
                        Err(_) => return,
                    }
                };
                let Some(section) = collect(io, &mut payload).await else {
                    return;
                };
                if payload.finish().is_err() {
                    return;
                }
                let end = position!(io, wire);
                let mut again = (Vec::<u8>::new(), &section[..]);
                let Ok(()) = again
                    .write_push_promise_frame_unpin(widths, push_id)
                    .await
                else {
                    panic!("a PUSH_PROMISE frame was not written");
                };
                assert_eq!(again.0, &wire[start..end]);
                continue;
            }
            _ => {
                // DATA, HEADERS and the frames of types no part claims.
                let Some(bytes) = collect(io, &mut payload).await else {
                    return;
                };
                assert_eq!(bytes.len() as u64, length);
                if payload.finish().is_err() {
                    return;
                }
                let end = position!(io, wire);
                let mut again = (Vec::<u8>::new(), &bytes[..]);
                match again
                    .write_payload_frame_unpin(head.type_field(), widths.length_width())
                    .await
                {
                    Ok(written) => assert_eq!(written, length),
                    Err(error) => panic!("a frame of the payload was not written: {error}"),
                }
                assert_eq!(again.0, &wire[start..end]);
                continue;
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

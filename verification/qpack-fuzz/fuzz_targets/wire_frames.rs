//! Walk a stream of HTTP/3 frames, a `FrameStream` of the parts of HTTP/3, HTTP
//! Datagrams and Extended CONNECT: heads, SETTINGS, the integer frames,
//! PUSH_PROMISE (its Push ID, then the rest of the payload), and the payload
//! of every other frame, which is collected. Every frame read whole is
//! written back (the collected ones through `write_frame` and
//! `write_push_promise_frame`) and must equal its bytes.
//!
//! The first byte sets how the stream arrives: its low four bits plus one are
//! the bytes given per read, and its high four bits the period of a
//! `Pending` (0 for none). The second sets the stream: bits 0 and 1 the kind
//! (a request stream, a control stream, a push stream, and again a request
//! stream) and bit 2 the role of the endpoint. The rest is the stream.
#![no_main]
#![feature(impl_trait_in_assoc_type)]
use bytes::BufMut;
use core::{
    convert::Infallible,
    future::Future,
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
};
use frunk_core::HList;
use hatate_wire::{
    Role,
    frame::{
        Frame, Http3FrameType,
        codec::{
            ReadPushPromisePushIdExt as _, WriteFrameExt as _, WritePushPromiseFrameHostExt as _,
        },
        control::codec::{
            ReadCancelPushFrameExt as _, ReadGoawayFrameExt as _, ReadMaxPushIdFrameExt as _,
            WriteCancelPushFrameExt as _, WriteGoawayFrameExt as _, WriteMaxPushIdFrameExt as _,
        },
    },
    settings::{
        codec::{
            ReadSettingExt as _, SettingsFrame, SettingsFrameError, WriteSettingsFrameExt as _,
        },
        set::{Settings, SettingsOf},
    },
    stream::{
        FrameStream,
        kind::{ControlStreamKind, PushStreamKind, RequestStreamKind},
    },
};
use libfuzzer_sys::fuzz_target;
use nitori_call::{ReceiverAccess, call};
use nitori_io::{ExactLen, Min, Read, Skip, Write, prelude::*};
use sakuya_var_int::{VarInt, VarIntField};

type Parts = HList![
    hatate_wire::Part,
    hatate_wire_datagram::Part,
    hatate_wire_extended_connect::Part
];

/// A stream that gives `chunk` bytes at most per read or skip and is pending
/// on every `period`-th one.
struct Arrival<'a> {
    input: &'a [u8],
    chunk: usize,
    period: usize,
    reads: usize,
    woken: bool,
}

impl Arrival<'_> {
    /// Whether this call is the pending one.
    fn pending(&mut self, cx: &mut Context<'_>) -> bool {
        if self.period != 0 && !self.woken && self.reads % self.period == 0 {
            self.woken = true;
            cx.waker().wake_by_ref();
            return true;
        }
        self.woken = false;
        self.reads += 1;
        false
    }
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
        if this.pending(cx) {
            return Poll::Pending;
        }
        let count = Ord::min(Ord::min(this.chunk, this.input.len()), dst.remaining_mut());
        let (head, tail) = this.input.split_at(count);
        dst.put_slice(head);
        this.input = tail;
        Poll::Ready(Ok(count))
    }
}

impl Skip for Arrival<'_> {
    type Count = usize;
    fn poll_skip<'visit, M: Min<usize, Output = usize> + Clone>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        cx: &mut Context<'_>,
        maximum: M,
    ) -> Poll<Result<Option<usize>, Self::Error>>
    where
        Self: 'visit,
    {
        let this = host.get_pin_mut().get_mut();
        if this.pending(cx) {
            return Poll::Pending;
        }
        let allowed = Min::min(maximum, this.chunk);
        if allowed != 0 && this.input.is_empty() {
            return Poll::Ready(Ok(None));
        }
        let count = Ord::min(allowed, this.input.len());
        this.input = &this.input[count..];
        Poll::Ready(Ok(Some(count)))
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

/// The rest of `payload`, read to its end; `None` if reading failed.
async fn collect<A: ReceiverAccess<Family: Read>>(payload: &mut A) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0; 64];
        match payload.read(&mut &mut buffer[..]).await {
            Ok(0) => return Some(bytes),
            Ok(count) => bytes.extend_from_slice(&buffer[..count]),
            Err(_) => return None,
        }
    }
}

/// Writes the frame of this Type and Length whose payload is the second
/// receiver of the host.
#[call(sync)]
async fn write_payload<R: Read + ExactLen, F: Write>(
    out: &mut impl ReceiverAccess<Family = F>,
    payload: &mut impl ReceiverAccess<Family = R>,
    r#type: VarIntField<VarInt>,
    length: VarIntField<VarInt>,
) -> Result<(), hatate_wire::frame::codec::WriteFrameError<R::Error, F::Error>>
where
    <R as ExactLen>::Length: TryInto<u64>,
{
    out.write_frame(Frame::new(r#type, length, payload)).await
}

/// Walks the frames of a stream of this kind, writes each frame read whole to
/// `out`, and puts the bytes it expects there in `expected`.
macro_rules! walk {
    ($io:expr, $kind:ty, $role:expr, $wire:expr, $out:expr, $expected:expr) => {{
        let wire: &[u8] = $wire;
        let Ok(Some(mut stream)) = FrameStream::<Parts, $kind, _>::read($io, $role).await else {
            return;
        };
        let mut start = 0usize;
        loop {
            let mut frame = stream.frame();
            let widths = frame.widths();
            let type_field = VarIntField::new(frame.frame_type().into(), frame.r#type().width())
                .expect("a field holds its value at its width");
            let length_field = frame.length();
            let length = length_field.get().get();
            let end = start
                + usize::from(type_field.encoded_len() as u8)
                + usize::from(length_field.encoded_len() as u8)
                + Ord::min(usize::try_from(length).unwrap_or(usize::MAX), wire.len());
            let mut whole = false;
            match Http3FrameType::of(type_field.get()) {
                Some(Http3FrameType::Settings) => {
                    let mut slots = Settings::<<Parts as SettingsOf>::Settings>::new();
                    let mut settings = Vec::new();
                    loop {
                        match frame.payload().read_setting(&mut slots).await {
                            Ok(Some(setting)) => settings.push(setting),
                            Ok(None) => break,
                            Err(_) => return,
                        }
                    }
                    match SettingsFrame::<<Parts as SettingsOf>::Settings>::new(settings, widths) {
                        Ok(settings_frame) => {
                            assert_eq!(settings_frame.payload_len(), length);
                            let Ok(()) = $out.write_settings_frame(&settings_frame).await else {
                                panic!("a SETTINGS frame was not written");
                            };
                            whole = true;
                        }
                        // Unknown identifiers may repeat on the wire; a frame may not.
                        Err(SettingsFrameError::Duplicate { .. }) => {}
                        Err(error) => {
                            panic!("a SETTINGS frame that was read cannot be built: {error}")
                        }
                    }
                }
                Some(Http3FrameType::CancelPush) => {
                    let Ok(read) = frame.payload().read_cancel_push_frame(widths).await else {
                        return;
                    };
                    let Ok(()) = $out.write_cancel_push_frame(read).await else {
                        panic!("a CANCEL_PUSH frame was not written");
                    };
                    whole = true;
                }
                Some(Http3FrameType::Goaway) => {
                    let Ok(read) = frame.payload().read_goaway_frame(widths).await else {
                        return;
                    };
                    let Ok(()) = $out.write_goaway_frame(read).await else {
                        panic!("a GOAWAY frame was not written");
                    };
                    whole = true;
                }
                Some(Http3FrameType::MaxPushId) => {
                    let Ok(read) = frame.payload().read_max_push_id_frame(widths).await else {
                        return;
                    };
                    let Ok(()) = $out.write_max_push_id_frame(read).await else {
                        panic!("a MAX_PUSH_ID frame was not written");
                    };
                    whole = true;
                }
                Some(Http3FrameType::PushPromise) => {
                    let Ok(push_id) = frame.payload().read_push_promise_push_id().await else {
                        return;
                    };
                    let Some(section) = collect(frame.payload()).await else {
                        return;
                    };
                    let mut again = (Vec::<u8>::new(), &section[..]);
                    let Ok(()) = again.write_push_promise_frame_unpin(widths, push_id).await else {
                        panic!("a PUSH_PROMISE frame was not written");
                    };
                    assert_eq!(again.0, &wire[start..end]);
                }
                _ => {
                    // DATA, HEADERS and the frames of types no part claims.
                    let Some(bytes) = collect(frame.payload()).await else {
                        return;
                    };
                    assert_eq!(bytes.len() as u64, length);
                    let mut again = (Vec::<u8>::new(), &bytes[..]);
                    if let Err(error) = again.write_payload_unpin(type_field, length_field).await {
                        panic!("a frame of the payload was not written: {error}");
                    }
                    assert_eq!(again.0, &wire[start..end]);
                }
            }
            if whole {
                // The frame was written from what was read: the payload was
                // read to its end, or the frame is not the bytes it was.
                if frame.into_payload().into_parts().1.remaining() == 0 {
                    $expected.extend_from_slice(&wire[start..end]);
                } else {
                    return;
                }
            }
            match stream.next_frame().await {
                Ok(Some(_)) => start = end,
                _ => return,
            }
        }
    }};
}

/// Reads every frame of `wire` from `io` as a stream of this kind, writes each
/// one it read whole to `out`, and puts the bytes it expects there in
/// `expected`.
#[call(sync)]
async fn walk<
    F: Read<Error = Infallible> + Skip<Count = usize>,
    A: ReceiverAccess<Family = F>,
    W: Write<Error = Infallible>,
    B: ReceiverAccess<Family = W>,
>(
    io: &mut A,
    out: &mut B,
    kind: u8,
    role: Role,
    wire: &[u8],
    expected: &mut Vec<u8>,
) {
    match kind & 3 {
        1 => walk!(&mut *io, ControlStreamKind, role, wire, out, expected),
        2 => walk!(&mut *io, PushStreamKind, role, wire, out, expected),
        _ => walk!(&mut *io, RequestStreamKind, role, wire, out, expected),
    }
}

fuzz_target!(|data: &[u8]| {
    let [control, setup, wire @ ..] = data else {
        return;
    };
    let arrival = Arrival {
        input: wire,
        chunk: usize::from(control & 0x0f) + 1,
        period: usize::from(control >> 4),
        reads: 0,
        woken: false,
    };
    let role = if setup & 4 == 0 {
        Role::Client
    } else {
        Role::Server
    };
    let mut hosts = (arrival, Vec::<u8>::new());
    let mut expected = Vec::new();
    complete(hosts.walk_unpin(setup & 3, role, wire, &mut expected));
    assert_eq!(hosts.1, expected);
});

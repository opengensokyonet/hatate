//! Frames read from a stream that carries frames, with the parts of HTTP/3,
//! HTTP Datagrams and Extended CONNECT: each frame's type is checked against
//! the kind of stream and the role of the endpoint, a prefix of its payload
//! is read, and the frame is finished (or moved past to the next) by skipping.
//!
//! The first byte sets how the stream arrives: its low four bits plus one are
//! the bytes given per read, and its high four bits the period of a
//! `Pending` (0 for none). The second sets the stream: bits 0 and 1 the kind
//! (a request stream, a control stream, a push stream, a stream of another
//! type), bit 2 the role of the endpoint, bit 3 whether a frame is moved past
//! with `next` or finished and the next one read, and bits 4 to 7 how many
//! bytes of each payload are read. The rest is the stream, read with a host
//! that skips natively and once more with a host that only reads, made to skip
//! by `ReadSkip`; both must give what an independent reading of the bytes
//! calls for, which includes the failure and its code.
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
    error_code::{ErrorCode, ErrorCodeOf as _},
    frame::{
        FrameType,
        codec::{NextFrameError, ReadFrameError, ReadReceivedFrameError, read_received_frame},
        set::{FrameSet, FrameStreamKind},
    },
    stream::{FrameStream, FrameStreamInfo},
};
use libfuzzer_sys::fuzz_target;
use nitori_call::{ReceiverAccess, call};
use nitori_io::{Min, Read, Skip, adapters::ReadSkip, prelude::*};
use sakuya_var_int::VarInt;

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

/// How reading frames ended, if not at a frame boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    /// The stream ended inside a Type or Length.
    Head,
    /// A frame type of HTTP/2.
    Http2,
    /// A frame that may not be on this kind of stream.
    NotAllowed,
    /// A frame that this role may not receive.
    NotReceivable,
    /// The stream ended inside a payload.
    Payload,
}

impl Failure {
    const fn code(self) -> ErrorCode {
        match self {
            Self::Head | Self::Payload => ErrorCode::H3_FRAME_ERROR,
            Self::Http2 | Self::NotAllowed | Self::NotReceivable => ErrorCode::H3_FRAME_UNEXPECTED,
        }
    }
}

/// The frames read, each as its type and the payload bytes read, and then how
/// it ended.
type Outcome = (Vec<(u64, Vec<u8>)>, Option<Failure>);

fn head_failure<E, T>(error: &ReadReceivedFrameError<E, T>) -> Failure {
    let (failure, code) = match error {
        ReadReceivedFrameError::Frame {
            source: ReadFrameError::Type { .. } | ReadFrameError::Length { .. },
        } => (Failure::Head, Some(ErrorCode::H3_FRAME_ERROR)),
        ReadReceivedFrameError::Http2Type { .. } => {
            (Failure::Http2, Some(ErrorCode::H3_FRAME_UNEXPECTED))
        }
        ReadReceivedFrameError::NotAllowedOnStream { .. } => {
            (Failure::NotAllowed, Some(ErrorCode::H3_FRAME_UNEXPECTED))
        }
        ReadReceivedFrameError::NotReceivableByRole { .. } => {
            (Failure::NotReceivable, Some(ErrorCode::H3_FRAME_UNEXPECTED))
        }
    };
    assert_eq!(error.error_code(), code);
    assert_eq!(code, Some(failure.code()));
    failure
}

/// Reads at most `take` bytes from `io`, stopping at EOF.
async fn read_some<A: ReceiverAccess<Family: Read>>(
    io: &mut A,
    take: usize,
) -> Result<Vec<u8>, <A::Family as Read>::Error> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 7];
    while bytes.len() < take {
        let want = Ord::min(take - bytes.len(), buffer.len());
        let count = io.read(&mut &mut buffer[..want]).await?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(bytes)
}

/// Reads every frame of a stream that carries frames: of each, at most
/// `take` bytes of its payload, then on to the next frame, by `next` or by
/// `finish` and a read.
#[call(sync)]
async fn frames<F>(io: &mut impl ReceiverAccess<Family = F>, take: usize, next: bool) -> Outcome
where
    F: Skip<Count = usize> + Read<Error = Infallible> + FrameStreamInfo<Parts = Parts>,
{
    let mut seen = Vec::new();
    let mut received = read_received_frame(&mut *io).await;
    loop {
        let mut frame = match received {
            Ok(Some(frame)) => frame,
            Ok(None) => return (seen, None),
            Err(error) => return (seen, Some(head_failure(&error))),
        };
        let payload = match read_some(frame.payload(), take).await {
            Ok(payload) => payload,
            Err(error) => {
                assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
                return (seen, Some(Failure::Payload));
            }
        };
        let frame_type = match frame.frame_type() {
            FrameType::Known(value) => <Parts as FrameSet>::value_of(value).get(),
            FrameType::Unknown(value) => value.get(),
        };
        seen.push((frame_type, payload));
        received = if next {
            match frame.next().await {
                Ok(frame) => Ok(frame),
                Err(NextFrameError::Finish { source }) => {
                    assert_eq!(source.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
                    return (seen, Some(Failure::Payload));
                }
                Err(NextFrameError::Read { source }) => Err(source),
            }
        } else {
            match frame.finish().await {
                Ok(stream) => read_received_frame(stream).await,
                Err(source) => {
                    assert_eq!(source.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
                    return (seen, Some(Failure::Payload));
                }
            }
        };
    }
}

/// [`frames`] on a host that skips by itself.
#[call(sync)]
async fn native<F: Skip<Count = usize> + Read<Error = Infallible>>(
    io: &mut impl ReceiverAccess<Family = F>,
    kind: FrameStreamKind,
    role: Role,
    take: usize,
    next: bool,
) -> Outcome {
    let mut stream = io.compose(FrameStream::<Parts>::new(kind, role));
    stream.frames(take, next).await
}

/// [`frames`] on a host that only reads, made to skip by [`ReadSkip`].
#[call(sync)]
async fn by_reading<F: Read<Error = Infallible>>(
    io: &mut impl ReceiverAccess<Family = F>,
    kind: FrameStreamKind,
    role: Role,
    take: usize,
    next: bool,
) -> Outcome {
    let mut stream = io.compose(FrameStream::<Parts>::new(kind, role));
    let mut skipping = stream.compose(ReadSkip);
    skipping.frames(take, next).await
}

/// The length and value of the variable-length integer at the start of
/// `bytes`, if it is all there.
fn integer(bytes: &[u8]) -> Option<(usize, u64)> {
    let first = *bytes.first()?;
    let length = 1usize << (first >> 6);
    if bytes.len() < length {
        return None;
    }
    let value = bytes[..length]
        .iter()
        .enumerate()
        .fold(0u64, |value, (index, &byte)| {
            let byte = if index == 0 { byte & 0x3f } else { byte };
            (value << 8) | u64::from(byte)
        });
    Some((length, value))
}

/// Whether a frame of type `frame_type` may be on a stream of this kind and
/// be received by this role, by RFC 9114 §7.2 and not by the library: the
/// failure it calls for, if not.
fn placement(frame_type: u64, kind: FrameStreamKind, role: Role) -> Option<Failure> {
    let unidirectional = match kind {
        FrameStreamKind::Request => None,
        FrameStreamKind::Unidirectional(value) => Some(value.get()),
    };
    let allowed = match frame_type {
        // DATA and HEADERS: a request or push stream.
        0x00 | 0x01 => matches!(unidirectional, None | Some(1)),
        // PUSH_PROMISE: a request stream.
        0x05 => unidirectional.is_none(),
        // CANCEL_PUSH, SETTINGS, GOAWAY and MAX_PUSH_ID: the control stream.
        0x03 | 0x04 | 0x07 | 0x0d => unidirectional == Some(0),
        _ => true,
    };
    if !allowed {
        return Some(Failure::NotAllowed);
    }
    let receivable = match frame_type {
        0x05 => role == Role::Client,
        0x0d => role == Role::Server,
        _ => true,
    };
    (!receivable).then_some(Failure::NotReceivable)
}

/// What an independent reading of `wire` gives.
fn expected(wire: &[u8], kind: FrameStreamKind, role: Role, take: usize) -> Outcome {
    let mut seen = Vec::new();
    let mut at = 0;
    while at < wire.len() {
        let Some((type_length, frame_type)) = integer(&wire[at..]) else {
            return (seen, Some(Failure::Head));
        };
        // HTTP/2's types and the placement are checked before the Length.
        if matches!(frame_type, 0x02 | 0x06 | 0x08 | 0x09) {
            return (seen, Some(Failure::Http2));
        }
        if let Some(failure) = placement(frame_type, kind, role) {
            return (seen, Some(failure));
        }
        let Some((length_length, length)) = integer(&wire[at + type_length..]) else {
            return (seen, Some(Failure::Head));
        };
        let start = at + type_length + length_length;
        let available = wire.len() - start;
        let length = usize::try_from(length).unwrap_or(usize::MAX);
        // The bytes of the payload that are read must be there, and are
        // seen; then the rest, which is skipped, must be there too.
        let read = Ord::min(length, take);
        if available < read {
            return (seen, Some(Failure::Payload));
        }
        seen.push((frame_type, wire[start..start + read].to_vec()));
        if available < length {
            return (seen, Some(Failure::Payload));
        }
        at = start + length;
    }
    (seen, None)
}

fuzz_target!(|data: &[u8]| {
    let [control, setup, wire @ ..] = data else {
        return;
    };
    let arrival = || Arrival {
        input: wire,
        chunk: usize::from(control & 0x0f) + 1,
        period: usize::from(control >> 4),
        reads: 0,
        woken: false,
    };
    let kind = match setup & 3 {
        0 => FrameStreamKind::Request,
        1 => FrameStreamKind::Unidirectional(VarInt::from_u32(0x00)),
        2 => FrameStreamKind::Unidirectional(VarInt::from_u32(0x01)),
        _ => FrameStreamKind::Unidirectional(VarInt::from_u32(0x21)),
    };
    let role = if setup & 4 == 0 {
        Role::Client
    } else {
        Role::Server
    };
    let next = setup & 8 != 0;
    let take = usize::from(setup >> 4);
    let expected = expected(wire, kind, role, take);

    let mut host = arrival();
    assert_eq!(
        complete(host.native_unpin(kind, role, take, next)),
        expected
    );
    let mut host = arrival();
    assert_eq!(
        complete(host.by_reading_unpin(kind, role, take, next)),
        expected
    );
});

//! Frames read from a [`FrameStream`] that carries frames, with the parts of
//! HTTP/3, HTTP Datagrams and Extended CONNECT: each frame's type is checked
//! against the kind of stream and the role of the endpoint, and the whole
//! stream is walked frame by frame.
//!
//! The first byte sets how the stream arrives: its low four bits plus one are
//! the bytes given per read, and its high four bits the period of a
//! `Pending` (0 for none). The second sets the stream: bits 0 and 1 the kind
//! (a request stream, a control stream, a push stream, and again a request
//! stream), bit 2 the role of the endpoint, bit 3 whether the walk uses
//! `next_known_frame` (which skips reserved and unknown frames after the
//! first) or `next_frame`, and bits 4 to 7 how many bytes of each payload are
//! read; 15 is the mode that writes every frame back whole with `write_frame`
//! instead, which must give the bytes of the frames it was read from. The
//! rest is the stream, read with a host that skips natively and once more with
//! a host that only reads, made to skip by `ReadSkip`; both must give what an
//! independent reading of the bytes calls for, which includes the failure and
//! its code.
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
    error_code::{ErrorCode, ErrorCodeOf},
    frame::codec::{ReadFrameError, ReadFrameHeadError, WriteFrameError, WriteFrameExt as _},
    stream::{
        FrameStream, NextFrameError,
        kind::{ControlStreamKind, PushStreamKind, RequestStreamKind},
    },
};
use libfuzzer_sys::fuzz_target;
use nitori_call::{ReceiverAccess, call};
use nitori_io::{Min, Read, Skip, Write, adapters::ReadSkip, prelude::*};

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

fn head_failure<E: ErrorCodeOf<ErrorCode>>(error: &ReadFrameHeadError<E>) -> Failure {
    let failure = match error {
        ReadFrameHeadError::Frame {
            source: ReadFrameError::Type { .. } | ReadFrameError::Length { .. },
        } => Failure::Head,
        ReadFrameHeadError::Http2Type { .. } => Failure::Http2,
        ReadFrameHeadError::NotAllowedOnStream { .. } => Failure::NotAllowed,
        ReadFrameHeadError::NotReceivableByRole { .. } => Failure::NotReceivable,
    };
    assert_eq!(error.error_code(), Some(failure.code()));
    failure
}

fn next_failure<E: ErrorCodeOf<ErrorCode>>(error: &NextFrameError<E>) -> Failure {
    match error {
        NextFrameError::Skip { source } => {
            assert_eq!(source.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
            Failure::Payload
        }
        NextFrameError::Head { source } => head_failure(source),
        NextFrameError::Interrupted => panic!("a stream was interrupted without a failure"),
    }
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

/// The mode of `take` that writes the frames back.
const WRITE_BACK: usize = 15;

/// Walks the stream of one kind from its first frame: of each frame at most
/// `take` bytes of its payload are read, or all of it is written to `out`.
macro_rules! walk {
    ($io:expr, $kind:ty, $role:expr, $take:expr, $known:expr, $out:expr) => {{
        let take: usize = $take;
        let known: bool = $known;
        let mut seen = Vec::new();
        let mut stream = match FrameStream::<Parts, $kind, _>::read($io, $role).await {
            Ok(Some(stream)) => stream,
            Ok(None) => return (seen, None),
            Err(error) => return (seen, Some(head_failure(&error))),
        };
        loop {
            let mut frame = stream.frame();
            let frame_type = frame.frame_type().value().get();
            if take == WRITE_BACK {
                match $out.write_frame(frame).await {
                    Ok(()) => seen.push((frame_type, Vec::new())),
                    Err(WriteFrameError::Payload { .. }) => return (seen, Some(Failure::Payload)),
                    Err(error) => panic!("a frame that was read was not written: {error}"),
                }
            } else {
                match read_some(frame.payload(), take).await {
                    Ok(payload) => seen.push((frame_type, payload)),
                    Err(error) => {
                        assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
                        return (seen, Some(Failure::Payload));
                    }
                }
            }
            let next = if known {
                stream.next_known_frame().await
            } else {
                stream.next_frame().await
            };
            match next {
                Ok(Some(_)) => {}
                Ok(None) => return (seen, None),
                Err(error) => return (seen, Some(next_failure(&error))),
            }
        }
    }};
}

async fn frames_of<I, B>(
    io: I,
    out: &mut B,
    kind: u8,
    role: Role,
    take: usize,
    known: bool,
) -> Outcome
where
    I: ReceiverAccess<Family: Skip<Count = usize> + Read<Error = Infallible>>,
    B: ReceiverAccess<Family: Write<Error = Infallible>>,
{
    match kind & 3 {
        1 => walk!(io, ControlStreamKind, role, take, known, out),
        2 => walk!(io, PushStreamKind, role, take, known, out),
        _ => walk!(io, RequestStreamKind, role, take, known, out),
    }
}

/// [`frames_of`] on a host that skips by itself.
#[call(sync)]
async fn native<F: Skip<Count = usize> + Read<Error = Infallible>, W: Write<Error = Infallible>>(
    io: &mut impl ReceiverAccess<Family = F>,
    out: &mut impl ReceiverAccess<Family = W>,
    kind: u8,
    role: Role,
    take: usize,
    known: bool,
) -> Outcome {
    frames_of(&mut *io, out, kind, role, take, known).await
}

/// [`frames_of`] on a host that only reads, made to skip by [`ReadSkip`].
#[call(sync)]
async fn by_reading<F: Read<Error = Infallible>, W: Write<Error = Infallible>>(
    io: &mut impl ReceiverAccess<Family = F>,
    out: &mut impl ReceiverAccess<Family = W>,
    kind: u8,
    role: Role,
    take: usize,
    known: bool,
) -> Outcome {
    let mut skipping = io.compose(ReadSkip);
    frames_of(&mut skipping, out, kind, role, take, known).await
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
fn placement(frame_type: u64, kind: u8, role: Role) -> Option<Failure> {
    let allowed = match frame_type {
        // DATA and HEADERS: a request or push stream.
        0x00 | 0x01 => kind != 1,
        // PUSH_PROMISE: a request stream.
        0x05 => kind != 1 && kind != 2,
        // CANCEL_PUSH, SETTINGS, GOAWAY and MAX_PUSH_ID: the control stream.
        0x03 | 0x04 | 0x07 | 0x0d => kind == 1,
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

/// Whether a frame of this type is one the parts have on this kind of
/// stream, rather than reserved or unknown.
fn known_on(frame_type: u64, kind: u8) -> bool {
    match frame_type {
        0x00 | 0x01 => kind != 1,
        0x05 => kind != 1 && kind != 2,
        0x03 | 0x04 | 0x07 | 0x0d => kind == 1,
        _ => false,
    }
}

/// What an independent reading of the stream gives, and the bytes the frames
/// it returns are written back as: `whole` of the complete ones, and `tail`, the
/// stream from the start of the frame whose payload is cut, a prefix of
/// which may have been written.
struct Expected {
    outcome: Outcome,
    whole: Vec<u8>,
    tail: Vec<u8>,
}

fn expected(wire: &[u8], kind: u8, role: Role, take: usize, known: bool) -> Expected {
    let write_back = take == WRITE_BACK;
    let mut seen = Vec::new();
    let mut whole = Vec::new();
    let mut at = 0;
    let finish = |seen, failure, whole, tail| Expected {
        outcome: (seen, failure),
        whole,
        tail,
    };
    while at < wire.len() {
        let start = at;
        let Some((type_length, frame_type)) = integer(&wire[at..]) else {
            return finish(seen, Some(Failure::Head), whole, Vec::new());
        };
        // HTTP/2's types and the placement are checked before the Length.
        if matches!(frame_type, 0x02 | 0x06 | 0x08 | 0x09) {
            return finish(seen, Some(Failure::Http2), whole, Vec::new());
        }
        if let Some(failure) = placement(frame_type, kind, role) {
            return finish(seen, Some(failure), whole, Vec::new());
        }
        let Some((length_length, length)) = integer(&wire[at + type_length..]) else {
            return finish(seen, Some(Failure::Head), whole, Vec::new());
        };
        let payload_start = at + type_length + length_length;
        let available = wire.len() - payload_start;
        let length = usize::try_from(length).unwrap_or(usize::MAX);
        // The first frame is always given; later ones are given by
        // next_known_frame only if known.
        let returned = start == 0 || !known || known_on(frame_type, kind);
        if !returned {
            if available < length {
                return finish(seen, Some(Failure::Payload), whole, Vec::new());
            }
        } else if write_back {
            if available < length {
                return finish(seen, Some(Failure::Payload), whole, wire[start..].to_vec());
            }
            seen.push((frame_type, Vec::new()));
            whole.extend_from_slice(&wire[start..payload_start + length]);
        } else {
            // The bytes of the payload that are read must be there, and are
            // seen; then the rest, which is skipped, must be there too.
            let read = Ord::min(length, take);
            if available < read {
                return finish(seen, Some(Failure::Payload), whole, Vec::new());
            }
            seen.push((
                frame_type,
                wire[payload_start..payload_start + read].to_vec(),
            ));
            if available < length {
                return finish(seen, Some(Failure::Payload), whole, Vec::new());
            }
        }
        at = payload_start + length;
    }
    finish(seen, None, whole, Vec::new())
}

/// What was written must be the bytes of the frames given, plus, after a
/// failure inside a payload, a prefix of the frame that failed.
fn check_written(expected: &Expected, written: &[u8]) {
    assert!(
        written.starts_with(&expected.whole),
        "{written:?} {:?}",
        expected.whole
    );
    if expected.outcome.1.is_none() {
        assert_eq!(written, expected.whole);
    } else {
        let extra = &written[expected.whole.len()..];
        assert!(
            expected.tail.starts_with(extra),
            "{extra:?} {:?}",
            expected.tail
        );
    }
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
    let kind = setup & 3;
    let role = if setup & 4 == 0 {
        Role::Client
    } else {
        Role::Server
    };
    let known = setup & 8 != 0;
    let take = usize::from(setup >> 4);
    let expected = expected(wire, kind, role, take, known);

    let mut hosts = (arrival(), Vec::<u8>::new());
    assert_eq!(
        complete(hosts.native_unpin(kind, role, take, known)),
        expected.outcome
    );
    check_written(&expected, &hosts.1);
    let mut hosts = (arrival(), Vec::<u8>::new());
    assert_eq!(
        complete(hosts.by_reading_unpin(kind, role, take, known)),
        expected.outcome
    );
    check_written(&expected, &hosts.1);
});

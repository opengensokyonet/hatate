//! The start of a unidirectional or a bidirectional stream, read by the two
//! constructors, and HTTP/3 datagrams, with the parts of HTTP/3, HTTP
//! Datagrams and Extended CONNECT.
//!
//! The low bit of the first byte picks the mode. In stream mode the rest is a
//! stream, however it arrives (bits 4 to 6 of the first byte are the bytes
//! given per read, minus one, and bits 1 to 3 the period of a `Pending`); the
//! second byte sets which of the four classes of stream it is (bits 0 and 1),
//! whether a stream no part claims is discarded (bit 2), and the rest is the
//! stream. What is read is checked against an independent decoding of the
//! first integer, and of the frame head after it where the stream is read up
//! to its first frame, with the reserved frames skipped before the first value
//! of a bidirectional stream; each field is written back and must equal its
//! bytes. In datagram mode the rest is the payload of a QUIC DATAGRAM frame,
//! read as a datagram, written back, and compared; a failure must be the one
//! the first bytes call for, and carry H3_DATAGRAM_ERROR.
#![no_main]
#![feature(impl_trait_in_assoc_type)]
use bytes::BufMut;
use core::{
    convert::Infallible,
    future::Future,
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
};
use frunk_core::{HList, coproduct::Coproduct};
use hatate_wire::{
    Role,
    error_code::{ErrorCode, ErrorCodeOf},
    stream::{
        ReceivedStream, TypedStream as _,
        class::{
            ClientInitiatedBidirectional, ClientInitiatedUnidirectional,
            ServerInitiatedBidirectional, ServerInitiatedUnidirectional,
        },
        codec::{
            ReadBidirectionalStreamError, ReadUnidirectionalStreamError, read_bidirectional_stream,
            read_unidirectional_stream,
        },
        http3::Http3UnidirectionalStream,
    },
};
use hatate_wire_datagram::{H3_DATAGRAM_ERROR, read_datagram, write_datagram};
use libfuzzer_sys::fuzz_target;
use nitori_call::{ReceiverAccess, call};
use nitori_io::{Min, Read, Skip};
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

/// The length and value of the variable-length integer at the start of
/// `bytes`, if it is all there.
fn integer(bytes: &[u8]) -> Result<(usize, u64), usize> {
    let Some(&first) = bytes.first() else {
        return Err(1);
    };
    let length = 1usize << (first >> 6);
    if bytes.len() < length {
        return Err(length);
    }
    let value = bytes[..length]
        .iter()
        .enumerate()
        .fold(0u64, |value, (index, &byte)| {
            let byte = if index == 0 { byte & 0x3f } else { byte };
            (value << 8) | u64::from(byte)
        });
    Ok((length, value))
}

/// `integer`, as an option.
fn integer_at(bytes: &[u8]) -> Option<(usize, u64)> {
    integer(bytes).ok()
}

fn bytes_of(field: VarIntField<VarInt>) -> Vec<u8> {
    let (bytes, length) = field.to_encoding();
    bytes[..length].to_vec()
}

/// The first frame of a stream that was read up to it: its Type and Length
/// as read, with the bytes of each field written back.
#[derive(Debug, PartialEq, Eq)]
struct First {
    frame_type: u64,
    type_bytes: Vec<u8>,
    length: u64,
    length_bytes: Vec<u8>,
}

fn first_of<T: Copy + Into<VarInt>, P>(frame: &hatate_wire::frame::Frame<T, P>) -> First {
    let value: VarInt = frame.frame_type().into();
    First {
        frame_type: value.get(),
        type_bytes: bytes_of(VarIntField::new(value, frame.r#type().width()).unwrap()),
        length: frame.length().get().get(),
        length_bytes: bytes_of(frame.length()),
    }
}

/// What reading the start of a stream gave.
#[derive(Debug, PartialEq, Eq)]
enum Started {
    /// A control stream, with the bytes of its Stream Type.
    Control(Vec<u8>, First),
    /// A push stream, with the bytes of its Stream Type, the Push ID and the
    /// bytes of it.
    Push(Vec<u8>, u64, Vec<u8>, First),
    /// A QPACK stream, with the bytes of its Stream Type.
    Qpack(Vec<u8>),
    /// A unidirectional stream no part claims, with the bytes of its Stream
    /// Type and its value.
    Unknown(Vec<u8>, u64),
    /// A bidirectional stream no part claims, with its value.
    UnknownFirst(u64),
    /// A request stream, at its first frame.
    Request(First),
}

/// A failure: which, and its code.
#[derive(Debug, PartialEq, Eq)]
struct Failed {
    kind: &'static str,
    code: Option<ErrorCode>,
}

type Outcome = Result<Option<Started>, Failed>;

fn unidirectional_failed<
    E: ErrorCodeOf<ErrorCode>,
    P: ErrorCodeOf<ErrorCode>,
    R: ErrorCodeOf<ErrorCode>,
>(
    error: &ReadUnidirectionalStreamError<E, P, R>,
) -> Failed {
    let kind = match error {
        ReadUnidirectionalStreamError::Type { source } => {
            assert!(source.is_incomplete());
            "type"
        }
        ReadUnidirectionalStreamError::Rejected { .. } => "rejected",
        ReadUnidirectionalStreamError::Part { .. } => "part",
    };
    Failed {
        kind,
        code: error.error_code(),
    }
}

fn bidirectional_failed<
    E: ErrorCodeOf<ErrorCode>,
    P: ErrorCodeOf<ErrorCode>,
    R: ErrorCodeOf<ErrorCode>,
>(
    error: &ReadBidirectionalStreamError<E, P, R>,
) -> Failed {
    let kind = match error {
        ReadBidirectionalStreamError::Head { .. } => "head",
        ReadBidirectionalStreamError::ReservedPayload { .. } => "reserved payload",
        ReadBidirectionalStreamError::Rejected { .. } => "rejected",
        ReadBidirectionalStreamError::Part { .. } => "part",
    };
    Failed {
        kind,
        code: error.error_code(),
    }
}

macro_rules! unidirectional {
    ($name:ident, $class:ty) => {
        #[call(sync)]
        async fn $name<
            F: Read<Error = Infallible> + Skip<Count = usize>,
            A: ReceiverAccess<Family = F>,
        >(
            io: &mut A,
            discard: bool,
        ) -> Outcome {
            let stream = match read_unidirectional_stream::<Parts, $class, _>(&mut *io).await {
                Ok(Some(stream)) => stream,
                Ok(None) => return Ok(None),
                Err(error) => return Err(unidirectional_failed(&error)),
            };
            // The field is written back as the bytes it was read from.
            let field = bytes_of(stream.type_field());
            assert_eq!(stream.type_field().get(), stream.stream().stream_type());
            Ok(Some(match stream.into_stream() {
                ReceivedStream::Unknown(unknown) => {
                    let value = unknown.value().get();
                    if discard {
                        unknown.discard().await.unwrap();
                    }
                    Started::Unknown(field, value)
                }
                ReceivedStream::Known(Coproduct::Inl(known)) => match known {
                    Http3UnidirectionalStream::Control(mut control) => {
                        Started::Control(field, first_of(&control.frame()))
                    }
                    Http3UnidirectionalStream::Push(mut push) => {
                        let id = push.push_id();
                        let id_bytes =
                            bytes_of(VarIntField::new(id.get().get(), id.width()).unwrap());
                        let first = first_of(&push.frames().frame());
                        Started::Push(field, id.get().get().get(), id_bytes, first)
                    }
                    Http3UnidirectionalStream::QpackEncoder(_)
                    | Http3UnidirectionalStream::QpackDecoder(_) => Started::Qpack(field),
                },
                ReceivedStream::Known(Coproduct::Inr(none)) => match none {
                    Coproduct::Inl(none) | Coproduct::Inr(Coproduct::Inl(none)) => match none {},
                    Coproduct::Inr(Coproduct::Inr(none)) => match none {},
                },
            }))
        }
    };
}

macro_rules! bidirectional {
    ($name:ident, $class:ty, |$known:ident| $request:expr) => {
        #[call(sync)]
        async fn $name<
            F: Read<Error = Infallible> + Skip<Count = usize>,
            A: ReceiverAccess<Family = F>,
        >(
            io: &mut A,
            discard: bool,
        ) -> Outcome {
            let stream = match read_bidirectional_stream::<Parts, $class, _>(&mut *io).await {
                Ok(Some(stream)) => stream,
                Ok(None) => return Ok(None),
                Err(error) => return Err(bidirectional_failed(&error)),
            };
            Ok(Some(match stream {
                ReceivedStream::Unknown(unknown) => {
                    let value = unknown.value().get();
                    if discard {
                        unknown.discard().await.unwrap();
                    }
                    Started::UnknownFirst(value)
                }
                ReceivedStream::Known($known) => $request,
            }))
        }
    };
}

unidirectional!(read_from_client, ClientInitiatedUnidirectional);
unidirectional!(read_from_server, ServerInitiatedUnidirectional);
bidirectional!(
    read_client_bidirectional,
    ClientInitiatedBidirectional,
    |known| match known {
        Coproduct::Inl(mut request) => Started::Request(first_of(&request.frame())),
        Coproduct::Inr(none) => match none {
            Coproduct::Inl(none) | Coproduct::Inr(Coproduct::Inl(none)) => match none {},
            Coproduct::Inr(Coproduct::Inr(none)) => match none {},
        },
    }
);
bidirectional!(
    read_server_bidirectional,
    ServerInitiatedBidirectional,
    |known| match known {
        Coproduct::Inl(none) => match none {},
        Coproduct::Inr(Coproduct::Inl(none) | Coproduct::Inr(Coproduct::Inl(none))) =>
            match none {},
        Coproduct::Inr(Coproduct::Inr(Coproduct::Inr(none))) => match none {},
    }
);

const FRAME_ERROR: Option<ErrorCode> = Some(ErrorCode::H3_FRAME_ERROR);
const UNEXPECTED: Option<ErrorCode> = Some(ErrorCode::H3_FRAME_UNEXPECTED);

fn failed(kind: &'static str, code: Option<ErrorCode>) -> Outcome {
    Err(Failed { kind, code })
}

/// A frame type of HTTP/2, which HTTP/3 does not have.
fn http2(value: u64) -> bool {
    matches!(value, 0x02 | 0x06 | 0x08 | 0x09)
}

/// A reserved value, 0x1f * N + 0x21.
fn reserved(value: u64) -> bool {
    value >= 0x21 && (value - 0x21) % 0x1f == 0
}

/// Whether a frame of `frame_type` may arrive on a control (1) or push (2)
/// stream, or a request stream (0), at an endpoint of this role, by RFC 9114
/// §7.2: the code of the failure if not.
fn placement(frame_type: u64, kind: u8, role: Role) -> Option<ErrorCode> {
    let allowed = match frame_type {
        0x00 | 0x01 => kind != 1,
        0x05 => kind == 0,
        0x03 | 0x04 | 0x07 | 0x0d => kind == 1,
        _ => true,
    };
    let receivable = match frame_type {
        0x05 => role == Role::Client,
        0x0d => role == Role::Server,
        _ => true,
    };
    (http2(frame_type) || !allowed || !receivable).then_some(ErrorCode::H3_FRAME_UNEXPECTED)
}

/// The head of the first frame of a stream of this kind, in `wire`, read by
/// an endpoint of this role: how many bytes it takes and the frame, or the
/// code of the failure.
fn head(wire: &[u8], kind: u8, role: Role) -> Result<(usize, First), Option<ErrorCode>> {
    // A control stream is critical: its end, inside a head too, is a failure
    // of the stream.
    let cut = Some(if kind == 1 {
        ErrorCode::H3_CLOSED_CRITICAL_STREAM
    } else {
        ErrorCode::H3_FRAME_ERROR
    });
    let Some((type_length, frame_type)) = integer_at(wire) else {
        return Err(cut);
    };
    if let Some(code) = placement(frame_type, kind, role) {
        return Err(Some(code));
    }
    let Some((length_length, length)) = integer_at(&wire[type_length..]) else {
        return Err(cut);
    };
    Ok((
        type_length + length_length,
        First {
            frame_type,
            type_bytes: wire[..type_length].to_vec(),
            length,
            length_bytes: wire[type_length..type_length + length_length].to_vec(),
        },
    ))
}

/// What reading the start of a unidirectional stream that `opener` opened
/// must give, and how many bytes it takes if it succeeds or is rejected.
fn expected_unidirectional(
    wire: &[u8],
    server_opened: bool,
    discard: bool,
) -> (Outcome, Option<usize>) {
    let receiver = if server_opened {
        Role::Client
    } else {
        Role::Server
    };
    let Ok((length, value)) = integer(wire) else {
        return if wire.is_empty() {
            (Ok(None), Some(0))
        } else {
            (failed("type", None), None)
        };
    };
    let field = wire[..length].to_vec();
    let after = &wire[length..];
    match value {
        0 if after.is_empty() => (
            failed("part", Some(ErrorCode::H3_CLOSED_CRITICAL_STREAM)),
            None,
        ),
        0 => match head(after, 1, receiver) {
            // The first frame of a control stream is SETTINGS (RFC 9114
            // §6.2.1).
            Ok((_, first)) if first.frame_type != 0x04 => {
                (failed("part", Some(ErrorCode::H3_MISSING_SETTINGS)), None)
            }
            Ok((used, first)) => (
                Ok(Some(Started::Control(field, first))),
                Some(length + used),
            ),
            Err(code) => (failed("part", code), None),
        },
        1 if !server_opened => (
            failed("rejected", Some(ErrorCode::H3_STREAM_CREATION_ERROR)),
            Some(length),
        ),
        1 => {
            let Some((id_length, id)) = integer_at(after) else {
                return (failed("part", None), None);
            };
            let rest = &after[id_length..];
            if rest.is_empty() {
                return (failed("part", None), None);
            }
            match head(rest, 2, receiver) {
                Ok((used, first)) => (
                    Ok(Some(Started::Push(
                        field,
                        id,
                        after[..id_length].to_vec(),
                        first,
                    ))),
                    Some(length + id_length + used),
                ),
                Err(code) => (failed("part", code), None),
            }
        }
        2 | 3 => (Ok(Some(Started::Qpack(field))), Some(length)),
        value => (
            Ok(Some(Started::Unknown(field, value))),
            Some(if discard { wire.len() } else { length }),
        ),
    }
}

/// What reading the start of a bidirectional stream that is opened by the
/// server (or the client) must give.
fn expected_bidirectional(
    wire: &[u8],
    server_opened: bool,
    discard: bool,
) -> (Outcome, Option<usize>) {
    let mut at = 0;
    let (value, value_length) = loop {
        let Some((type_length, value)) = integer_at(&wire[at..]) else {
            return if at == wire.len() {
                (Ok(None), Some(at))
            } else {
                (failed("head", FRAME_ERROR), None)
            };
        };
        if !reserved(value) {
            break (value, type_length);
        }
        let Some((length_length, length)) = integer_at(&wire[at + type_length..]) else {
            return (failed("head", FRAME_ERROR), None);
        };
        let payload = at + type_length + length_length;
        if (wire.len() - payload) as u64 >= length {
            at = payload + usize::try_from(length).unwrap();
        } else {
            return (failed("reserved payload", FRAME_ERROR), None);
        }
    };
    let after_value = at + value_length;
    if server_opened {
        return (
            failed("rejected", Some(ErrorCode::H3_STREAM_CREATION_ERROR)),
            Some(after_value),
        );
    }
    match value {
        0 | 1 => match integer_at(&wire[after_value..]) {
            None => (failed("part", FRAME_ERROR), None),
            Some((length_length, length)) => (
                Ok(Some(Started::Request(First {
                    frame_type: value,
                    type_bytes: wire[at..after_value].to_vec(),
                    length,
                    length_bytes: wire[after_value..after_value + length_length].to_vec(),
                }))),
                Some(after_value + length_length),
            ),
        },
        value if http2(value) || matches!(value, 0x03 | 0x04 | 0x05 | 0x07 | 0x0d) => {
            (failed("rejected", UNEXPECTED), Some(after_value))
        }
        value => (
            Ok(Some(Started::UnknownFirst(value))),
            Some(if discard { wire.len() } else { after_value }),
        ),
    }
}

fn stream(control: u8, setup: u8, wire: &[u8]) {
    let arrival = || Arrival {
        input: wire,
        chunk: usize::from(control >> 4 & 0x07) + 1,
        period: usize::from(control >> 1 & 0x07),
        reads: 0,
        woken: false,
    };
    let discard = setup & 4 != 0;
    let (result, expected, consumed) = {
        let mut host = arrival();
        let result = match setup & 3 {
            0 => complete(host.read_from_client_unpin(discard)),
            1 => complete(host.read_from_server_unpin(discard)),
            2 => complete(host.read_client_bidirectional_unpin(discard)),
            _ => complete(host.read_server_bidirectional_unpin(discard)),
        };
        let (expected, consumed) = match setup & 3 {
            0 => expected_unidirectional(wire, false, discard),
            1 => expected_unidirectional(wire, true, discard),
            2 => expected_bidirectional(wire, false, discard),
            _ => expected_bidirectional(wire, true, discard),
        };
        assert_eq!(
            wire.len() - host.input.len(),
            consumed.unwrap_or(wire.len() - host.input.len())
        );
        (result, expected, consumed)
    };
    let _ = consumed;
    assert_eq!(result, expected);
}

fn datagram(payload: &[u8]) {
    let expected = integer(payload);
    match read_datagram(payload) {
        Ok(datagram) => {
            let Ok((length, value)) = expected else {
                panic!("a datagram was read from {payload:?}");
            };
            assert!(value < 1 << 60);
            assert_eq!(datagram.quarter_stream_id().get().get().get(), value);
            assert_eq!(datagram.quarter_stream_id().encoded_len(), length);
            assert_eq!(*datagram.payload(), &payload[length..]);
            let mut written = Vec::new();
            write_datagram(&mut written, datagram);
            assert_eq!(written, payload);
        }
        Err(error) => {
            assert_eq!(error.error_code(), Some(H3_DATAGRAM_ERROR));
            match expected {
                Err(_) => {}
                Ok((_, value)) => assert!(value >= 1 << 60),
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&control, rest)) = data.split_first() else {
        return;
    };
    if control & 1 == 0 {
        let Some((&setup, wire)) = rest.split_first() else {
            return;
        };
        stream(control, setup, wire);
    } else {
        datagram(rest);
    }
});

#![feature(impl_trait_in_assoc_type)]
//! The start of a bidirectional stream (RFC 9114 §6.1): reserved frames are
//! skipped and told to the parts, which judge the first value that is not
//! reserved; a request stream comes back at its first frame.
use core::convert::Infallible;
use frunk_core::{
    HList,
    coproduct::{CNil, Coproduct},
};
use hatate_wire::{
    Part,
    error_code::{ErrorCode, ErrorCodeOf},
    frame::{
        FrameType,
        codec::UnexpectedFrameTypeError,
        set::{FramePart, FramePartOn},
    },
    registry::ClaimedValues,
    stream::{
        FrameStream, ReceivedStream,
        class::{ClientInitiatedBidirectional, ServerInitiatedBidirectional},
        codec::{ReadBidirectionalStreamError, read_bidirectional_stream},
        http3::ServerBidirectionalStreamError,
        kind::{RequestStreamKind, StreamKind},
        part::{StreamPart, StreamVerdict},
    },
};
use nitori_call::{AsAccess, ReceiverAccess, call};
use nitori_codec::{payload::Buffered, prelude::*};
use nitori_io::{Combine, Read, Skip, Write, calls::ReadValue, prelude::*};
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};

/// A part that exists for these tests: it claims the value 0x41 on the
/// bidirectional streams, as a stream that tells whether reserved frames
/// came before it, and rejects 0x2b.
#[derive(Clone, Copy)]
struct Probe;

const PROBE_ERROR: ErrorCode = ErrorCode::new(VarInt::from_u32(0x1234));

/// Why the probe rejects 0x2b.
#[derive(Debug)]
struct ProbeRejection;

impl core::fmt::Display for ProbeRejection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the probe rejects the stream")
    }
}

impl core::error::Error for ProbeRejection {}

impl ErrorCodeOf<ErrorCode> for ProbeRejection {
    fn error_code(&self) -> Option<ErrorCode> {
        Some(PROBE_ERROR)
    }
}

impl FramePart for Probe {
    const FRAME_TYPES: &'static ClaimedValues = &ClaimedValues::NONE;
}

impl<K: StreamKind> FramePartOn<K> for Probe {
    type FrameType = CNil;
}

/// What the probe's stream is: whether reserved frames came before its value.
#[derive(Debug, PartialEq, Eq)]
struct ProbeStream {
    skipped: bool,
}

macro_rules! probe_part {
    ($class:ty) => {
        impl<L> StreamPart<$class, L> for Probe {
            type Claimed = bool;
            type Rejection = ProbeRejection;
            type Stream<I, M> = ProbeStream;
            type ReadError<E> = CNil;

            fn judge(value: VarInt, skipped: bool) -> StreamVerdict<bool, ProbeRejection> {
                match value.get() {
                    0x2a => StreamVerdict::Claimed(skipped),
                    0x2b => StreamVerdict::Error(ProbeRejection),
                    _ => StreamVerdict::NotClaimed,
                }
            }

            async fn read<
                I: ReceiverAccess<Family: Read<Metadata = M>>,
                M: Combine + Unpin + Clone,
            >(
                skipped: bool,
                _field: ReadValue<VarIntField<VarInt>, M>,
                _io: I,
            ) -> Result<ProbeStream, CNil> {
                Ok(ProbeStream { skipped })
            }
        }
    };
}

probe_part!(ClientInitiatedBidirectional);
probe_part!(ServerInitiatedBidirectional);

type Plain = HList![Part];
type Probing = HList![Part, Probe];

/// One frame read: its type, as the stream reads it, the width of the Type,
/// the Length and the payload.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    /// 'K' for a known type, 'R' for a reserved one, 'U' for an unknown one.
    class: char,
    frame_type: u64,
    type_width: VarIntWidth,
    length: u64,
    payload: Vec<u8>,
}

/// What reading the start of a bidirectional stream gave.
#[derive(Debug, PartialEq, Eq)]
enum Started {
    /// A request stream: its frames to the end, and how that ended.
    Request {
        frames: Vec<Seen>,
        end: Option<ErrorCode>,
    },
    /// The stream of the probe.
    Probe { skipped: bool },
    /// No part claims it.
    Unknown { value: u64 },
}

#[derive(Debug, PartialEq, Eq)]
enum Failed {
    /// The head of a reserved frame at the start was cut; the code.
    Head(Option<ErrorCode>),
    /// The payload of a reserved frame at the start was cut; the code.
    ReservedPayload(Option<ErrorCode>),
    /// A part rejected the value, for this reason.
    Rejected {
        value: u64,
        code: ErrorCode,
        reason: Reason,
    },
    /// The part that claims the value could not read the start; the code.
    Part(Option<ErrorCode>),
}

/// Which rule rejected a value.
#[derive(Debug, PartialEq, Eq)]
enum Reason {
    Http2Type,
    NotAllowedOnStream,
    NotReceivableByRole,
    ServerBidirectionalStream,
    Probe,
}

/// The reason in a sum of rejections.
trait Classify {
    fn reason(&self) -> Reason;
}

impl Classify for CNil {
    fn reason(&self) -> Reason {
        match *self {}
    }
}

impl<H: Classify, T: Classify> Classify for Coproduct<H, T> {
    fn reason(&self) -> Reason {
        match self {
            Coproduct::Inl(head) => head.reason(),
            Coproduct::Inr(rest) => rest.reason(),
        }
    }
}

impl Classify for UnexpectedFrameTypeError {
    fn reason(&self) -> Reason {
        match self {
            Self::Http2Type { .. } => Reason::Http2Type,
            Self::NotAllowedOnStream { .. } => Reason::NotAllowedOnStream,
            Self::NotReceivableByRole { .. } => Reason::NotReceivableByRole,
        }
    }
}

impl Classify for ServerBidirectionalStreamError {
    fn reason(&self) -> Reason {
        Reason::ServerBidirectionalStream
    }
}

impl Classify for ProbeRejection {
    fn reason(&self) -> Reason {
        Reason::Probe
    }
}

fn failed<
    E: hatate_wire::error_code::ErrorCodeOf<ErrorCode>,
    P: hatate_wire::error_code::ErrorCodeOf<ErrorCode>,
    R: hatate_wire::error_code::ErrorCodeOf<ErrorCode> + Classify,
>(
    error: &ReadBidirectionalStreamError<E, P, R>,
) -> Failed {
    let code = error.error_code();
    match error {
        ReadBidirectionalStreamError::Head { .. } => Failed::Head(code),
        ReadBidirectionalStreamError::ReservedPayload { .. } => Failed::ReservedPayload(code),
        ReadBidirectionalStreamError::Rejected { value, source } => Failed::Rejected {
            value: value.get(),
            code: code.expect("a rejection has a code"),
            reason: source.get().reason(),
        },
        ReadBidirectionalStreamError::Part { .. } => Failed::Part(code),
    }
}

/// Reads at most `take` bytes from `io`, stopping at the end.
async fn read_some<A: AsAccess<Family: Read<Metadata = ()>>>(
    io: &mut A,
    take: usize,
) -> Result<Vec<u8>, <A::Family as Read>::Error> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 7];
    while bytes.len() < take {
        let want = (take - bytes.len()).min(buffer.len());
        let count = io
            .access()
            .read(&mut &mut buffer[..want])
            .await?
            .map_or(0, |segment| segment.count.get());
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(bytes)
}

/// Reads every frame of a request stream, from the first, and tells how the
/// stream ended.
async fn request_frames<L, I>(mut request: FrameStream<L, RequestStreamKind, I>) -> Started
where
    L: hatate_wire::frame::set::FrameSetOn<RequestStreamKind>,
    I: ReceiverAccess<
        Family: Skip<Count = usize, Metadata = ()> + Read<Error = Infallible, Metadata = ()>,
    >,
{
    let mut frames = Vec::new();
    let mut frame = request.frame();
    loop {
        let class = match frame.frame_type() {
            FrameType::Known(_) => 'K',
            FrameType::Reserved(_) => 'R',
            FrameType::Unknown(_) => 'U',
        };
        let length = frame.length().get().get();
        let type_width = frame.r#type().width();
        let frame_type = frame.frame_type().value().get();
        let payload = match read_some(frame.payload(), 1000).await {
            Ok(payload) => payload,
            Err(error) => {
                return Started::Request {
                    frames,
                    end: error.error_code(),
                };
            }
        };
        frames.push(Seen {
            class,
            frame_type,
            type_width,
            length,
            payload,
        });
        match request.next_frame().await {
            Ok(Some(next)) => frame = next,
            Ok(None) => return Started::Request { frames, end: None },
            Err(error) => {
                return Started::Request {
                    frames,
                    end: Some(error.error_code().expect("a code")),
                };
            }
        }
    }
}

macro_rules! start {
    ($name:ident, $list:ty, $class:ty, |$stream:ident| $known:expr) => {
        #[call(sync)]
        async fn $name<
            F: Read<Error = Infallible, Metadata = ()> + Skip<Count = usize, Metadata = ()>,
            A: ReceiverAccess<Family = F>,
        >(
            io: &mut A,
            discard: bool,
        ) -> Result<Option<Started>, Failed> {
            let stream = match read_bidirectional_stream::<$list, $class, _, ()>(&mut *io).await {
                Ok(Some(stream)) => stream,
                Ok(None) => return Ok(None),
                Err(error) => return Err(failed(&error)),
            };
            Ok(Some(match stream {
                ReceivedStream::Unknown(unknown) => {
                    let value = unknown.value().get();
                    if discard {
                        unknown.discard().await.unwrap();
                    }
                    Started::Unknown { value }
                }
                ReceivedStream::Known($stream) => $known,
            }))
        }
    };
}

start!(
    read_client_plain,
    Plain,
    ClientInitiatedBidirectional,
    |known| match known {
        Coproduct::Inl(request) => request_frames(request).await,
        Coproduct::Inr(none) => match none {},
    }
);
start!(
    read_server_plain,
    Plain,
    ServerInitiatedBidirectional,
    |known| match known {
        Coproduct::Inl(none) | Coproduct::Inr(none) => match none {},
    }
);
start!(
    read_client_probing,
    Probing,
    ClientInitiatedBidirectional,
    |known| match known {
        Coproduct::Inl(request) => request_frames(request).await,
        Coproduct::Inr(Coproduct::Inl(probe)) => Started::Probe {
            skipped: probe.skipped
        },
        Coproduct::Inr(Coproduct::Inr(none)) => match none {},
    }
);
start!(
    read_server_probing,
    Probing,
    ServerInitiatedBidirectional,
    |known| match known {
        Coproduct::Inl(none) => match none {},
        Coproduct::Inr(Coproduct::Inl(probe)) => Started::Probe {
            skipped: probe.skipped
        },
        Coproduct::Inr(Coproduct::Inr(none)) => match none {},
    }
);

type Outcome = (Result<Option<Started>, Failed>, usize);

fn client(wire: &[u8], discard: bool) -> Outcome {
    let mut input = wire;
    let started = input.sync_read_client_plain_unpin(discard);
    (started, input.len())
}

fn server(wire: &[u8], discard: bool) -> Outcome {
    let mut input = wire;
    let started = input.sync_read_server_plain_unpin(discard);
    (started, input.len())
}

fn client_probing(wire: &[u8]) -> Outcome {
    let mut input = wire;
    let started = input.sync_read_client_probing_unpin(false);
    (started, input.len())
}

fn server_probing(wire: &[u8]) -> Outcome {
    let mut input = wire;
    let started = input.sync_read_server_probing_unpin(false);
    (started, input.len())
}

fn frame(frame_type: u64, payload: &[u8]) -> Seen {
    Seen {
        class: 'K',
        frame_type,
        type_width: VarIntWidth::One,
        length: payload.len() as u64,
        payload: payload.to_vec(),
    }
}

#[test]
fn a_request_stream_comes_back_at_its_first_frame_and_reads_to_its_end() {
    // HEADERS with two bytes, DATA with one, a frame of an unknown type, a
    // reserved one, and the end.
    let wire = [
        0x01, 0x02, 0xaa, 0xbb, 0x00, 0x01, 0xcc, 0x33, 0x01, 0xdd, 0x21, 0x00,
    ];
    let (started, rest) = client(&wire, false);
    assert_eq!(rest, 0);
    let Started::Request { frames, end } = started.unwrap().unwrap() else {
        panic!("not a request stream");
    };
    assert_eq!(end, None);
    assert_eq!(
        frames,
        [
            frame(0x01, &[0xaa, 0xbb]),
            frame(0x00, &[0xcc]),
            Seen {
                class: 'U',
                ..frame(0x33, &[0xdd])
            },
            Seen {
                class: 'R',
                ..frame(0x21, &[])
            },
        ]
    );
}

#[test]
fn only_the_head_of_the_first_frame_is_read_when_the_stream_comes_back() {
    // The stream is given at the first frame: its payload is still there.
    let mut input = &[0x01, 0x03, 0xaa, 0xbb, 0xcc, 0x00][..];
    let (started, rest) = {
        let started = input.sync_read_client_plain_unpin(false);
        (started, input.len())
    };
    assert!(matches!(started, Ok(Some(Started::Request { .. }))));
    assert_eq!(rest, 0);

    // Unknown: nothing after the value.
    let (started, rest) = client(&[0x33, 0x01, 0xaa], false);
    assert_eq!(started.unwrap().unwrap(), Started::Unknown { value: 0x33 });
    assert_eq!(rest, 2);
    let (_, rest) = client(&[0x33, 0x01, 0xaa], true);
    assert_eq!(rest, 0);
}

#[test]
fn reserved_frames_at_the_start_are_skipped_and_the_part_is_told() {
    // One reserved frame, with a payload; the type in two bytes (0x40 is
    // reserved: 0x1f + 0x21); several, of every width; the last with a
    // payload longer than a skip.
    let long = vec![0x55; 20_000];
    let long_head = [0x40, 0x5f, 0x80, 0x00, 0x4e, 0x20];
    let prefixes: [Vec<u8>; 4] = [
        vec![0x21, 0x02, 0xaa, 0xbb],
        vec![0x40, 0x40, 0x00],
        [
            vec![0x21, 0x00],
            vec![0x40, 0x40, 0x01, 0x01],
            vec![0x40, 0x7e, 0x00],
        ]
        .concat(),
        [&long_head[..], &long[..]].concat(),
    ];
    for prefix in prefixes {
        // The part is told: a request stream after them is read as before,
        // and the stream of the probe knows that something came before it.
        let wire = [&prefix[..], &[0x01, 0x01, 0xee]].concat();
        let (started, rest) = client(&wire, false);
        assert_eq!(rest, 0);
        let Started::Request { frames, .. } = started.unwrap().unwrap() else {
            panic!("not a request stream");
        };
        assert_eq!(frames, [frame(0x01, &[0xee])]);

        let wire = [&prefix[..], &[0x2a, 0xff]].concat();
        let (started, rest) = client_probing(&wire);
        assert_eq!(started.unwrap().unwrap(), Started::Probe { skipped: true });
        assert_eq!(rest, 1);
        let (started, rest) = server_probing(&wire);
        assert_eq!(started.unwrap().unwrap(), Started::Probe { skipped: true });
        assert_eq!(rest, 1);

        let wire = [&prefix[..], &[0x33]].concat();
        let (started, _) = client(&wire, true);
        assert_eq!(started.unwrap().unwrap(), Started::Unknown { value: 0x33 });
    }
    // Nothing skipped: the part is told so.
    let (started, rest) = client_probing(&[0x2a, 0xff]);
    assert_eq!(started.unwrap().unwrap(), Started::Probe { skipped: false });
    assert_eq!(rest, 1);
    let (started, _) = server_probing(&[0x2a]);
    assert_eq!(started.unwrap().unwrap(), Started::Probe { skipped: false });
    // The value 0x2a means nothing to a list without the probe.
    let (started, _) = client(&[0x2a, 0x00], false);
    assert_eq!(started.unwrap().unwrap(), Started::Unknown { value: 0x2a });
}

#[test]
fn a_request_stream_after_reserved_frames_has_the_widths_it_had() {
    // The Type of HEADERS in two bytes, after a reserved frame.
    let wire = [0x21, 0x00, 0x40, 0x01, 0x00];
    let (started, _) = client(&wire, false);
    let Started::Request { frames, .. } = started.unwrap().unwrap() else {
        panic!("not a request stream");
    };
    assert_eq!(
        frames,
        [Seen {
            type_width: VarIntWidth::Two,
            ..frame(0x01, &[])
        }]
    );
}

#[test]
fn frame_types_a_request_stream_may_not_start_with_are_rejected() {
    let cases: [(u8, &str, Reason); 11] = [
        (0x02, "HTTP/2 PRIORITY", Reason::Http2Type),
        (0x06, "HTTP/2 PING", Reason::Http2Type),
        (0x08, "HTTP/2 WINDOW_UPDATE", Reason::Http2Type),
        (0x09, "HTTP/2 CONTINUATION", Reason::Http2Type),
        // Frames of HTTP/3 for other streams.
        (0x03, "CANCEL_PUSH", Reason::NotAllowedOnStream),
        (0x04, "SETTINGS", Reason::NotAllowedOnStream),
        (0x07, "GOAWAY", Reason::NotAllowedOnStream),
        (0x0d, "MAX_PUSH_ID", Reason::NotAllowedOnStream),
        // Only a client receives PUSH_PROMISE, and a server receives the
        // streams a client opens.
        (0x05, "PUSH_PROMISE", Reason::NotReceivableByRole),
        (0x02, "again, after a reserved frame", Reason::Http2Type),
        (
            0x04,
            "again, after a reserved frame",
            Reason::NotAllowedOnStream,
        ),
    ];
    for (index, (value, name, reason)) in cases.into_iter().enumerate() {
        let prefix: &[u8] = if index >= 9 { &[0x21, 0x00] } else { &[] };
        let wire = [prefix, &[value, 0x00, 0xaa]].concat();
        let (started, rest) = client(&wire, false);
        assert_eq!(
            started.unwrap_err(),
            Failed::Rejected {
                value: u64::from(value),
                code: ErrorCode::H3_FRAME_UNEXPECTED,
                reason
            },
            "{name}"
        );
        // Only the value was read, the Length was not.
        assert_eq!(rest, 2, "{name}");
        // With the probe in the list, the verdict is the same.
        let (started, _) = client_probing(&wire);
        assert!(matches!(started, Err(Failed::Rejected { .. })), "{name}");
    }
}

#[test]
fn values_no_part_claims_are_unknown_streams_that_are_discarded_to_the_end() {
    let values: [(&[u8], u64); 6] = [
        (&[0x0a], 0x0a),
        (&[0x20], 0x20),
        (&[0x22], 0x22),
        (&[0x33], 0x33),
        (&[0x7f, 0xff], 0x3fff),
        (&[0xff; 8], (1 << 62) - 1),
    ];
    for (value, expected) in values {
        let wire = [value, &[0x00, 0xaa, 0xbb]].concat();
        let (started, rest) = client(&wire, false);
        assert_eq!(
            started.unwrap().unwrap(),
            Started::Unknown { value: expected }
        );
        assert_eq!(rest, 3);
        let (started, rest) = client(&wire, true);
        assert!(matches!(started, Ok(Some(Started::Unknown { .. }))));
        assert_eq!(rest, 0);
    }
}

/// Writes every frame of the request stream in the first receiver to the
/// second, as the frames are read.
#[call(sync)]
async fn rewrite<
    R: Read<Error = Infallible, Metadata = ()> + Skip<Count = usize, Metadata = ()>,
    A: ReceiverAccess<Family = R>,
    W: Write<Report = ()>,
    B: ReceiverAccess<Family = W>,
>(
    io: &mut A,
    out: &mut B,
) where
    W::Error: core::fmt::Debug,
{
    let Some(ReceivedStream::Known(Coproduct::Inl(mut request))) =
        read_bidirectional_stream::<Plain, ClientInitiatedBidirectional, _, ()>(&mut *io)
            .await
            .unwrap()
    else {
        panic!("not a request stream");
    };
    loop {
        let frame = request.frame().map_payload(|payload| Buffered {
            source: payload,
            buffer: [0u8; 5],
        });
        out.encode(frame).await.unwrap();
        if request.next_frame().await.unwrap().is_none() {
            break;
        }
    }
}

#[test]
fn the_frames_of_a_request_stream_are_written_back_as_the_bytes_they_were_read_from() {
    // Types and Lengths of every width, known, unknown and reserved types.
    let frames = [
        &[0x40, 0x01, 0xc0, 0, 0, 0, 0, 0, 0, 0x02, 0xaa, 0xbb][..],
        &[0x00, 0x01, 0xcc],
        &[0x80, 0x00, 0x00, 0x33, 0x40, 0x00],
        &[0x33, 0x00],
        &[0x21, 0x01, 0xdd],
        &[0x40, 0x40, 0x00],
        &[0x00, 0x00],
    ];
    let wire = [&[0x21, 0x00][..], &frames.concat()].concat();
    // The reserved frames before the first value are not part of the stream.
    let mut hosts = (&wire[..], Vec::<u8>::new());
    hosts.sync_rewrite_unpin();
    assert_eq!(hosts.0, [] as [u8; 0]);
    assert_eq!(hosts.1, frames.concat());
}
#[test]
fn a_stream_with_nothing_but_reserved_frames_has_no_first_value() {
    for wire in [
        &[][..],
        &[0x21, 0x00],
        &[0x21, 0x01, 0xaa, 0x40, 0x40, 0x00],
    ] {
        let (started, rest) = client(wire, false);
        assert_eq!(started.unwrap(), None, "{wire:?}");
        assert_eq!(rest, 0);
        let (started, _) = server(wire, false);
        assert_eq!(started.unwrap(), None, "{wire:?}");
    }
}

#[test]
fn a_cut_start_is_an_error_with_the_code_of_the_cut() {
    // The first value cut, and the head of a reserved frame cut.
    for wire in [
        &[0x40][..],
        &[0x21],
        &[0x21, 0x40],
        &[0x21, 0x00, 0x80, 0, 0],
    ] {
        let (started, _) = client(wire, false);
        let Failed::Head(code) = started.unwrap_err() else {
            panic!("{wire:?}: not a failure of the head");
        };
        assert_eq!(code, Some(ErrorCode::H3_FRAME_ERROR), "{wire:?}");
    }
    // The payload of a reserved frame cut.
    for wire in [
        &[0x21, 0x02, 0xaa][..],
        &[0x21, 0x01],
        &[0x40, 0x40, 0x05, 1, 2],
    ] {
        let (started, _) = client(wire, false);
        let Failed::ReservedPayload(code) = started.unwrap_err() else {
            panic!("{wire:?}: not a failure of the payload");
        };
        assert_eq!(code, Some(ErrorCode::H3_FRAME_ERROR), "{wire:?}");
    }
    // The first frame of a request stream cut inside its head: the part
    // that claims it could not read it.
    for wire in [&[0x01][..], &[0x00, 0x40], &[0x21, 0x00, 0x01]] {
        let (started, _) = client(wire, false);
        assert_eq!(
            started.unwrap_err(),
            Failed::Part(Some(ErrorCode::H3_FRAME_ERROR)),
            "{wire:?}"
        );
    }
}

#[test]
fn a_request_stream_cut_inside_a_later_frame_ends_with_the_code_of_the_cut() {
    // The wire, the frames read before the failure, and its code.
    let cases: [(&[u8], usize, ErrorCode); 5] = [
        // Inside the payload of the first frame.
        (&[0x01, 0x02, 0xaa], 0, ErrorCode::H3_FRAME_ERROR),
        // Inside the Length of the next frame, and inside its payload.
        (&[0x01, 0x00, 0x00, 0x40], 1, ErrorCode::H3_FRAME_ERROR),
        (&[0x01, 0x00, 0x00, 0x01], 1, ErrorCode::H3_FRAME_ERROR),
        // Inside the payload of the next frame.
        (
            &[0x01, 0x00, 0x00, 0x02, 0x00],
            1,
            ErrorCode::H3_FRAME_ERROR,
        ),
        // A frame that does not belong on the stream.
        (&[0x01, 0x00, 0x04, 0x00], 1, ErrorCode::H3_FRAME_UNEXPECTED),
    ];
    for (wire, count, code) in cases {
        let (started, _) = client(wire, false);
        let Started::Request { frames, end } = started.unwrap().unwrap() else {
            panic!("not a request stream");
        };
        assert_eq!(frames.len(), count, "{wire:?}");
        assert_eq!(end, Some(code), "{wire:?}");
    }
}

#[test]
fn http3_does_not_use_bidirectional_streams_the_server_opens() {
    // The wire, the value, and how many bytes are left after the value.
    let cases: [(&[u8], u64, usize); 6] = [
        (&[0x00], 0x00, 0),
        (&[0x01, 0x00], 0x01, 1),
        (&[0x04, 0x00], 0x04, 1),
        (&[0x33], 0x33, 0),
        (&[0x2a, 0x07], 0x2a, 1),
        (&[0x21, 0x00, 0x01, 0x00], 0x01, 1),
    ];
    for (wire, value, left) in cases {
        let (started, rest) = server(wire, false);
        assert_eq!(
            started.unwrap_err(),
            Failed::Rejected {
                value,
                code: ErrorCode::H3_STREAM_CREATION_ERROR,
                reason: Reason::ServerBidirectionalStream
            },
            "{wire:?}"
        );
        // Reserved frames and the value were read, nothing after.
        assert_eq!(rest, left, "{wire:?}");
    }
}

#[test]
fn an_extension_may_claim_a_stream_the_server_opens_or_reject_it() {
    // The probe claims 0x2a: the weak error of HTTP/3 gives way.
    let (started, rest) = server_probing(&[0x21, 0x00, 0x2a, 0x09]);
    assert_eq!(started.unwrap().unwrap(), Started::Probe { skipped: true });
    assert_eq!(rest, 1);
    // The probe's own error for 0x2b, on both sides.
    for read in [client_probing, server_probing] {
        let (started, _) = read(&[0x2b]);
        assert_eq!(
            started.unwrap_err(),
            Failed::Rejected {
                value: 0x2b,
                code: PROBE_ERROR,
                reason: Reason::Probe
            }
        );
    }
    // What the probe does not claim is still HTTP/3's to reject.
    let (started, _) = server_probing(&[0x2c]);
    assert_eq!(
        started.unwrap_err(),
        Failed::Rejected {
            value: 0x2c,
            code: ErrorCode::H3_STREAM_CREATION_ERROR,
            reason: Reason::ServerBidirectionalStream
        }
    );
    // On the client-initiated side it is a stream no part claims.
    let (started, _) = client_probing(&[0x2c]);
    assert_eq!(started.unwrap().unwrap(), Started::Unknown { value: 0x2c });
}

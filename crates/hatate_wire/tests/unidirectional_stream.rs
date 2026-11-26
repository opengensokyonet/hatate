#![feature(impl_trait_in_assoc_type)]
//! The start of a unidirectional stream (RFC 9114 §6.2, RFC 9204 §4.2): the
//! type, which keeps its width, what the parts of HTTP/3 make of each type in
//! each of the two classes, and the streams they give.
mod common;

use common::{next_critical_decoder, next_critical_encoder};
use core::convert::Infallible;
use frunk_core::{HList, coproduct::Coproduct};
use hatate_wire::{
    Part,
    error_code::{ErrorCode, ErrorCodeOf as _},
    frame::{Frame, FrameType},
    registry::ClaimedValue,
    stream::{
        ReceivedStream, TypedStream as _,
        class::{
            ClientInitiatedBidirectional, ClientInitiatedUnidirectional,
            ServerInitiatedBidirectional, ServerInitiatedUnidirectional, StreamClass as _,
        },
        codec::{ReadUnidirectionalStreamError, read_unidirectional_stream},
        http3::Http3UnidirectionalStream,
    },
    stream_type::Http3StreamType,
};
use hatate_wire_qpack::{
    QpackStreamType,
    stream::{QpackDecoderStream, QpackEncoderStream},
};
use nitori_call::{AsAccess, ReceiverAccess, call};
use nitori_io::{Read, ReadChunk, Skip, prelude::*};
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};

type Parts = HList![Part];
hatate_wire::assert_claims_valid!(Parts);

/// One frame read: its type and the widths of its fields, its Length and
/// its payload.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    frame_type: u64,
    type_width: VarIntWidth,
    length: u64,
    payload: Vec<u8>,
}

/// What reading the start of a unidirectional stream gave.
#[derive(Debug, PartialEq, Eq)]
enum Started {
    Control {
        type_field: Vec<u8>,
        first: Seen,
    },
    Push {
        type_field: Vec<u8>,
        push_id: u64,
        push_id_width: VarIntWidth,
        first: Seen,
    },
    QpackEncoder {
        type_field: Vec<u8>,
    },
    QpackDecoder {
        type_field: Vec<u8>,
    },
    Unknown {
        type_field: Vec<u8>,
        value: u64,
    },
}

/// What went wrong.
#[derive(Debug, PartialEq, Eq)]
enum Failed {
    /// The stream ended inside the type; how many bytes were read.
    Type { completed: usize },
    /// A part rejected the type with a code, for this reason.
    Rejected {
        value: u64,
        code: ErrorCode,
        reason: String,
    },
    /// The part that claims the type could not read the start: the code, if
    /// any, and the name of the failure.
    Part {
        code: Option<ErrorCode>,
        name: String,
    },
}

fn failed<
    E: hatate_wire::error_code::ErrorCodeOf<ErrorCode>,
    P: hatate_wire::error_code::ErrorCodeOf<ErrorCode> + core::fmt::Debug,
    R: hatate_wire::error_code::ErrorCodeOf<ErrorCode> + core::fmt::Debug,
>(
    error: &ReadUnidirectionalStreamError<E, P, R>,
) -> Failed {
    match error {
        ReadUnidirectionalStreamError::Type { source } => {
            assert!(source.is_incomplete());
            assert_eq!(error.error_code(), None);
            Failed::Type {
                completed: source.completed(),
            }
        }
        ReadUnidirectionalStreamError::Rejected {
            stream_type,
            source,
        } => Failed::Rejected {
            value: stream_type.get(),
            code: error.error_code().expect("a rejection has a code"),
            reason: format!("{:?}", source.get()),
        },
        ReadUnidirectionalStreamError::Part { source } => Failed::Part {
            code: error.error_code(),
            name: format!("{source:?}"),
        },
    }
}

fn field_bytes(field: VarIntField<VarInt>) -> Vec<u8> {
    let (bytes, length) = field.to_encoding();
    bytes[..length].to_vec()
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

async fn seen<T: ClaimedValue + Copy, P: AsAccess<Family: Read<Metadata = ()>>>(
    mut frame: Frame<FrameType<T>, P>,
) -> Seen
where
    <P::Family as Read>::Error: core::fmt::Debug,
{
    let length = frame.length().get().get();
    let payload = read_some(frame.payload(), 1000).await.unwrap();
    Seen {
        frame_type: frame.frame_type().value().get(),
        type_width: frame.r#type().width(),
        length,
        payload,
    }
}

/// Reads the start of a stream of the class `$class`; `discard` discards a
/// stream that no part claims.
macro_rules! start {
    ($name:ident, $class:ty) => {
        #[call(sync)]
        async fn $name<
            F: Read<Error = Infallible, Metadata = ()> + Skip<Count = usize, Metadata = ()>,
            A: ReceiverAccess<Family = F>,
        >(
            io: &mut A,
            discard: bool,
        ) -> Result<Option<Started>, Failed> {
            let stream = match read_unidirectional_stream::<Parts, $class, _, ()>(&mut *io).await {
                Ok(Some(stream)) => stream,
                Ok(None) => return Ok(None),
                Err(error) => return Err(failed(&error)),
            };
            Ok(Some(match stream.transpose() {
                ReceivedStream::Unknown(unknown) => {
                    let type_field = field_bytes(unknown.type_field());
                    let value = unknown.stream().stream_type().get();
                    if discard {
                        unknown.into_stream().discard().await.unwrap();
                    }
                    Started::Unknown { type_field, value }
                }
                ReceivedStream::Known(known) => match known.transpose() {
                    Coproduct::Inr(none) => match none.into_stream() {},
                    Coproduct::Inl(http3) => match http3.transpose() {
                        Http3UnidirectionalStream::Control(stream) => {
                            let type_field = field_bytes(stream.type_field());
                            let mut control = stream.into_stream();
                            let first = seen(control.frame()).await;
                            Started::Control { type_field, first }
                        }
                        Http3UnidirectionalStream::Push(stream) => {
                            let type_field = field_bytes(stream.type_field());
                            let mut push = stream.into_stream();
                            let push_id = push.push_id();
                            let first = seen(push.frames().frame()).await;
                            Started::Push {
                                type_field,
                                push_id: push_id.get().get().get(),
                                push_id_width: push_id.width(),
                                first,
                            }
                        }
                        Http3UnidirectionalStream::QpackEncoder(stream) => Started::QpackEncoder {
                            type_field: field_bytes(stream.type_field()),
                        },
                        Http3UnidirectionalStream::QpackDecoder(stream) => Started::QpackDecoder {
                            type_field: field_bytes(stream.type_field()),
                        },
                    },
                },
            }))
        }
    };
}

start!(start_from_client, ClientInitiatedUnidirectional);
start!(start_from_server, ServerInitiatedUnidirectional);

fn read_from_client(wire: &[u8], discard: bool) -> (Result<Option<Started>, Failed>, usize) {
    let mut input = wire;
    let started = input.sync_start_from_client_unpin(discard);
    (started, input.len())
}

fn read_from_server(wire: &[u8], discard: bool) -> (Result<Option<Started>, Failed>, usize) {
    let mut input = wire;
    let started = input.sync_start_from_server_unpin(discard);
    (started, input.len())
}

fn first(frame_type: u64, length: u64, payload: &[u8]) -> Seen {
    Seen {
        frame_type,
        type_width: VarIntWidth::One,
        length,
        payload: payload.to_vec(),
    }
}

#[test]
fn the_receiver_of_each_class_is_the_peer_of_the_one_that_opens_it() {
    assert_eq!(
        ClientInitiatedBidirectional::INITIATOR,
        hatate_wire::Role::Client
    );
    assert_eq!(
        ClientInitiatedBidirectional::RECEIVER,
        hatate_wire::Role::Server
    );
    assert_eq!(
        ClientInitiatedUnidirectional::INITIATOR,
        hatate_wire::Role::Client
    );
    assert_eq!(
        ClientInitiatedUnidirectional::RECEIVER,
        hatate_wire::Role::Server
    );
    assert_eq!(
        ServerInitiatedBidirectional::INITIATOR,
        hatate_wire::Role::Server
    );
    assert_eq!(
        ServerInitiatedBidirectional::RECEIVER,
        hatate_wire::Role::Client
    );
    assert_eq!(
        ServerInitiatedUnidirectional::INITIATOR,
        hatate_wire::Role::Server
    );
    assert_eq!(
        ServerInitiatedUnidirectional::RECEIVER,
        hatate_wire::Role::Client
    );
}

#[test]
fn a_control_stream_comes_back_at_its_first_frame_from_either_side() {
    // A SETTINGS frame without settings, and a byte of the next frame.
    let wire = [0x00, 0x04, 0x00, 0x07];
    for read in [read_from_client, read_from_server] {
        let (started, rest) = read(&wire, false);
        assert_eq!(
            started.unwrap().unwrap(),
            Started::Control {
                type_field: vec![0x00],
                first: first(0x04, 0, &[]),
            }
        );
        // The type and the head of the first frame were read, nothing more.
        assert_eq!(rest, 1);
    }
}

#[test]
fn a_push_stream_has_its_push_id_and_first_frame_when_a_server_opens_it() {
    let wire = [0x01, 0x09, 0x01, 0x02, 0xaa, 0xbb, 0xcc];
    let (started, rest) = read_from_server(&wire, false);
    assert_eq!(
        started.unwrap().unwrap(),
        Started::Push {
            type_field: vec![0x01],
            push_id: 9,
            push_id_width: VarIntWidth::One,
            first: first(0x01, 2, &[0xaa, 0xbb]),
        }
    );
    // The payload was read by the test, the byte after it is left.
    assert_eq!(rest, 1);
}

#[test]
fn a_client_may_not_open_a_push_stream() {
    for wire in [&[0x01][..], &[0x01, 0x00, 0x00, 0x00], &[0x40, 0x01]] {
        let (started, rest) = read_from_client(wire, false);
        assert_eq!(
            started.unwrap_err(),
            Failed::Rejected {
                value: 1,
                code: ErrorCode::H3_STREAM_CREATION_ERROR,
                // The part of HTTP/3 is the only part of the list.
                reason: "Inl(ClientPushStreamError)".to_owned()
            }
        );
        // Only the type was read.
        assert_eq!(rest, wire.len() - if wire[0] == 0x40 { 2 } else { 1 });
    }
}

#[test]
fn the_two_qpack_streams_are_given_without_reading_an_instruction() {
    for read in [read_from_client, read_from_server] {
        let (started, rest) = read(&[0x02, 0x25, 0x01], false);
        assert_eq!(
            started.unwrap().unwrap(),
            Started::QpackEncoder {
                type_field: vec![0x02]
            }
        );
        assert_eq!(rest, 2);
        let (started, rest) = read(&[0x03, 0x05], false);
        assert_eq!(
            started.unwrap().unwrap(),
            Started::QpackDecoder {
                type_field: vec![0x03]
            }
        );
        assert_eq!(rest, 1);
    }
}

#[test]
fn types_no_part_claims_come_back_unknown_and_are_discarded_to_the_end() {
    let cases: [(&[u8], u64); 6] = [
        (&[0x04], 0x04),
        (&[0x21], 0x21),
        (&[0x40, 0x40], 0x40),
        (&[0x7f, 0xff], 0x3fff),
        (&[0xbf, 0xff, 0xff, 0xff], 0x3fff_ffff),
        (&[0xff; 8], (1 << 62) - 1),
    ];
    for (type_field, value) in cases {
        let wire = [type_field, &[0xde, 0xad, 0xbe, 0xef]].concat();
        for read in [read_from_client, read_from_server] {
            let (started, rest) = read(&wire, false);
            assert_eq!(
                started.unwrap().unwrap(),
                Started::Unknown {
                    type_field: type_field.to_vec(),
                    value
                }
            );
            assert_eq!(rest, 4, "nothing but the type is read");
            let (started, rest) = read(&wire, true);
            assert!(matches!(started, Ok(Some(Started::Unknown { .. }))));
            assert_eq!(rest, 0, "discarding reads to the end");
        }
    }
}

#[test]
fn reserved_types_are_unknown_like_any_other() {
    for n in [0, 1, 2, 7, 100, 1 << 20, 1 << 40] {
        let value = hatate_wire::registry::reserved(n).unwrap();
        let field = VarIntField::shortest(value);
        let (bytes, length) = field.to_encoding();
        for read in [read_from_client, read_from_server] {
            let (started, rest) = read(&bytes[..length], true);
            assert_eq!(
                started.unwrap().unwrap(),
                Started::Unknown {
                    type_field: bytes[..length].to_vec(),
                    value: value.get()
                }
            );
            assert_eq!(rest, 0);
        }
    }
}

#[test]
fn an_empty_stream_has_no_type_and_a_cut_type_is_an_error_without_a_code() {
    for read in [read_from_client, read_from_server] {
        let (started, _) = read(&[], false);
        assert_eq!(started.unwrap(), None);
        let cases: [(&[u8], usize); 4] = [
            (&[0x40], 1),
            (&[0x80, 0, 0], 3),
            (&[0xc0, 0, 0, 0], 4),
            (&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 7),
        ];
        for (wire, completed) in cases {
            let (started, _) = read(wire, false);
            assert_eq!(started.unwrap_err(), Failed::Type { completed });
        }
    }
}

#[test]
fn a_control_stream_that_ends_before_its_first_frame_is_a_closed_critical_stream() {
    for read in [read_from_client, read_from_server] {
        let (started, _) = read(&[0x00], false);
        let Failed::Part { code, name } = started.unwrap_err() else {
            panic!("not a failure of the part");
        };
        assert_eq!(code, Some(ErrorCode::H3_CLOSED_CRITICAL_STREAM));
        assert!(name.contains("Control"), "{name}");
    }
}

#[test]
fn the_first_frame_of_a_control_stream_is_checked_for_the_stream_and_the_receiver() {
    let cases: [(&[u8], Option<ErrorCode>); 8] = [
        // HTTP/2's types.
        (&[0x00, 0x02, 0x00], Some(ErrorCode::H3_FRAME_UNEXPECTED)),
        (&[0x00, 0x09, 0x00], Some(ErrorCode::H3_FRAME_UNEXPECTED)),
        // Frames of the request and push streams.
        (&[0x00, 0x00, 0x00], Some(ErrorCode::H3_FRAME_UNEXPECTED)),
        (&[0x00, 0x01, 0x00], Some(ErrorCode::H3_FRAME_UNEXPECTED)),
        (
            &[0x00, 0x05, 0x01, 0x00],
            Some(ErrorCode::H3_FRAME_UNEXPECTED),
        ),
        // A head cut inside the Type or the Length.
        // The control stream is critical: the end is H3_CLOSED_CRITICAL_STREAM.
        (&[0x00, 0x40], Some(ErrorCode::H3_CLOSED_CRITICAL_STREAM)),
        (&[0x00, 0x04], Some(ErrorCode::H3_CLOSED_CRITICAL_STREAM)),
        (
            &[0x00, 0x04, 0x40],
            Some(ErrorCode::H3_CLOSED_CRITICAL_STREAM),
        ),
    ];
    for (wire, code) in cases {
        for read in [read_from_client, read_from_server] {
            let (started, _) = read(wire, false);
            let Failed::Part { code: found, name } = started.unwrap_err() else {
                panic!("{wire:?}: not a failure of the part");
            };
            assert_eq!(found, code, "{wire:?}: {name}");
        }
    }
    // MAX_PUSH_ID is received by a server only, and the stream a client
    // opened is received by one: its head is accepted there, and it is not
    // SETTINGS (see `control_stream.rs`). The client rejects the head.
    let wire = [0x00, 0x0d, 0x01, 0x00];
    let (started, _) = read_from_client(&wire, false);
    let Failed::Part { code, name } = started.unwrap_err() else {
        panic!("not a failure of the part");
    };
    assert_eq!(code, Some(ErrorCode::H3_MISSING_SETTINGS));
    assert!(name.contains("MissingSettings"), "{name}");
    let (started, _) = read_from_server(&wire, false);
    let Failed::Part { code, name } = started.unwrap_err() else {
        panic!("not a failure of the part");
    };
    assert_eq!(code, Some(ErrorCode::H3_FRAME_UNEXPECTED));
    assert!(name.contains("Control"), "{name}");
}

#[test]
fn a_cut_push_id_or_a_push_stream_without_frames_is_an_error_without_a_code() {
    for wire in [
        &[0x01][..],
        &[0x01, 0x40],
        &[0x01, 0xc0, 0, 0],
        &[0x01, 0x00],
    ] {
        let (started, _) = read_from_server(wire, false);
        let Failed::Part { code, name } = started.unwrap_err() else {
            panic!("{wire:?}: not a failure of the part");
        };
        assert_eq!(code, None, "{wire:?}: {name}");
    }
    // A frame that may not be on a push stream, and a cut head.
    let cases: [(&[u8], ErrorCode); 4] = [
        (
            &[0x01, 0x00, 0x05, 0x01, 0x00],
            ErrorCode::H3_FRAME_UNEXPECTED,
        ),
        (&[0x01, 0x00, 0x04, 0x00], ErrorCode::H3_FRAME_UNEXPECTED),
        (&[0x01, 0x00, 0x06, 0x00], ErrorCode::H3_FRAME_UNEXPECTED),
        (&[0x01, 0x00, 0x00], ErrorCode::H3_FRAME_ERROR),
    ];
    for (wire, code) in cases {
        let (started, _) = read_from_server(wire, false);
        let Failed::Part { code: found, name } = started.unwrap_err() else {
            panic!("{wire:?}: not a failure of the part");
        };
        assert_eq!(found, Some(code), "{wire:?}: {name}");
    }
}

#[test]
fn the_width_of_the_type_and_of_the_push_id_is_kept_and_written_back() {
    for width in VarIntWidth::ALL {
        let encode = |value: u32| {
            let (bytes, length) = VarIntField::new(VarInt::from_u32(value), width)
                .unwrap()
                .to_encoding();
            bytes[..length].to_vec()
        };
        // Each of the four types, and an unknown one.
        let streams = [
            (0x00, vec![0x04, 0x00]),
            (0x01, vec![0x05, 0x01, 0x00]),
            (0x02, vec![]),
            (0x03, vec![]),
            (0x33, vec![]),
        ];
        for (value, after) in streams {
            let type_field = encode(value);
            let wire = [&type_field[..], &after].concat();
            let (started, _) = read_from_server(&wire, false);
            let started = started.unwrap().unwrap();
            let written = match started {
                Started::Control { type_field, .. }
                | Started::QpackEncoder { type_field }
                | Started::QpackDecoder { type_field }
                | Started::Unknown { type_field, .. } => type_field,
                Started::Push {
                    type_field,
                    push_id,
                    push_id_width,
                    ..
                } => {
                    assert_eq!(push_id, 5);
                    assert_eq!(push_id_width, VarIntWidth::One);
                    type_field
                }
            };
            assert_eq!(written, encode(value), "type {value} at {width:?}");
            assert_eq!(written.len(), 1 << (width as usize).min(3));
        }
        // The Push ID keeps its width as well.
        let push_id = encode(5);
        let wire = [&[0x01][..], &push_id, &[0x00, 0x00]].concat();
        let (started, _) = read_from_server(&wire, false);
        let Some(Started::Push {
            push_id,
            push_id_width,
            ..
        }) = started.unwrap()
        else {
            panic!("not a push stream");
        };
        assert_eq!(push_id, 5);
        assert_eq!(push_id_width, width);
    }
}

#[test]
fn the_types_of_http3_and_qpack_are_the_four_values() {
    let expected = [
        (0x00, Http3StreamType::Control),
        (0x01, Http3StreamType::Push),
        (0x02, Http3StreamType::Qpack(QpackStreamType::Encoder)),
        (0x03, Http3StreamType::Qpack(QpackStreamType::Decoder)),
    ];
    for (value, stream_type) in expected {
        assert_eq!(stream_type.value().get(), value);
        assert_eq!(
            Http3StreamType::of(VarInt::from_u32(value as u32)),
            Some(stream_type)
        );
    }
    assert_eq!(
        Http3StreamType::ALL
            .map(Http3StreamType::value)
            .map(VarInt::get),
        [0, 1, 2, 3]
    );
    assert_eq!(Http3StreamType::of(VarInt::from_u32(4)), None);
}

/// How reading a critical stream ended.
#[derive(Debug, PartialEq, Eq)]
enum End {
    /// The stream ended, at a boundary or inside a frame or instruction:
    /// H3_CLOSED_CRITICAL_STREAM.
    Closed,
    /// Another failure, with its code.
    Failed(Option<ErrorCode>),
}

fn ended(code: Option<ErrorCode>) -> End {
    if code == Some(ErrorCode::H3_CLOSED_CRITICAL_STREAM) {
        End::Closed
    } else {
        End::Failed(code)
    }
}

/// Reads the frames of a control stream a server opened, the first and then
/// each next one, until the stream fails or ends; `known` skips the reserved
/// and unknown ones after the first.
#[call(sync)]
async fn control_frames<
    F: Read<Error = Infallible, Metadata = ()> + Skip<Count = usize, Metadata = ()>,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
    known: bool,
) -> (Vec<u64>, End) {
    let stream =
        read_unidirectional_stream::<Parts, ServerInitiatedUnidirectional, _, ()>(&mut *io)
            .await
            .unwrap()
            .unwrap();
    let ReceivedStream::Known(known_stream) = stream.transpose() else {
        panic!("not a stream of a part");
    };
    let Coproduct::Inl(http3) = known_stream.transpose() else {
        unreachable!("one part");
    };
    let Http3UnidirectionalStream::Control(control) = http3.transpose() else {
        panic!("not a control stream");
    };
    let mut control = control.into_stream();
    let mut types = vec![control.frame().frame_type().value().get()];
    loop {
        let next = if known {
            control.next_known_frame().await
        } else {
            control.next_frame().await
        };
        match next {
            Ok(frame) => types.push(frame.frame_type().value().get()),
            Err(error) => return (types, ended(error.error_code())),
        }
    }
}

#[test]
fn a_control_stream_that_ends_after_a_frame_is_a_closed_critical_stream() {
    let wire = [
        0x00, 0x04, 0x00, 0x21, 0x01, 0xaa, 0x33, 0x00, 0x07, 0x01, 0x00,
    ];
    let mut input = &wire[..];
    let (types, end) = input.sync_control_frames_unpin(false);
    assert_eq!(types, [0x04, 0x21, 0x33, 0x07]);
    assert_eq!(end, End::Closed);

    // Skipping the reserved and unknown frames after the first.
    let mut input = &wire[..];
    let (types, end) = input.sync_control_frames_unpin(true);
    assert_eq!(types, [0x04, 0x07]);
    assert_eq!(end, End::Closed);

    // Only the first frame.
    let mut input = &[0x00, 0x04, 0x00][..];
    assert_eq!(
        input.sync_control_frames_unpin(false),
        (vec![0x04], End::Closed)
    );
}

#[test]
fn a_control_stream_cut_inside_a_frame_is_a_closed_critical_stream() {
    // Inside the payload of the first frame, which is skipped to get to the
    // next, and inside the head of the next.
    for wire in [
        &[0x00, 0x04, 0x02, 0xaa][..],
        &[0x00, 0x04, 0x00, 0x07],
        &[0x00, 0x04, 0x00, 0x40],
    ] {
        let mut input = wire;
        let (types, end) = input.sync_control_frames_unpin(false);
        assert_eq!(types, [0x04], "{wire:?}");
        assert_eq!(end, End::Closed, "{wire:?}");
    }
}

/// The instructions of a QPACK stream the peer opened, as text, until the
/// stream fails or ends.
#[call(sync)]
async fn qpack_instructions<
    F: Read<Error = !, Metadata = ()> + ReadChunk<Metadata = ()> + Skip<Count = usize, Metadata = ()>,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
) -> (Vec<String>, End) {
    let stream =
        read_unidirectional_stream::<Parts, ServerInitiatedUnidirectional, _, ()>(&mut *io)
            .await
            .unwrap()
            .unwrap();
    let ReceivedStream::Known(known_stream) = stream.transpose() else {
        panic!("not a stream of a part");
    };
    let Coproduct::Inl(http3) = known_stream.transpose() else {
        unreachable!("one part");
    };
    let mut seen = Vec::new();
    match http3.transpose() {
        Http3UnidirectionalStream::QpackEncoder(stream) => {
            let mut stream: QpackEncoderStream<_> = stream.into_stream();
            loop {
                match next_critical_encoder(&mut stream, 1032).await {
                    Ok(started) => {
                        // The variants of the instruction belong to hatate_qpack.
                        drop(started);
                        seen.push("instruction".to_string());
                    }
                    Err(error) => return (seen, ended(error.error_code())),
                }
            }
        }
        Http3UnidirectionalStream::QpackDecoder(stream) => {
            let mut stream: QpackDecoderStream<_> = stream.into_stream();
            loop {
                match next_critical_decoder(&mut stream, 1000).await {
                    Ok(instruction) => seen.push(format!("{instruction:?}")),
                    Err(error) => return (seen, ended(error.error_code())),
                }
            }
        }
        _ => panic!("not a QPACK stream"),
    }
}

#[test]
fn the_two_qpack_streams_end_only_as_a_closed_critical_stream() {
    let mut input = &[0x02, 0x25, 0x01][..];
    let (seen, end) = input.sync_qpack_instructions_unpin();
    assert_eq!(seen.len(), 2);
    assert_eq!(end, End::Closed);
    let mut input = &[0x02][..];
    assert_eq!(input.sync_qpack_instructions_unpin(), (vec![], End::Closed));

    // Insert Count Increment 5, Stream Cancellation of stream 1.
    let mut input = &[0x03, 0x05, 0x41][..];
    let (seen, end) = input.sync_qpack_instructions_unpin();
    assert_eq!(
        seen,
        [
            "InsertCountIncrement { increment: PrefixedField { value: Increment(5), padding: 0 } }",
            "StreamCancellation { stream_id: PrefixedField { value: StreamId(1), padding: 0 } }"
        ]
        .map(String::from)
        .to_vec()
    );
    assert_eq!(end, End::Closed);
    let mut input = &[0x03][..];
    assert_eq!(input.sync_qpack_instructions_unpin(), (vec![], End::Closed));
}

#[test]
fn a_qpack_instruction_cut_in_the_middle_is_a_closed_critical_stream() {
    // The first byte of an integer that goes on, then the end.
    for wire in [&[0x02, 0x3f][..], &[0x03, 0x3f]] {
        let mut input = wire;
        let (seen, end) = input.sync_qpack_instructions_unpin();
        assert!(seen.is_empty(), "{wire:?}");
        assert_eq!(end, End::Closed, "{wire:?}");
    }
}

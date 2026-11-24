#![feature(impl_trait_in_assoc_type)]
//! Reading the head of a frame: RFC 9114 §7.1, §7.2.8 and §9.
//!
//! `read_frame` reads any Type and Length from any readable source;
//! `read_received_frame` is for a stream that carries frames and looks the
//! Type up and checks it.
mod common;

use common::{Dribble, run};
use frunk_core::{HList, coproduct::Coproduct};
use hatate_wire::{
    Role,
    error_code::{ErrorCode, ErrorCodeOf as _},
    frame::{
        FrameType, FrameWidths, Http2FrameType, Http3FrameType,
        codec::{
            ReadFrameError, ReadReceivedFrameError, WriteFrameHeadHostExt as _, read_frame,
            read_received_frame,
        },
        set::{FrameSet, FrameStreamKind},
    },
    stream::FrameStream,
};
use nitori_call::{ReceiverAccess, call};
use nitori_io::Read;
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};

type Parts = HList![hatate_wire::Part];
hatate_wire::assert_claims_valid!(Parts);
type Value = <Parts as FrameSet>::TypeValue;

/// What a frame read says of its head.
#[derive(Debug, PartialEq, Eq)]
struct Head {
    type_field: VarIntField<VarInt>,
    length: VarIntField<VarInt>,
    widths: FrameWidths,
    /// The payload still to be read, as the frame holds it.
    remaining: u64,
}

/// A `read_received_frame` result in the form the tests compare.
#[derive(Debug, PartialEq, Eq)]
struct Received {
    frame_type: FrameType<Value>,
    head: Head,
}

type RawResult<E> = Result<Option<Head>, ReadFrameError<E>>;
type ReceivedResult<E> = Result<Option<Received>, ReadReceivedFrameError<E, Value>>;

/// Reads a frame from any readable source and reports its head.
#[call(sync)]
async fn read_raw<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> RawResult<<F as Read>::Error> {
    let Some(frame) = read_frame(&mut *io).await? else {
        return Ok(None);
    };
    Ok(Some(Head {
        type_field: frame.r#type(),
        length: frame.length(),
        widths: frame.widths(),
        remaining: frame.into_payload().into_parts().1.remaining(),
    }))
}

/// Reads a frame from a stream of this kind and role that carries frames.
#[call(sync)]
async fn read_on<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    kind: FrameStreamKind,
    role: Role,
) -> ReceivedResult<<F as Read>::Error> {
    let io = io.compose(FrameStream::<Parts>::new(kind, role));
    let Some(frame) = read_received_frame(io).await? else {
        return Ok(None);
    };
    let frame_type = frame.frame_type();
    let frame = frame.into_frame();
    Ok(Some(Received {
        frame_type,
        head: Head {
            type_field: frame.r#type(),
            length: frame.length(),
            widths: frame.widths(),
            remaining: frame.into_payload().into_parts().1.remaining(),
        },
    }))
}

fn control() -> FrameStreamKind {
    FrameStreamKind::Unidirectional(VarInt::from_u32(0x00))
}

fn raw(mut input: &[u8]) -> RawResult<core::convert::Infallible> {
    input.sync_read_raw_unpin()
}

/// Reads on a request stream of a server, which may receive every frame of
/// RFC 9114 on it except PUSH_PROMISE; for unknown and HTTP/2 types.
fn on_request(mut input: &[u8]) -> ReceivedResult<core::convert::Infallible> {
    input.sync_read_on_unpin(FrameStreamKind::Request, Role::Server)
}

fn var_int(value: u64, width: VarIntWidth) -> Vec<u8> {
    let (bytes, len) = VarIntField::new(VarInt::new(value).unwrap(), width)
        .unwrap()
        .to_encoding();
    bytes[..len].to_vec()
}

#[test]
fn the_seven_types_of_rfc_9114_are_known_where_they_may_arrive() {
    for frame_type in Http3FrameType::ALL {
        // A stream and a role that may receive the type.
        let (kind, role) = match frame_type {
            Http3FrameType::Data | Http3FrameType::Headers => {
                (FrameStreamKind::Request, Role::Server)
            }
            Http3FrameType::PushPromise => (FrameStreamKind::Request, Role::Client),
            Http3FrameType::MaxPushId => (control(), Role::Server),
            Http3FrameType::CancelPush | Http3FrameType::Settings | Http3FrameType::Goaway => {
                (control(), Role::Client)
            }
        };
        let wire = [frame_type.value().get() as u8, 0x03];
        let mut input = &wire[..];
        let received = input.sync_read_on_unpin(kind, role).unwrap().unwrap();
        assert_eq!(
            received.frame_type,
            FrameType::Known(Coproduct::Inl(frame_type))
        );
        assert_eq!(received.head.length.get().get(), 3);
        assert_eq!(received.head.widths, FrameWidths::SHORTEST);
        assert_eq!(received.head.remaining, 3);
        assert!(input.is_empty());
    }
}

#[test]
fn reading_without_a_stream_looks_nothing_up() {
    for frame_type in Http3FrameType::ALL {
        let wire = [frame_type.value().get() as u8, 0x03];
        let head = raw(&wire).unwrap().unwrap();
        assert_eq!(head.type_field.get(), frame_type.value());
        assert_eq!(head.length.get().get(), 3);
        assert_eq!(head.widths, FrameWidths::SHORTEST);
        assert_eq!(head.remaining, 3);
    }
}

#[test]
fn reserved_and_undeclared_types_are_unknown() {
    // 0x0a, 0x0b: undeclared; 0x0e: undeclared above MAX_PUSH_ID; 0x21, 0x40
    // (two bytes), 0x3fff and 2^62-1: reserved or large.
    let cases: [(u64, VarIntWidth); 7] = [
        (0x0a, VarIntWidth::One),
        (0x0b, VarIntWidth::One),
        (0x0e, VarIntWidth::One),
        (0x21, VarIntWidth::One),
        (0x40, VarIntWidth::Two),
        (0x3fff, VarIntWidth::Two),
        ((1 << 62) - 1, VarIntWidth::Eight),
    ];
    for (value, width) in cases {
        let mut wire = var_int(value, width);
        wire.push(0);
        let received = on_request(&wire).unwrap().unwrap();
        assert_eq!(
            received.frame_type,
            FrameType::Unknown(VarInt::new(value).unwrap())
        );
        assert_eq!(received.head.type_field.width(), width);
        assert_eq!(received.head.type_field.get().get(), value);
        let head = raw(&wire).unwrap().unwrap();
        assert_eq!(head, received.head);
    }
}

#[test]
fn a_known_type_in_a_wider_encoding_is_still_known() {
    for width in VarIntWidth::ALL {
        let mut wire = var_int(0x04, width);
        wire.extend([0x00]);
        let mut input = &wire[..];
        let received = input
            .sync_read_on_unpin(control(), Role::Client)
            .unwrap()
            .unwrap();
        assert_eq!(
            received.frame_type,
            FrameType::Known(Coproduct::Inl(Http3FrameType::Settings))
        );
        assert_eq!(received.head.widths.type_width(), width);
    }
}

#[test]
fn http2_types_are_a_frame_unexpected_error_before_the_length() {
    for (value, frame_type) in [
        (0x02, Http2FrameType::Priority),
        (0x06, Http2FrameType::Ping),
        (0x08, Http2FrameType::WindowUpdate),
        (0x09, Http2FrameType::Continuation),
    ] {
        for width in VarIntWidth::ALL {
            // The Length is not read: a stream that ends after the Type
            // still reports the type.
            let wire = var_int(value, width);
            let error = on_request(&wire).unwrap_err();
            assert!(
                matches!(&error, ReadReceivedFrameError::Http2Type { source } if source.frame_type() == frame_type),
                "{error:?}"
            );
            assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_UNEXPECTED));

            // Reading without a stream does not reject it.
            let mut wire = wire;
            wire.push(0);
            let head = raw(&wire).unwrap().unwrap();
            assert_eq!(head.type_field.get().get(), value);
            assert_eq!(head.type_field.width(), width);
        }
    }
}

#[test]
fn a_frame_where_it_may_not_arrive_is_a_frame_unexpected_error_before_the_length() {
    // DATA on the control stream; SETTINGS on a request stream.
    let mut input = &[0x00][..];
    let error = input
        .sync_read_on_unpin(control(), Role::Client)
        .unwrap_err();
    assert!(
        matches!(&error, ReadReceivedFrameError::NotAllowedOnStream { frame_type, stream }
            if *frame_type == Coproduct::Inl(Http3FrameType::Data) && *stream == control()),
        "{error:?}"
    );
    assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_UNEXPECTED));
    let error = on_request(&[0x04]).unwrap_err();
    assert!(
        matches!(&error, ReadReceivedFrameError::NotAllowedOnStream { stream, .. }
            if *stream == FrameStreamKind::Request),
        "{error:?}"
    );

    // PUSH_PROMISE received by a server; MAX_PUSH_ID received by a client.
    let error = on_request(&[0x05]).unwrap_err();
    assert!(
        matches!(&error, ReadReceivedFrameError::NotReceivableByRole { role, .. } if *role == Role::Server),
        "{error:?}"
    );
    assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_UNEXPECTED));
    let mut input = &[0x0d][..];
    let error = input
        .sync_read_on_unpin(control(), Role::Client)
        .unwrap_err();
    assert!(
        matches!(&error, ReadReceivedFrameError::NotReceivableByRole { role, .. } if *role == Role::Client),
        "{error:?}"
    );
}

#[test]
fn a_stream_that_ends_at_a_frame_boundary_has_no_frame() {
    assert!(raw(&[]).unwrap().is_none());
    assert!(on_request(&[]).unwrap().is_none());
}

#[test]
fn a_stream_that_ends_inside_the_head_is_a_frame_error() {
    // Inside the Type: first byte promises two, four and eight bytes.
    for wire in [&[0x40][..], &[0x80, 0, 0], &[0xc0, 0, 0, 0, 0, 0, 0]] {
        let error = raw(wire).unwrap_err();
        assert!(matches!(error, ReadFrameError::Type { .. }), "{error:?}");
        assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
        let error = on_request(wire).unwrap_err();
        assert!(
            matches!(
                error,
                ReadReceivedFrameError::Frame {
                    source: ReadFrameError::Type { .. }
                }
            ),
            "{error:?}"
        );
        assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
    }
    // The Type is complete, the Length is missing or partial.
    for wire in [
        &[0x01][..],
        &[0x01, 0x40],
        &[0x01, 0x80, 0],
        &[0x40, 0x01, 0xc0, 1],
    ] {
        let error = raw(wire).unwrap_err();
        assert!(matches!(error, ReadFrameError::Length { .. }), "{error:?}");
        assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
        let error = on_request(wire).unwrap_err();
        assert!(
            matches!(
                error,
                ReadReceivedFrameError::Frame {
                    source: ReadFrameError::Length { .. }
                }
            ),
            "{error:?}"
        );
        assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
    }
}

#[test]
fn widths_of_type_and_length_are_kept_and_written_back() {
    for type_width in VarIntWidth::ALL {
        for length_width in VarIntWidth::ALL {
            let type_field = VarIntField::new(VarInt::from_u32(0x04), type_width).unwrap();
            let length = VarIntField::new(VarInt::from_u32(0x0a), length_width).unwrap();
            let mut wire = Vec::new();
            wire.sync_write_frame_head_unpin(type_field, length)
                .unwrap();
            assert_eq!(
                wire.len(),
                type_width.encoded_len() + length_width.encoded_len()
            );
            let head = raw(&wire).unwrap().unwrap();
            assert_eq!(head.type_field, type_field);
            assert_eq!(head.length, length);
            assert_eq!(head.widths, FrameWidths::new(type_width, length_width));
            assert_eq!(head.remaining, 0x0a);
            let mut again = Vec::new();
            again
                .sync_write_frame_head_unpin(head.type_field, head.length)
                .unwrap();
            assert_eq!(again, wire);
        }
    }
}

#[test]
fn the_head_reads_the_same_with_a_pending_between_every_byte() {
    let wire = [0xc0, 0, 0, 0, 0, 0, 0, 0x07, 0x80, 0, 0x01, 0x00, 0xaa];
    let expected = raw(&wire).unwrap().unwrap();
    let mut host = Dribble::new(&wire, 1);
    let (head, pending) = run(host.read_raw_unpin());
    assert_eq!(head.unwrap().unwrap(), expected);
    assert!(pending >= 12, "{pending}");
    assert_eq!(host.rest(), [0xaa]);

    let mut host = Dribble::new(&wire, 1);
    let (received, pending) = run(host.read_on_unpin(control(), Role::Client));
    assert_eq!(received.unwrap().unwrap().head, expected);
    assert!(pending >= 12, "{pending}");
    assert_eq!(host.rest(), [0xaa]);
}

#[test]
fn only_the_head_is_consumed() {
    let mut input = &[0x01, 0x02, 0xaa, 0xbb, 0x00, 0x00][..];
    let head = input.sync_read_raw_unpin().unwrap().unwrap();
    assert_eq!(head.length.get().get(), 2);
    assert_eq!(head.remaining, 2);
    assert_eq!(input, [0xaa, 0xbb, 0x00, 0x00]);
}

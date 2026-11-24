#![feature(impl_trait_in_assoc_type)]
//! Reading the head of a frame: RFC 9114 §7.1, §7.2.8 and §9.
//!
//! A `FrameStream` reads the head of its first frame when it is made, and
//! looks the Type up and checks it against the kind of stream and the role
//! of the endpoint. A list of no parts looks nothing up.
mod common;

use common::{Dribble, Ty, known, run, ty};
use frunk_core::{HList, coproduct::Coproduct, hlist::HNil};
use hatate_wire::{
    Role,
    error_code::{ErrorCode, ErrorCodeOf as _},
    frame::{
        ControlFrameType, FrameType, FrameWidths, Http2FrameType, Http3FrameType, PushFrameType,
        RequestFrameType,
        codec::{
            ReadFrameError, ReadFrameHeadError, UnexpectedFrameTypeError,
            WriteFrameHeadHostExt as _,
        },
        set::FrameSetOn,
    },
    registry::{is_reserved, reserved},
    stream::{
        FrameStream,
        kind::{ControlStreamKind, PushStreamKind, RequestStreamKind, StreamKind},
    },
};
use nitori_call::{ReceiverAccess, call};
use nitori_io::Read;
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};

type Parts = HList![hatate_wire::Part];
hatate_wire::assert_claims_valid!(Parts);

/// What a frame read says of its head.
#[derive(Debug, PartialEq, Eq)]
struct Head {
    type_field: VarIntField<VarInt>,
    length: VarIntField<VarInt>,
    widths: FrameWidths,
    /// The payload still to be read, as the frame holds it.
    remaining: u64,
}

/// A frame read in the form the tests compare.
#[derive(Debug, PartialEq, Eq)]
struct Received {
    ty: Ty,
    head: Head,
}

type ReceivedResult<E> = Result<Option<Received>, ReadFrameHeadError<E>>;

/// Reads the first frame of a stream of kind `K`, with the parts `L`, at an
/// endpoint of this role, and reports its head.
#[call(sync)]
async fn read_on<K: StreamKind, L, F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    _kind: K,
    _parts: core::marker::PhantomData<L>,
    role: Role,
) -> ReceivedResult<<F as Read>::Error>
where
    L: FrameSetOn<K>,
{
    let Some(mut stream) = FrameStream::<L, K, _>::read(&mut *io, role).await? else {
        return Ok(None);
    };
    let frame = stream.frame();
    let type_field = frame.r#type();
    let ty = ty(type_field.get());
    let head = Head {
        type_field: VarIntField::new(frame.frame_type().value(), type_field.width()).unwrap(),
        length: frame.length(),
        widths: frame.widths(),
        remaining: frame.into_payload().into_parts().1.remaining(),
    };
    Ok(Some(Received { ty, head }))
}

fn on<K: StreamKind>(
    kind: K,
    role: Role,
    mut input: &[u8],
) -> ReceivedResult<core::convert::Infallible>
where
    Parts: FrameSetOn<K>,
{
    input.sync_read_on_unpin(kind, core::marker::PhantomData::<Parts>, role)
}

/// Reads with a list of no parts, which claims no frame type.
fn on_nothing(mut input: &[u8]) -> ReceivedResult<core::convert::Infallible> {
    input.sync_read_on_unpin(
        RequestStreamKind,
        core::marker::PhantomData::<HNil>,
        Role::Server,
    )
}

/// Reads on a request stream of a server, which may receive every frame of
/// RFC 9114 on it except PUSH_PROMISE; for unknown and HTTP/2 types.
fn on_request(input: &[u8]) -> ReceivedResult<core::convert::Infallible> {
    on(RequestStreamKind, Role::Server, input)
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
        let wire = [frame_type.value().get() as u8, 0x03];
        // The stream and the role that may receive the type.
        let received = match frame_type {
            Http3FrameType::Data | Http3FrameType::Headers => {
                // Both request and push streams carry them.
                let push = on(PushStreamKind, Role::Client, &wire).unwrap().unwrap();
                assert_eq!(push.ty, known(frame_type));
                on(RequestStreamKind, Role::Server, &wire)
            }
            Http3FrameType::PushPromise => on(RequestStreamKind, Role::Client, &wire),
            Http3FrameType::MaxPushId => on(ControlStreamKind, Role::Server, &wire),
            Http3FrameType::CancelPush | Http3FrameType::Settings | Http3FrameType::Goaway => {
                on(ControlStreamKind, Role::Client, &wire)
            }
        }
        .unwrap()
        .unwrap();
        assert_eq!(received.ty, known(frame_type));
        assert_eq!(received.head.length.get().get(), 3);
        assert_eq!(received.head.widths, FrameWidths::SHORTEST);
        assert_eq!(received.head.remaining, 3);
    }
}

#[test]
fn a_list_of_no_parts_looks_nothing_up() {
    for frame_type in Http3FrameType::ALL {
        let wire = [frame_type.value().get() as u8, 0x03];
        let received = on_nothing(&wire).unwrap().unwrap();
        // No role or kind of stream rejects it: it is unknown.
        assert_eq!(received.ty, Ty::Unknown(frame_type.value().get()));
        assert_eq!(received.head.type_field.get(), frame_type.value());
        assert_eq!(received.head.length.get().get(), 3);
        assert_eq!(received.head.widths, FrameWidths::SHORTEST);
        assert_eq!(received.head.remaining, 3);
    }
    // A type of HTTP/2 is rejected whatever the list.
    let error = on_nothing(&[0x06, 0x00]).unwrap_err();
    assert!(
        matches!(
            error,
            ReadFrameHeadError::Unexpected {
                source: UnexpectedFrameTypeError::Http2Type { .. }
            }
        ),
        "{error:?}"
    );
}

#[test]
fn types_no_part_has_are_reserved_or_unknown() {
    // 0x0a, 0x0b: undeclared; 0x0e: undeclared above MAX_PUSH_ID; 0x21, 0x40
    // (two bytes): reserved, 0x1f * N + 0x21; 0x3fff and 2^62-1: undeclared.
    let cases: [(u64, VarIntWidth, bool); 8] = [
        (0x0a, VarIntWidth::One, false),
        (0x0b, VarIntWidth::One, false),
        (0x0e, VarIntWidth::One, false),
        (0x21, VarIntWidth::One, true),
        (0x40, VarIntWidth::Two, true),
        (0x3fff, VarIntWidth::Two, false),
        ((1 << 62) - 1, VarIntWidth::Eight, false),
        (reserved(1 << 40).unwrap().get(), VarIntWidth::Eight, true),
    ];
    for (value, width, is_reserved_value) in cases {
        assert_eq!(is_reserved(VarInt::new(value).unwrap()), is_reserved_value);
        let mut wire = var_int(value, width);
        wire.push(0);
        let received = on_request(&wire).unwrap().unwrap();
        let expected = if is_reserved_value {
            Ty::Reserved(value)
        } else {
            Ty::Unknown(value)
        };
        assert_eq!(received.ty, expected, "{value:#x}");
        assert_eq!(received.head.type_field.width(), width);
        assert_eq!(received.head.type_field.get().get(), value);
        // The same on any kind of stream.
        assert_eq!(
            on(ControlStreamKind, Role::Client, &wire)
                .unwrap()
                .unwrap()
                .ty,
            expected
        );
        assert_eq!(
            on(PushStreamKind, Role::Client, &wire).unwrap().unwrap().ty,
            expected
        );
    }
}

#[test]
fn a_known_type_in_a_wider_encoding_is_still_known() {
    for width in VarIntWidth::ALL {
        let mut wire = var_int(0x04, width);
        wire.extend([0x00]);
        let received = on(ControlStreamKind, Role::Client, &wire).unwrap().unwrap();
        assert_eq!(received.ty, known(Http3FrameType::Settings));
        assert_eq!(received.head.widths.type_width(), width);
    }
}

/// Whether the first frame of a control stream is a GOAWAY of the kind of the
/// control stream.
#[call(sync)]
async fn first_is_goaway<F: Read, A: ReceiverAccess<Family = F>>(io: &mut A) -> bool {
    let Ok(Some(mut stream)) =
        FrameStream::<Parts, ControlStreamKind, _>::read(&mut *io, Role::Client).await
    else {
        panic!("no frame head");
    };
    matches!(
        stream.frame().frame_type(),
        FrameType::Known(Coproduct::Inl(ControlFrameType::Goaway))
    )
}

#[call(sync)]
async fn first_is_headers<K: StreamKind, F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    _kind: K,
) -> (bool, bool)
where
    Parts: FrameSetOn<K>,
{
    let Ok(Some(mut stream)) = FrameStream::<Parts, K, _>::read(&mut *io, Role::Server).await
    else {
        panic!("no frame head");
    };
    let value = stream.frame().frame_type().value();
    (
        value == Http3FrameType::Headers.value(),
        matches!(ty(stream.frame().frame_type()), Ty::Known(_)),
    )
}

#[test]
fn the_type_a_frame_gives_is_the_enum_of_its_kind_of_stream() {
    assert!((&[0x07, 0x01, 0x04][..]).sync_first_is_goaway_unpin());
    // The enums of the request and push streams are not the control one;
    // what they name is known to the compiler.
    let _: fn(FrameType<Coproduct<RequestFrameType, frunk_core::coproduct::CNil>>) -> Ty = ty;
    let _: fn(FrameType<Coproduct<PushFrameType, frunk_core::coproduct::CNil>>) -> Ty = ty;
    assert_eq!(
        (&[0x01, 0x00][..]).sync_first_is_headers_unpin(RequestStreamKind),
        (true, true)
    );
    assert_eq!(
        (&[0x01, 0x00][..]).sync_first_is_headers_unpin(PushStreamKind),
        (true, true)
    );
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
            for error in [
                on_request(&wire).unwrap_err(),
                on(ControlStreamKind, Role::Client, &wire).unwrap_err(),
                on(PushStreamKind, Role::Client, &wire).unwrap_err(),
            ] {
                assert!(
                    matches!(&error, ReadFrameHeadError::Unexpected { source: UnexpectedFrameTypeError::Http2Type { source } } if source.frame_type() == frame_type),
                    "{error:?}"
                );
                assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_UNEXPECTED));
            }
        }
    }
}

#[test]
fn a_frame_where_it_may_not_arrive_is_a_frame_unexpected_error_before_the_length() {
    // DATA on the control stream; SETTINGS on a request stream; every frame
    // on the stream of a kind that does not have it.
    let error = on(ControlStreamKind, Role::Client, &[0x00]).unwrap_err();
    assert!(
        matches!(&error, ReadFrameHeadError::Unexpected { source: UnexpectedFrameTypeError::NotAllowedOnStream { frame_type } } if frame_type.get() == 0x00),
        "{error:?}"
    );
    assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_UNEXPECTED));
    let error = on_request(&[0x04]).unwrap_err();
    assert!(
        matches!(&error, ReadFrameHeadError::Unexpected { source: UnexpectedFrameTypeError::NotAllowedOnStream { frame_type } } if frame_type.get() == 0x04),
        "{error:?}"
    );
    // PUSH_PROMISE on a push stream or a control stream; MAX_PUSH_ID on a
    // request stream; HEADERS on a control stream.
    for (frame_type, error) in [
        (0x05, on(PushStreamKind, Role::Client, &[0x05]).unwrap_err()),
        (
            0x05,
            on(ControlStreamKind, Role::Client, &[0x05]).unwrap_err(),
        ),
        (0x0d, on_request(&[0x0d]).unwrap_err()),
        (
            0x01,
            on(ControlStreamKind, Role::Server, &[0x01]).unwrap_err(),
        ),
        (0x03, on(PushStreamKind, Role::Client, &[0x03]).unwrap_err()),
    ] {
        assert!(
            matches!(&error, ReadFrameHeadError::Unexpected { source: UnexpectedFrameTypeError::NotAllowedOnStream { frame_type: got } } if got.get() == frame_type),
            "{frame_type:#x}: {error:?}"
        );
        assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_UNEXPECTED));
    }
    // A frame wider than its value is rejected by the same rule.
    let error = on_request(&[0x40, 0x04]).unwrap_err();
    assert!(
        matches!(
            error,
            ReadFrameHeadError::Unexpected {
                source: UnexpectedFrameTypeError::NotAllowedOnStream { .. }
            }
        ),
        "{error:?}"
    );
}

#[test]
fn a_role_that_may_not_receive_a_frame_is_a_frame_unexpected_error_before_the_length() {
    // PUSH_PROMISE received by a server; MAX_PUSH_ID received by a client.
    let error = on_request(&[0x05]).unwrap_err();
    assert!(
        matches!(&error, ReadFrameHeadError::Unexpected { source: UnexpectedFrameTypeError::NotReceivableByRole { role, frame_type } } if *role == Role::Server && frame_type.get() == 0x05),
        "{error:?}"
    );
    assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_UNEXPECTED));
    let error = on(ControlStreamKind, Role::Client, &[0x0d]).unwrap_err();
    assert!(
        matches!(&error, ReadFrameHeadError::Unexpected { source: UnexpectedFrameTypeError::NotReceivableByRole { role, .. } } if *role == Role::Client),
        "{error:?}"
    );
    assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_UNEXPECTED));
    // And the other roles receive them.
    assert!(
        on(RequestStreamKind, Role::Client, &[0x05, 0x00])
            .unwrap()
            .is_some()
    );
    assert!(
        on(ControlStreamKind, Role::Server, &[0x0d, 0x00])
            .unwrap()
            .is_some()
    );
}

#[test]
fn a_stream_that_ends_before_the_first_byte_has_no_frame() {
    assert!(on_request(&[]).unwrap().is_none());
    assert!(on_nothing(&[]).unwrap().is_none());
    assert!(on(ControlStreamKind, Role::Client, &[]).unwrap().is_none());
    assert!(on(PushStreamKind, Role::Client, &[]).unwrap().is_none());
}

#[test]
fn a_stream_that_ends_inside_the_head_is_a_frame_error() {
    // Inside the Type: first byte promises two, four and eight bytes.
    for wire in [&[0x40][..], &[0x80, 0, 0], &[0xc0, 0, 0, 0, 0, 0, 0]] {
        for error in [on_request(wire).unwrap_err(), on_nothing(wire).unwrap_err()] {
            assert!(
                matches!(
                    error,
                    ReadFrameHeadError::Frame {
                        source: ReadFrameError::Type { .. }
                    }
                ),
                "{error:?}"
            );
            assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
        }
    }
    // The Type is complete, the Length is missing or partial.
    for wire in [
        &[0x01][..],
        &[0x01, 0x40],
        &[0x01, 0x80, 0],
        &[0x40, 0x01, 0xc0, 1],
    ] {
        for error in [on_request(wire).unwrap_err(), on_nothing(wire).unwrap_err()] {
            assert!(
                matches!(
                    error,
                    ReadFrameHeadError::Frame {
                        source: ReadFrameError::Length { .. }
                    }
                ),
                "{error:?}"
            );
            assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
        }
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
            let head = on(ControlStreamKind, Role::Client, &wire)
                .unwrap()
                .unwrap()
                .head;
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
    let wire = [0xc0, 0, 0, 0, 0, 0, 0, 0x04, 0x80, 0, 0x01, 0x00, 0xaa];
    let expected = on(ControlStreamKind, Role::Client, &wire).unwrap().unwrap();
    let mut host = Dribble::new(&wire, 1);
    let (received, pending) = run(host.read_on_unpin(
        ControlStreamKind,
        core::marker::PhantomData::<Parts>,
        Role::Client,
    ));
    assert_eq!(received.unwrap().unwrap(), expected);
    assert!(pending >= 12, "{pending}");
    assert_eq!(host.rest(), [0xaa]);
}

#[test]
fn only_the_head_is_consumed() {
    let input = [0x01, 0x02, 0xaa, 0xbb, 0x00, 0x00];
    let mut host = &input[..];
    let received = host
        .sync_read_on_unpin(
            RequestStreamKind,
            core::marker::PhantomData::<Parts>,
            Role::Server,
        )
        .unwrap()
        .unwrap();
    assert_eq!(received.head.length.get().get(), 2);
    assert_eq!(received.head.remaining, 2);
    assert_eq!(host, [0xaa, 0xbb, 0x00, 0x00]);
}

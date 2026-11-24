//! Placement and role rules of frame types (RFC 9114 §7.2), and the types a
//! list of parts has on each kind of stream.
use frunk_core::{
    HList,
    coproduct::{CNil, Coproduct},
};
use hatate_wire::{
    Role,
    frame::{
        ControlFrameType, FrameType, Http2FrameType, Http3FrameType, PushFrameType,
        RequestFrameType,
        set::{FrameKind, FramePartOn, FrameSetOn},
    },
    registry::{ClaimedValue, is_reserved, reserved},
    stream::kind::{ControlStreamKind, PushStreamKind, RequestStreamKind, StreamKind},
};
use sakuya_var_int::VarInt;

use Http3FrameType::*;

type Parts = HList![hatate_wire::Part];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Request,
    Control,
    Push,
}

const KINDS: [Kind; 3] = [Kind::Request, Kind::Control, Kind::Push];

/// RFC 9114 §7.2: where each frame may appear.
fn allowed(frame: Http3FrameType) -> &'static [Kind] {
    match frame {
        Data | Headers => &[Kind::Request, Kind::Push],
        CancelPush | Settings | Goaway | MaxPushId => &[Kind::Control],
        PushPromise => &[Kind::Request],
    }
}

/// Whether the part of RFC 9114 has the frame type on the kind of stream.
fn of_part(kind: Kind, frame: Http3FrameType) -> bool {
    let value = frame.value();
    match kind {
        Kind::Request => {
            <<hatate_wire::Part as FramePartOn<RequestStreamKind>>::FrameType>::of(value).is_some()
        }
        Kind::Control => {
            <<hatate_wire::Part as FramePartOn<ControlStreamKind>>::FrameType>::of(value).is_some()
        }
        Kind::Push => {
            <<hatate_wire::Part as FramePartOn<PushStreamKind>>::FrameType>::of(value).is_some()
        }
    }
}

/// The same for the list of parts.
fn of_list(kind: Kind, frame: Http3FrameType) -> bool {
    let value = frame.value();
    match kind {
        Kind::Request => <<Parts as FrameSetOn<RequestStreamKind>>::FrameType>::of(value).is_some(),
        Kind::Control => <<Parts as FrameSetOn<ControlStreamKind>>::FrameType>::of(value).is_some(),
        Kind::Push => <<Parts as FrameSetOn<PushStreamKind>>::FrameType>::of(value).is_some(),
    }
}

#[test]
fn every_frame_is_on_the_kinds_of_stream_of_rfc_9114_only() {
    for frame in Http3FrameType::ALL {
        for kind in KINDS {
            let expected = allowed(frame).contains(&kind);
            assert_eq!(of_part(kind, frame), expected, "{frame:?} on {kind:?}");
            assert_eq!(
                of_list(kind, frame),
                expected,
                "{frame:?} on {kind:?} in a list"
            );
        }
    }
}

#[test]
fn the_frame_types_of_a_kind_of_stream_are_enums_of_those_that_appear_on_it() {
    assert_eq!(
        RequestFrameType::of_frame_type(Data),
        Some(RequestFrameType::Data)
    );
    assert_eq!(RequestFrameType::of_frame_type(Settings), None);
    assert_eq!(
        ControlFrameType::of_frame_type(Settings),
        Some(ControlFrameType::Settings)
    );
    assert_eq!(ControlFrameType::of_frame_type(Data), None);
    assert_eq!(
        PushFrameType::of_frame_type(Headers),
        Some(PushFrameType::Headers)
    );
    assert_eq!(PushFrameType::of_frame_type(PushPromise), None);
    for frame in Http3FrameType::ALL {
        if let Some(on) = RequestFrameType::of_frame_type(frame) {
            assert_eq!(on.frame_type(), frame);
            assert_eq!(Http3FrameType::from(on), frame);
            assert_eq!(ClaimedValue::value(on), frame.value());
        }
        if let Some(on) = ControlFrameType::of_frame_type(frame) {
            assert_eq!(on.frame_type(), frame);
            assert_eq!(ClaimedValue::value(on), frame.value());
        }
        if let Some(on) = PushFrameType::of_frame_type(frame) {
            assert_eq!(on.frame_type(), frame);
            assert_eq!(ClaimedValue::value(on), frame.value());
        }
    }
}

#[test]
fn only_a_client_receives_push_promise_and_only_a_server_max_push_id() {
    for frame in Http3FrameType::ALL {
        for role in [Role::Client, Role::Server] {
            let expected = match frame {
                PushPromise => role == Role::Client,
                MaxPushId => role == Role::Server,
                _ => true,
            };
            let on_request = RequestFrameType::of_frame_type(frame);
            let on_control = ControlFrameType::of_frame_type(frame);
            let on_push = PushFrameType::of_frame_type(frame);
            if let Some(on) = on_request {
                assert_eq!(on.receivable_by(role), expected, "{frame:?} by {role:?}");
            }
            if let Some(on) = on_control {
                assert_eq!(on.receivable_by(role), expected, "{frame:?} by {role:?}");
            }
            if let Some(on) = on_push {
                assert_eq!(on.receivable_by(role), expected, "{frame:?} by {role:?}");
            }
        }
    }
}

#[test]
fn the_rules_of_a_frame_of_a_list_are_those_of_its_part() {
    for frame in Http3FrameType::ALL {
        let value = frame.value();
        if let Some(on) = <<Parts as FrameSetOn<RequestStreamKind>>::FrameType>::of(value) {
            assert_eq!(on.value(), value);
            for role in [Role::Client, Role::Server] {
                assert_eq!(
                    on.receivable_by(role),
                    RequestFrameType::of_frame_type(frame)
                        .unwrap()
                        .receivable_by(role)
                );
            }
        }
        if let Some(on) = <<Parts as FrameSetOn<ControlStreamKind>>::FrameType>::of(value) {
            assert_eq!(on.value(), value);
            for role in [Role::Client, Role::Server] {
                assert_eq!(
                    on.receivable_by(role),
                    ControlFrameType::of_frame_type(frame)
                        .unwrap()
                        .receivable_by(role)
                );
            }
        }
    }
}

#[test]
fn a_list_has_the_sum_of_the_types_of_its_parts_on_a_kind_of_stream() {
    // The list of one part has its types in the first branch; the empty
    // list has none.
    let on: <Parts as FrameSetOn<RequestStreamKind>>::FrameType =
        Coproduct::Inl(RequestFrameType::Headers);
    assert_eq!(on.value(), Headers.value());
    let none: Option<<HList![] as FrameSetOn<ControlStreamKind>>::FrameType> =
        <CNil as ClaimedValue>::of(Settings.value());
    assert!(none.is_none());
    assert!(<CNil as ClaimedValue>::of(VarInt::ZERO).is_none());
    // Every stream kind is a marker with a default.
    fn marker<K: StreamKind + Default>() {
        let _ = K::default();
    }
    marker::<RequestStreamKind>();
    marker::<ControlStreamKind>();
    marker::<PushStreamKind>();
}

#[test]
fn a_value_is_known_reserved_or_unknown_by_the_types_of_the_kind_of_stream() {
    type Request = <Parts as FrameSetOn<RequestStreamKind>>::FrameType;
    type Control = <Parts as FrameSetOn<ControlStreamKind>>::FrameType;
    // Known where it appears.
    assert_eq!(
        FrameType::<Request>::from(Headers.value()),
        FrameType::Known(Coproduct::Inl(RequestFrameType::Headers))
    );
    assert_eq!(
        FrameType::<Control>::from(Settings.value()),
        FrameType::Known(Coproduct::Inl(ControlFrameType::Settings))
    );
    // Claimed for another kind of stream: unknown here (reading rejects it
    // before it becomes a frame type).
    assert_eq!(
        FrameType::<Request>::from(Settings.value()),
        FrameType::Unknown(Settings.value())
    );
    // Reserved: 0x1f * N + 0x21.
    for n in [0, 1, 7, 1 << 20] {
        let value = reserved(n).unwrap();
        assert_eq!(
            FrameType::<Request>::from(value),
            FrameType::Reserved(value)
        );
        assert_eq!(FrameType::<Control>::from(value).value(), value);
    }
    // Neither claimed nor reserved: unknown.
    for value in [0x0a, 0x0b, 0x0e, 0x20, 0x22, 0x3f, 0x3fff] {
        let value = VarInt::from_u32(value);
        assert!(!is_reserved(value));
        assert_eq!(FrameType::<Request>::from(value), FrameType::Unknown(value));
    }
    // The type on the wire is kept for all three.
    for value in 0..0x200u32 {
        let value = VarInt::from_u32(value);
        assert_eq!(VarInt::from(FrameType::<Request>::from(value)), value);
    }
}

#[test]
fn the_values_of_the_frame_types_are_those_of_rfc_9114() {
    let values: Vec<u64> = Http3FrameType::ALL
        .map(|frame| frame.value().get())
        .to_vec();
    assert_eq!(values, [0x00, 0x01, 0x03, 0x04, 0x05, 0x07, 0x0d]);
    for frame in Http3FrameType::ALL {
        assert_eq!(Http3FrameType::of(frame.value()), Some(frame));
        assert_eq!(Http3FrameType::try_from(frame.value()), Ok(frame));
        assert_eq!(VarInt::from(frame), frame.value());
    }
    for value in [0x02, 0x06, 0x08, 0x09, 0x0a, 0x0e, 0x21] {
        assert_eq!(Http3FrameType::of(VarInt::from_u32(value)), None);
        assert!(Http3FrameType::try_from(VarInt::from_u32(value)).is_err());
    }
}

#[test]
fn the_types_left_by_http2_are_named_and_not_taken_by_http3() {
    let http2 = [
        (Http2FrameType::Priority, 0x02),
        (Http2FrameType::Ping, 0x06),
        (Http2FrameType::WindowUpdate, 0x08),
        (Http2FrameType::Continuation, 0x09),
    ];
    for (frame, value) in http2 {
        assert_eq!(frame.value().get(), value);
        assert_eq!(Http2FrameType::of(frame.value()), Some(frame));
        assert_eq!(Http3FrameType::of(frame.value()), None);
        for kind in KINDS {
            // No part has it on any kind of stream.
            let on_kind = match kind {
                Kind::Request => {
                    <<Parts as FrameSetOn<RequestStreamKind>>::FrameType>::of(frame.value())
                        .is_some()
                }
                Kind::Control => {
                    <<Parts as FrameSetOn<ControlStreamKind>>::FrameType>::of(frame.value())
                        .is_some()
                }
                Kind::Push => {
                    <<Parts as FrameSetOn<PushStreamKind>>::FrameType>::of(frame.value()).is_some()
                }
            };
            assert!(!on_kind, "{frame:?} on {kind:?}");
        }
    }
    assert_eq!(Http2FrameType::of(VarInt::from_u32(0x03)), None);
}

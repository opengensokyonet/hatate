//! Placement and role rules of frame types (RFC 9114 §7.2).
use frunk_core::HList;
use hatate_wire::{
    Role,
    frame::{
        Http2FrameType, Http3FrameType,
        set::{FrameKind, FrameSet, StreamKind},
    },
};
use sakuya_var_int::VarInt;

use Http3FrameType::*;
use StreamKind::{Control, Push, Request};

/// RFC 9114 §7.2: where each frame may appear.
fn allowed(frame: Http3FrameType) -> &'static [StreamKind] {
    match frame {
        Data | Headers => &[Request, Push],
        CancelPush | Settings | Goaway | MaxPushId => &[Control],
        PushPromise => &[Request],
    }
}

#[test]
fn every_frame_is_allowed_on_the_streams_of_rfc_9114_only() {
    for frame in Http3FrameType::ALL {
        for stream in [Control, Request, Push] {
            assert_eq!(
                frame.allowed_on(stream),
                allowed(frame).contains(&stream),
                "{frame:?} on {stream:?}"
            );
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
            assert_eq!(frame.receivable_by(role), expected, "{frame:?} by {role:?}");
        }
    }
}

#[test]
fn the_kind_of_a_frame_of_a_list_is_that_of_its_part() {
    type Parts = HList![hatate_wire::Part];
    for frame in Http3FrameType::ALL {
        let value = <Parts as FrameSet>::type_value_of(frame.value()).unwrap();
        assert_eq!(<Parts as FrameSet>::value_of(value), frame.value());
        let kind = <Parts as FrameSet>::kind_of(value);
        for stream in [Control, Request, Push] {
            assert_eq!(kind.allowed_on(stream), frame.allowed_on(stream));
        }
        for role in [Role::Client, Role::Server] {
            assert_eq!(kind.receivable_by(role), frame.receivable_by(role));
        }
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
    }
    for value in [0x02, 0x06, 0x08, 0x09, 0x0a, 0x0e, 0x21] {
        assert_eq!(Http3FrameType::of(VarInt::from_u32(value)), None);
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
    }
    assert_eq!(Http2FrameType::of(VarInt::from_u32(0x03)), None);
}

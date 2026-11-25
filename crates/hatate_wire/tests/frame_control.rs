#![feature(impl_trait_in_assoc_type)]
//! CANCEL_PUSH, GOAWAY and MAX_PUSH_ID (RFC 9114 §7.2.3, §7.2.6, §7.2.7).
mod common;

use common::{Dribble, Failing, field_bytes, frame_bytes, run};
use core::num::NonZeroU64;
use hatate_wire::{
    error_code::{ErrorCode, ErrorCodeOf as _},
    frame::{
        CancelPushFrameType, Frame, FrameTypeMismatchError, FrameWidths, GoawayFrameType, GoawayId,
        Http2FrameType, Http3FrameType, MaxPushIdFrameType, PushId,
        codec::{DecodeFrameError, DecodeToEndError, DecodeWholeFrameError},
        control::{CancelPushFrame, GoawayFrame, MaxPushIdFrame},
        payload::{FramePayload, PayloadError},
    },
};
use nitori_call::{ReceiverAccess, call};
use nitori_codec::prelude::*;
use nitori_io::{Read, calls::ReadValue};
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth, stream::ReadVarIntError};

type E = PayloadError<core::convert::Infallible>;
/// The failures of reading a whole frame of one integer from a source whose
/// failures are `E`.
type Error<E> = DecodeWholeFrameError<E, FrameTypeMismatchError, ReadVarIntError<PayloadError<E>>>;

macro_rules! frame_reader {
    ($name:ident, $frame:ty) => {
        /// Reads one whole frame of the kind from the source.
        #[call(sync)]
        async fn $name<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
            io: &mut A,
        ) -> Result<$frame, Error<F::Error>> {
            <$frame>::decode_from(&mut *io).await
        }
    };
}

frame_reader!(read_cancel_push, CancelPushFrame);
frame_reader!(read_goaway, GoawayFrame);
frame_reader!(read_max_push_id, MaxPushIdFrame);

fn field<T: Copy + Into<VarInt> + TryFrom<VarInt>>(value: u64, width: VarIntWidth) -> VarIntField<T>
where
    <T as TryFrom<VarInt>>::Error: core::fmt::Debug,
{
    VarIntField::new(T::try_from(VarInt::new(value).unwrap()).unwrap(), width).unwrap()
}

/// Every width of Type, Length and integer, each frame type.
fn wire(kind: Http3FrameType, widths: FrameWidths, value: u64, width: VarIntWidth) -> Vec<u8> {
    frame_bytes(
        kind.value(),
        widths,
        &field_bytes(field::<VarInt>(value, width)),
    )
}

#[test]
fn goaway_keeps_every_width() {
    for type_width in VarIntWidth::ALL {
        for length_width in VarIntWidth::ALL {
            for width in VarIntWidth::ALL {
                let widths = FrameWidths::new(type_width, length_width);
                let bytes = wire(Http3FrameType::Goaway, widths, 4, width);
                let mut frame = (&bytes[..]).sync_read_goaway_unpin().unwrap();
                assert_eq!(frame.widths(), widths);
                let id = frame.payload().value;
                assert_eq!(id.get().get().get(), 4);
                assert_eq!(id.width(), width);
                let mut written = Vec::new();
                written.sync_encode_unpin(frame).unwrap();
                assert_eq!(written, bytes);
            }
        }
    }
}

#[test]
fn cancel_push_and_max_push_id_keep_their_widths() {
    let widths = FrameWidths::new(VarIntWidth::Two, VarIntWidth::Four);
    let bytes = wire(Http3FrameType::CancelPush, widths, 9, VarIntWidth::Eight);
    let mut frame = (&bytes[..]).sync_read_cancel_push_unpin().unwrap();
    assert_eq!(frame.widths(), widths);
    let id = frame.payload().value;
    assert_eq!(id.get(), PushId::new(VarInt::from_u32(9)));
    assert_eq!(id.width(), VarIntWidth::Eight);
    let mut written = Vec::new();
    written.sync_encode_unpin(frame).unwrap();
    assert_eq!(written, bytes);

    let bytes = wire(
        Http3FrameType::MaxPushId,
        widths,
        1 << 40,
        VarIntWidth::Eight,
    );
    let mut frame = (&bytes[..]).sync_read_max_push_id_unpin().unwrap();
    assert_eq!(frame.widths(), widths);
    assert_eq!(frame.payload().value.get().get().get(), 1 << 40);
    let mut written = Vec::new();
    written.sync_encode_unpin(frame).unwrap();
    assert_eq!(written, bytes);
}

fn payload_of<T>(value: T) -> ReadValue<VarIntField<T>, ()>
where
    T: Copy + Into<VarInt> + TryFrom<VarInt>,
{
    ReadValue {
        value: VarIntField::shortest(value),
        metadata: (),
    }
}

#[test]
fn new_writes_the_shortest_widths() {
    let mut out = Vec::new();
    let frame = nitori_call::__private::run_sync(Frame::new(
        GoawayFrameType,
        payload_of(GoawayId::new(VarInt::from_u32(300))),
    ))
    .unwrap();
    assert_eq!(frame.widths(), FrameWidths::SHORTEST);
    out.sync_encode_unpin(frame).unwrap();
    assert_eq!(out, [0x07, 0x02, 0x41, 0x2c]);

    let mut out = Vec::new();
    let frame = nitori_call::__private::run_sync(Frame::new(
        CancelPushFrameType,
        payload_of(PushId::new(VarInt::from_u32(5))),
    ))
    .unwrap();
    out.sync_encode_unpin(frame).unwrap();
    assert_eq!(out, [0x03, 0x01, 0x05]);

    let mut out = Vec::new();
    let frame = nitori_call::__private::run_sync(Frame::new(
        MaxPushIdFrameType,
        payload_of(PushId::new(VarInt::from_u32(1 << 20))),
    ))
    .unwrap();
    out.sync_encode_unpin(frame).unwrap();
    assert_eq!(out, [0x0d, 0x04, 0x80, 0x10, 0x00, 0x00]);
}

#[test]
fn a_payload_shorter_than_its_integer_is_a_frame_error() {
    // Length 0; Length 1 with a two-byte integer.
    for bytes in [
        &[0x07, 0x00][..],
        &[0x07, 0x01, 0x40],
        &[0x07, 0x03, 0x80, 0, 0],
    ] {
        let error = (&bytes[..]).sync_read_goaway_unpin().unwrap_err();
        assert!(
            matches!(
                &error,
                DecodeWholeFrameError::Payload {
                    source: DecodeToEndError::Value { source }
                } if source.is_incomplete()
            ),
            "{error:?}"
        );
        assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
    }
    let error = (&[0x03, 0x00][..])
        .sync_read_cancel_push_unpin()
        .unwrap_err();
    assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
    let error = (&[0x0d, 0x00][..])
        .sync_read_max_push_id_unpin()
        .unwrap_err();
    assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
}

#[test]
fn bytes_after_the_integer_are_a_frame_error() {
    // The integer ends before the Length does: one and three bytes follow.
    let error = (&[0x07, 0x02, 0x04, 0xff, 0xee][..])
        .sync_read_goaway_unpin()
        .unwrap_err();
    assert!(
        matches!(
            &error,
            DecodeWholeFrameError::Payload { source: DecodeToEndError::Unread { left } }
                if left.get() == 1
        ),
        "{error:?}"
    );
    assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
    let error = (&[0x0d, 0x04, 0x04, 1, 2, 3][..])
        .sync_read_max_push_id_unpin()
        .unwrap_err();
    assert!(
        matches!(
            &error,
            DecodeWholeFrameError::Payload { source: DecodeToEndError::Unread { left } }
                if left.get() == 3
        ),
        "{error:?}"
    );
    assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
    // A payload that is exactly the integer is fine, in any width.
    let mut frame = (&[0x03, 0x02, 0x40, 0x04][..])
        .sync_read_cancel_push_unpin()
        .unwrap();
    assert_eq!(frame.payload().value.width(), VarIntWidth::Two);
    let error = (&[0x03, 0x03, 0x05, 0x40, 0x04][..])
        .sync_read_cancel_push_unpin()
        .unwrap_err();
    assert!(
        matches!(
            error,
            DecodeWholeFrameError::Payload {
                source: DecodeToEndError::Unread { .. }
            }
        ),
        "{error:?}"
    );
}

#[test]
fn a_frame_of_another_type_is_not_the_frame() {
    // MAX_PUSH_ID where GOAWAY is read: the type is not the field's.
    let error = (&[0x0d, 0x01, 0x08][..])
        .sync_read_goaway_unpin()
        .unwrap_err();
    let DecodeWholeFrameError::Frame {
        source: DecodeFrameError::Type { source },
    } = &error
    else {
        panic!("{error:?}");
    };
    assert_eq!(source.expected(), Http3FrameType::Goaway);
    assert_eq!(source.frame_type(), Http3FrameType::MaxPushId.value());
    assert_eq!(error.error_code(), None);
}

#[test]
fn a_type_of_http2_is_rejected() {
    let error = (&[0x02, 0x01, 0x04][..])
        .sync_read_goaway_unpin()
        .unwrap_err();
    let DecodeWholeFrameError::Frame {
        source: DecodeFrameError::Http2Type { source },
    } = &error
    else {
        panic!("{error:?}");
    };
    assert_eq!(source.frame_type(), Http2FrameType::Priority);
    assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_UNEXPECTED));
}

#[test]
fn a_stream_that_ends_inside_the_payload_is_a_frame_error() {
    let error = (&[0x07, 0x02, 0x40][..])
        .sync_read_goaway_unpin()
        .unwrap_err();
    assert!(
        matches!(
            &error,
            DecodeWholeFrameError::Payload {
                source: DecodeToEndError::Value { source }
            } if matches!(source.host_error(), Some(PayloadError::Truncated { .. }))
        ),
        "{error:?}"
    );
    assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
}

#[test]
fn the_next_frame_is_left_unread() {
    let mut input = &[0x07, 0x01, 0x04, 0x0d, 0x01, 0x08][..];
    assert_eq!(
        input
            .sync_read_goaway_unpin()
            .unwrap()
            .into_payload()
            .value
            .get()
            .get()
            .get(),
        4
    );
    assert_eq!(input, [0x0d, 0x01, 0x08]);
    assert_eq!(
        input
            .sync_read_max_push_id_unpin()
            .unwrap()
            .into_payload()
            .value
            .get()
            .get()
            .get(),
        8
    );
    assert!(input.is_empty());
}

#[test]
fn a_pending_between_every_byte_changes_nothing() {
    let bytes = wire(
        Http3FrameType::Goaway,
        FrameWidths::new(VarIntWidth::Two, VarIntWidth::Two),
        1 << 30,
        VarIntWidth::Eight,
    );
    let mut host = Dribble::new(&bytes, 1);
    let (frame, pending) = run(host.read_goaway_unpin());
    let id = frame.unwrap().into_payload().value;
    assert_eq!(id.get().get().get(), 1 << 30);
    assert_eq!(id.width(), VarIntWidth::Eight);
    assert!(pending >= bytes.len(), "{pending}");
    assert!(host.rest().is_empty());
}

/// Reads the integer of a GOAWAY from the payload of its frame, twice.
#[call(sync)]
async fn goaway_twice<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> [Result<
    ReadValue<VarIntField<GoawayId>, ()>,
    DecodeToEndError<ReadVarIntError<PayloadError<F::Error>>>,
>; 2]
where
    <F as Read>::Error: core::fmt::Debug,
{
    let mut frame = Frame::<GoawayFrameType, FramePayload<_>, ()>::decode_from(&mut *io)
        .await
        .unwrap();
    let first = frame.payload().decode_to_end().await;
    let second = frame.payload().decode_to_end().await;
    [first, second]
}

#[test]
fn the_error_code_follows_the_failure_of_the_payload() {
    // A failing stream has no code of its own, and neither has the read
    // after it.
    let mut host = Failing::new(&[0x07, 0x01]);
    let (results, _) = run(host.goaway_twice_unpin());
    let [first, second] = results;
    let error = first.unwrap_err();
    assert!(
        matches!(
            &error,
            DecodeToEndError::Value { source }
                if matches!(source.host_error(), Some(PayloadError::Host { .. }))
        ),
        "{error:?}"
    );
    assert_eq!(error.error_code(), None);
    let error = second.unwrap_err();
    assert!(
        matches!(
            &error,
            DecodeToEndError::Value { source }
                if matches!(source.host_error(), Some(PayloadError::Failed))
        ),
        "{error:?}"
    );
    assert_eq!(error.error_code(), None);
    // Bytes after the integer are a frame error, however many are counted.
    let error = DecodeToEndError::<ReadVarIntError<E>>::Unread {
        left: NonZeroU64::MIN,
    };
    assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
}

#[test]
fn a_stream_that_ends_inside_the_integer_of_each_frame_is_a_frame_error() {
    for (bytes, name) in [
        (&[0x03, 0x02, 0x40][..], "CANCEL_PUSH"),
        (&[0x07, 0x04, 0x80, 0x00, 0x00][..], "GOAWAY"),
        (&[0x0d, 0x08, 0xc0][..], "MAX_PUSH_ID"),
    ] {
        let error = match name {
            "CANCEL_PUSH" => (&bytes[..])
                .sync_read_cancel_push_unpin()
                .unwrap_err()
                .error_code(),
            "GOAWAY" => (&bytes[..])
                .sync_read_goaway_unpin()
                .unwrap_err()
                .error_code(),
            _ => (&bytes[..])
                .sync_read_max_push_id_unpin()
                .unwrap_err()
                .error_code(),
        };
        assert_eq!(error, Some(ErrorCode::H3_FRAME_ERROR), "{name}");
    }
}

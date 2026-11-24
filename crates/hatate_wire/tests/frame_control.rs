#![feature(impl_trait_in_assoc_type)]
//! CANCEL_PUSH, GOAWAY and MAX_PUSH_ID (RFC 9114 §7.2.3, §7.2.6, §7.2.7).
mod common;

use common::{Broken, Dribble, run};
use hatate_wire::{
    error_code::{ErrorCode, ErrorCodeOf as _},
    frame::{
        FrameWidths, GoawayId, Http3FrameType, PushId,
        codec::read_frame,
        control::{codec::*, *},
        payload::PayloadError,
    },
};
use nitori_call::{ReceiverAccess, call};
use nitori_io::Read;
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};

type E = PayloadError<core::convert::Infallible>;

macro_rules! frame_reader {
    ($name:ident, $frame:ty, $kind:expr, $method:ident) => {
        /// Reads one whole frame of the kind from the stream.
        #[call(sync)]
        async fn $name<F: Read, A: ReceiverAccess<Family = F>>(
            io: &mut A,
        ) -> Result<$frame, ReadIntegerFrameError<PayloadError<F::Error>>> {
            let Ok(Some(head)) = read_frame(&mut *io).await else {
                panic!("no frame head");
            };
            assert_eq!(head.r#type().get(), $kind.value());
            let widths = head.widths();
            let mut payload = head.into_payload().into_parts().1;
            let frame = {
                let mut source = io.compose(&mut payload);
                source.$method(widths).await?
            };
            assert_eq!(payload.remaining(), 0, "the payload was read to its end");
            Ok(frame)
        }
    };
}

frame_reader!(
    read_cancel_push,
    CancelPushFrame,
    Http3FrameType::CancelPush,
    read_cancel_push_frame
);
frame_reader!(
    read_goaway,
    GoawayFrame,
    Http3FrameType::Goaway,
    read_goaway_frame
);
frame_reader!(
    read_max_push_id,
    MaxPushIdFrame,
    Http3FrameType::MaxPushId,
    read_max_push_id_frame
);

fn field<T: Copy + Into<VarInt> + TryFrom<VarInt>>(value: u64, width: VarIntWidth) -> VarIntField<T>
where
    <T as TryFrom<VarInt>>::Error: core::fmt::Debug,
{
    VarIntField::new(T::try_from(VarInt::new(value).unwrap()).unwrap(), width).unwrap()
}

/// Every width of Type, Length and integer, each frame type.
fn wire(kind: Http3FrameType, widths: FrameWidths, value: u64, width: VarIntWidth) -> Vec<u8> {
    let mut wire = Vec::new();
    for (value, width) in [
        (kind.value().get(), widths.type_width()),
        (width.encoded_len() as u64, widths.length_width()),
        (value, width),
    ] {
        let field = VarIntField::new(VarInt::new(value).unwrap(), width).unwrap();
        let (bytes, len) = field.to_encoding();
        wire.extend_from_slice(&bytes[..len]);
    }
    wire
}

#[test]
fn goaway_keeps_every_width() {
    for type_width in VarIntWidth::ALL {
        for length_width in VarIntWidth::ALL {
            for width in VarIntWidth::ALL {
                let widths = FrameWidths::new(type_width, length_width);
                let bytes = wire(Http3FrameType::Goaway, widths, 4, width);
                let frame = (&bytes[..]).sync_read_goaway_unpin().unwrap();
                assert_eq!(frame.widths(), widths);
                assert_eq!(frame.id().get().get().get(), 4);
                assert_eq!(frame.id().width(), width);
                assert_eq!(frame.encoded_len(), bytes.len());
                let mut written = Vec::new();
                written.sync_write_goaway_frame_unpin(frame).unwrap();
                assert_eq!(written, bytes);
            }
        }
    }
}

#[test]
fn cancel_push_and_max_push_id_keep_their_widths() {
    let widths = FrameWidths::new(VarIntWidth::Two, VarIntWidth::Four);
    let bytes = wire(Http3FrameType::CancelPush, widths, 9, VarIntWidth::Eight);
    let frame = (&bytes[..]).sync_read_cancel_push_unpin().unwrap();
    assert_eq!(frame.widths(), widths);
    assert_eq!(frame.push_id().get(), PushId::new(VarInt::from_u32(9)));
    assert_eq!(frame.push_id().width(), VarIntWidth::Eight);
    let mut written = Vec::new();
    written.sync_write_cancel_push_frame_unpin(frame).unwrap();
    assert_eq!(written, bytes);

    let bytes = wire(
        Http3FrameType::MaxPushId,
        widths,
        1 << 40,
        VarIntWidth::Eight,
    );
    let frame = (&bytes[..]).sync_read_max_push_id_unpin().unwrap();
    assert_eq!(frame.widths(), widths);
    assert_eq!(frame.push_id().get().get().get(), 1 << 40);
    let mut written = Vec::new();
    written.sync_write_max_push_id_frame_unpin(frame).unwrap();
    assert_eq!(written, bytes);
}

#[test]
fn new_writes_the_shortest_widths() {
    let mut out = Vec::new();
    let frame = GoawayFrame::new(VarIntField::shortest(GoawayId::new(VarInt::from_u32(300))));
    assert_eq!(frame.widths(), FrameWidths::SHORTEST);
    assert_eq!(frame.encoded_len(), 4);
    out.sync_write_goaway_frame_unpin(frame).unwrap();
    assert_eq!(out, [0x07, 0x02, 0x41, 0x2c]);

    let mut out = Vec::new();
    out.sync_write_cancel_push_frame_unpin(CancelPushFrame::new(VarIntField::shortest(
        PushId::new(VarInt::from_u32(5)),
    )))
    .unwrap();
    assert_eq!(out, [0x03, 0x01, 0x05]);

    let mut out = Vec::new();
    out.sync_write_max_push_id_frame_unpin(MaxPushIdFrame::new(VarIntField::shortest(
        PushId::new(VarInt::from_u32(1 << 20)),
    )))
    .unwrap();
    assert_eq!(out, [0x0d, 0x04, 0x80, 0x10, 0x00, 0x00]);
}

#[test]
fn with_widths_gives_the_requested_widths() {
    let frame = MaxPushIdFrame::with_widths(
        field(3, VarIntWidth::Two),
        FrameWidths::new(VarIntWidth::Eight, VarIntWidth::Two),
    );
    let mut out = Vec::new();
    out.sync_write_max_push_id_frame_unpin(frame).unwrap();
    assert_eq!(out, [0xc0, 0, 0, 0, 0, 0, 0, 0x0d, 0x40, 0x02, 0x40, 0x03]);
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
            matches!(&error, ReadIntegerFrameError::Field { source } if source.is_incomplete()),
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
        matches!(&error, ReadIntegerFrameError::Trailing { remaining: Some(n) } if n.get() == 1),
        "{error:?}"
    );
    assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
    let error = (&[0x0d, 0x04, 0x04, 1, 2, 3][..])
        .sync_read_max_push_id_unpin()
        .unwrap_err();
    assert!(
        matches!(&error, ReadIntegerFrameError::Trailing { remaining: Some(n) } if n.get() == 3),
        "{error:?}"
    );
    assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
    // A payload that is exactly the integer is fine, in any width.
    let frame = (&[0x03, 0x02, 0x40, 0x04][..])
        .sync_read_cancel_push_unpin()
        .unwrap();
    assert_eq!(frame.push_id().width(), VarIntWidth::Two);
    let error = (&[0x03, 0x03, 0x05, 0x40, 0x04][..])
        .sync_read_cancel_push_unpin()
        .unwrap_err();
    assert!(
        matches!(error, ReadIntegerFrameError::Trailing { .. }),
        "{error:?}"
    );
}

#[test]
fn a_stream_that_ends_inside_the_payload_is_a_frame_error() {
    let error = (&[0x07, 0x02, 0x40][..])
        .sync_read_goaway_unpin()
        .unwrap_err();
    assert!(
        matches!(
            &error,
            ReadIntegerFrameError::Field { source }
                if matches!(source.host_error(), Some(PayloadError::Truncated { .. }))
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
            .id()
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
            .push_id()
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
    let frame = frame.unwrap();
    assert_eq!(frame.id().get().get().get(), 1 << 30);
    assert_eq!(frame.id().width(), VarIntWidth::Eight);
    assert!(pending >= bytes.len(), "{pending}");
    assert!(host.rest().is_empty());
}

/// Reads the integer of a GOAWAY from a payload of the stream.
#[call(sync)]
async fn goaway_of<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    payload: &mut hatate_wire::frame::payload::FramePayload,
) -> Result<GoawayFrame, ReadIntegerFrameError<PayloadError<F::Error>>> {
    let mut source = io.compose(payload);
    source.read_goaway_frame(FrameWidths::SHORTEST).await
}

#[test]
fn the_error_code_follows_the_failure_of_the_payload() {
    use hatate_wire::frame::payload::FramePayload;
    // A failing stream has no code of its own, and neither has the read
    // after it.
    let mut host = Broken;
    let mut payload = FramePayload::new(1);
    let (result, _) = run(host.goaway_of_unpin(&mut payload));
    let error = result.unwrap_err();
    assert!(
        matches!(
            &error,
            ReadIntegerFrameError::Field { source }
                if matches!(source.host_error(), Some(PayloadError::Host { .. }))
        ),
        "{error:?}"
    );
    assert_eq!(error.error_code(), None);
    let (result, _) = run(host.goaway_of_unpin(&mut payload));
    let error = result.unwrap_err();
    assert!(
        matches!(
            &error,
            ReadIntegerFrameError::Field { source }
                if matches!(source.host_error(), Some(PayloadError::Failed))
        ),
        "{error:?}"
    );
    assert_eq!(error.error_code(), None);
    // Bytes after the integer are a frame error, however many are counted.
    let error = ReadIntegerFrameError::<E>::Trailing { remaining: None };
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

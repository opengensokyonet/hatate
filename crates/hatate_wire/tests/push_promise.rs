#![feature(impl_trait_in_assoc_type)]
//! The Push ID of PUSH_PROMISE (RFC 9114 §7.2.5).
mod common;

use common::{Dribble, run};
use core::marker::PhantomData;
use frunk_core::{HList, coproduct::Coproduct};
use hatate_wire::{
    error_code::{ErrorCode, ErrorCodeOf as _},
    frame::{
        FrameType, FrameWidths, Http3FrameType, PushId,
        codec::{
            ReadFrameHeadExt as _, ReadPushPromisePushIdError, ReadPushPromisePushIdExt as _,
            WritePushPromiseFrameHostExt as _,
        },
        payload::PayloadError,
    },
};
use nitori_call::{ReceiverAccess, call};
use nitori_io::{Read, prelude::*};
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};

type Parts = HList![hatate_wire::Part];

/// What a PUSH_PROMISE frame leaves after its Push ID was read.
#[derive(Debug, PartialEq, Eq)]
struct Promise {
    push_id: VarIntField<PushId>,
    widths: FrameWidths,
    /// The remaining length of the payload when the Push ID was read.
    remaining: u64,
    /// The field section: the rest of the payload.
    section: Vec<u8>,
}

/// Reads a whole PUSH_PROMISE frame: its Push ID, then the rest of the
/// payload.
#[call(sync)]
async fn read_promise<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> Result<Promise, ReadPushPromisePushIdError<PayloadError<F::Error>>>
where
    <F as Read>::Error: core::fmt::Debug,
{
    let head = io
        .read_frame_head(PhantomData::<Parts>)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        head.frame_type(),
        FrameType::Known(Coproduct::Inl(Http3FrameType::PushPromise))
    );
    let mut payload = head.payload();
    let push_id = {
        let mut source = io.compose(&mut payload);
        source.read_push_promise_push_id().await?
    };
    let remaining = payload.remaining();
    let mut section = Vec::new();
    {
        let mut source = io.compose(&mut payload);
        loop {
            let mut buffer = [0; 3];
            let count = source.read(&mut &mut buffer[..]).await.unwrap();
            if count == 0 {
                break;
            }
            section.extend_from_slice(&buffer[..count]);
        }
    }
    payload.finish().unwrap();
    Ok(Promise {
        push_id,
        widths: head.widths(),
        remaining,
        section,
    })
}

fn push_id(value: u64, width: VarIntWidth) -> VarIntField<PushId> {
    VarIntField::new(PushId::new(VarInt::new(value).unwrap()), width).unwrap()
}

fn wire(widths: FrameWidths, push_id: VarIntField<PushId>, section: &[u8]) -> Vec<u8> {
    let mut hosts = (Vec::new(), section);
    hosts
        .sync_write_push_promise_frame_unpin(widths, push_id)
        .unwrap();
    hosts.0
}

#[test]
fn the_push_id_of_every_width_is_read_and_the_section_stays_in_the_payload() {
    for width in VarIntWidth::ALL {
        for (type_width, length_width) in [
            (VarIntWidth::One, VarIntWidth::One),
            (VarIntWidth::Two, VarIntWidth::Four),
            (VarIntWidth::Eight, VarIntWidth::Two),
        ] {
            let widths = FrameWidths::new(type_width, length_width);
            let id = push_id(9, width);
            let bytes = wire(widths, id, b"field section");
            let promise = (&bytes[..]).sync_read_promise_unpin().unwrap();
            assert_eq!(promise.push_id, id);
            assert_eq!(promise.push_id.width(), width);
            assert_eq!(promise.widths, widths);
            // The section's bytes were still in the payload.
            assert_eq!(promise.remaining, 13);
            assert_eq!(promise.section, b"field section");
        }
    }
    let id = push_id(1 << 40, VarIntWidth::Eight);
    let promise = (&wire(FrameWidths::SHORTEST, id, b"")[..])
        .sync_read_promise_unpin()
        .unwrap();
    assert_eq!(promise.push_id.get().get().get(), 1 << 40);
    assert_eq!(promise.remaining, 0);
    assert!(promise.section.is_empty());
}

#[test]
fn what_is_read_is_written_back_to_the_same_bytes() {
    for width in VarIntWidth::ALL {
        let widths = FrameWidths::new(VarIntWidth::Two, VarIntWidth::Two);
        let original = wire(widths, push_id(5, width), &[1, 2, 3, 4, 5]);
        let promise = (&original[..]).sync_read_promise_unpin().unwrap();
        assert_eq!(
            wire(promise.widths, promise.push_id, &promise.section),
            original
        );
    }
}

#[test]
fn the_next_frame_is_left_unread() {
    let mut bytes = wire(FrameWidths::SHORTEST, push_id(2, VarIntWidth::Two), b"ab");
    bytes.extend([0xee, 0xff]);
    let mut input = &bytes[..];
    let promise = input.sync_read_promise_unpin().unwrap();
    assert_eq!(promise.section, b"ab");
    assert_eq!(input, [0xee, 0xff]);
}

#[test]
fn a_payload_shorter_than_the_push_id_is_a_frame_error() {
    // Length 0; Length 1 with a two-byte Push ID, the stream going on;
    // Length 3 with an eight-byte one.
    for wire in [
        &[0x05, 0x00, 0xaa, 0xbb][..],
        &[0x05, 0x01, 0x40, 0x07, 0xaa],
        &[0x05, 0x03, 0xc0, 0, 0, 0, 0, 0, 0, 0x01],
    ] {
        let error = (&wire[..]).sync_read_promise_unpin().unwrap_err();
        assert!(error.read_error().is_incomplete(), "{error:?}");
        assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
    }
}

#[test]
fn a_stream_that_ends_inside_the_push_id_is_a_frame_error() {
    for wire in [&[0x05, 0x04, 0x80, 0x00][..], &[0x05, 0x04][..]] {
        let error = (&wire[..]).sync_read_promise_unpin().unwrap_err();
        assert!(
            matches!(
                error.read_error().host_error(),
                Some(PayloadError::Truncated { .. })
            ),
            "{error:?}"
        );
        assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
    }
}

#[test]
fn a_pending_between_every_byte_changes_nothing() {
    let bytes = wire(
        FrameWidths::new(VarIntWidth::Two, VarIntWidth::Two),
        push_id(5, VarIntWidth::Four),
        b"section",
    );
    let expected = (&bytes[..]).sync_read_promise_unpin().unwrap();
    let mut host = Dribble::new(&bytes, 1);
    let (promise, pending) = run(host.read_promise_unpin());
    assert_eq!(promise.unwrap(), expected);
    assert!(pending >= bytes.len(), "{pending}");
    assert!(host.rest().is_empty());
}

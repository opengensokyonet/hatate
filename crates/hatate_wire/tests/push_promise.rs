#![feature(impl_trait_in_assoc_type)]
//! The Push ID of PUSH_PROMISE (RFC 9114 §7.2.5).
mod common;

use common::{Dribble, field_bytes, frame_bytes, read_some, run};
use core::num::NonZeroUsize;
use frunk_core::HList;
use hatate_wire::{
    Role,
    error_code::{ErrorCode, ErrorCodeOf as _},
    frame::{
        Frame, FrameWidths, Http3FrameType, PushId, PushPromiseFrameType,
        payload::{FramePayload, PayloadError},
        push_promise::{DecodePushPromisePayloadError, PushPromisePayload},
    },
    stream::{FrameStream, kind::RequestStreamKind},
};
use nitori_call::{ConstructedAccess, ReceiverAccess, call};
use nitori_codec::{DecodeFrom as _, payload::Chunks, prelude::*};
use nitori_io::{Read, ReadChunk, Write, calls::ReadValue};
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth, stream::ReadVarIntError};

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
async fn read_promise<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> Result<Promise, DecodePushPromisePayloadError<ReadVarIntError<PayloadError<F::Error>>>>
where
    <F as Read>::Error: core::fmt::Debug,
{
    // A client receives PUSH_PROMISE on a request stream.
    let mut stream = FrameStream::<Parts, RequestStreamKind, _>::read(&mut *io, Role::Client)
        .await
        .unwrap()
        .unwrap();
    let mut frame = stream.frame();
    assert_eq!(
        frame.frame_type().value(),
        Http3FrameType::PushPromise.value()
    );
    let widths = frame.widths();
    let mut promise =
        PushPromisePayload::<&mut FramePayload<_>, ()>::decode_from(&mut **frame.payload()).await?;
    let remaining = promise.section.remaining();
    let section = read_some(&mut promise.section, 1000).await.unwrap();
    let push_id = promise.push_id.value;
    assert_eq!(promise.section.remaining(), 0);
    Ok(Promise {
        push_id,
        widths,
        remaining,
        section,
    })
}

fn push_id(value: u64, width: VarIntWidth) -> VarIntField<PushId> {
    VarIntField::new(PushId::new(VarInt::new(value).unwrap()), width).unwrap()
}

fn wire(widths: FrameWidths, push_id: VarIntField<PushId>, section: &[u8]) -> Vec<u8> {
    let mut payload = field_bytes(push_id);
    payload.extend_from_slice(section);
    frame_bytes(Http3FrameType::PushPromise.value(), widths, &payload)
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

/// Reads the PUSH_PROMISE frame at the start of the stream and writes it
/// back whole, as it was read.
#[call(sync)]
async fn write_frame_back<R: ReadChunk<Metadata = ()>, W: Write<Report = ()>>(
    source: &mut impl ReceiverAccess<Family = R>,
    sink: &mut impl ReceiverAccess<Family = W>,
) where
    <R as Read>::Error: core::fmt::Debug,
    <W as Write>::Error: core::fmt::Debug,
{
    let mut stream = FrameStream::<Parts, RequestStreamKind, _>::read(&mut *source, Role::Client)
        .await
        .unwrap()
        .unwrap();
    let frame = stream.frame().map_payload(|payload| Chunks {
        source: payload,
        chunk_maximum: NonZeroUsize::new(3).unwrap(),
    });
    sink.encode(frame).await.unwrap();
}

/// Reads the PUSH_PROMISE frame at the start of the stream and writes its
/// payload back as the Push ID and the section.
#[call(sync)]
async fn write_payload_back<R: ReadChunk<Metadata = ()>, W: Write<Report = ()>>(
    source: &mut impl ReceiverAccess<Family = R>,
    sink: &mut impl ReceiverAccess<Family = W>,
) where
    <R as Read>::Error: core::fmt::Debug,
    <W as Write>::Error: core::fmt::Debug,
{
    let mut stream = FrameStream::<Parts, RequestStreamKind, _>::read(&mut *source, Role::Client)
        .await
        .unwrap()
        .unwrap();
    let mut frame = stream.frame();
    let promise =
        PushPromisePayload::<&mut FramePayload<_>, ()>::decode_from(&mut **frame.payload())
            .await
            .unwrap();
    sink.encode(PushPromisePayload {
        push_id: promise.push_id,
        section: Chunks {
            source: promise.section,
            chunk_maximum: NonZeroUsize::new(3).unwrap(),
        },
    })
    .await
    .unwrap();
}

#[test]
fn what_is_read_is_written_back_to_the_same_bytes() {
    for width in VarIntWidth::ALL {
        let widths = FrameWidths::new(VarIntWidth::Two, VarIntWidth::Two);
        let id = push_id(5, width);
        let original = wire(widths, id, &[1, 2, 3, 4, 5]);
        let mut output = Vec::new();
        (&mut &original[..], &mut output).sync_write_frame_back_unpin();
        assert_eq!(output, original);
        // The Push ID keeps its width.
        let mut output = Vec::new();
        (&mut &original[..], &mut output).sync_write_payload_back_unpin();
        assert_eq!(output, original[4..]);
    }
}

#[test]
fn a_promise_is_written_and_read_back() {
    for section in [&b""[..], b"field section"] {
        let id = push_id(55, VarIntWidth::One);
        let frame = nitori_call::__private::run_sync(Frame::new(
            PushPromiseFrameType,
            PushPromisePayload {
                push_id: ReadValue {
                    value: id,
                    metadata: (),
                },
                section: Chunks {
                    source: ConstructedAccess::new(section),
                    chunk_maximum: NonZeroUsize::new(4).unwrap(),
                },
            },
        ))
        .unwrap();
        // The Length is the Push ID and the section, in the shortest width.
        assert_eq!(frame.length().get().get(), 1 + section.len() as u64);
        assert_eq!(frame.widths(), FrameWidths::SHORTEST);
        let mut output = Vec::new();
        output.sync_encode_unpin(frame).unwrap();
        let expected = wire(FrameWidths::SHORTEST, id, section);
        assert_eq!(output, expected);
        let promise = (&expected[..]).sync_read_promise_unpin().unwrap();
        assert_eq!(promise.push_id, id);
        assert_eq!(promise.section, section);
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

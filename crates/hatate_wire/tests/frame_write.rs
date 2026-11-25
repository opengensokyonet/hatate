//! Writing frames whose payload comes from a source: DATA, HEADERS, unknown
//! types and PUSH_PROMISE (RFC 9114 §7.1, §7.2.1, §7.2.2, §7.2.5).
#![feature(impl_trait_in_assoc_type)]
mod common;

use bytes::Bytes;
use common::{field_bytes, frame_bytes};
use core::num::NonZeroUsize;
use frunk_core::hlist::HNil;
use hatate_wire::{
    Role,
    frame::{
        Frame, FrameWidths, Http2FrameType, Http3FrameType, NewFrameError, PushId,
        PushPromiseFrameType, push_promise::PushPromisePayload,
    },
    stream::{FrameStream, kind::RequestStreamKind},
};
use nitori_call::{ConstructedAccess, ReceiverAccess, call};
use nitori_codec::{payload::Chunks, prelude::*};
use nitori_io::{Read, calls::ReadValue};
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};

fn chunks<A>(source: A) -> Chunks<ConstructedAccess<A>> {
    Chunks {
        source: ConstructedAccess::new(source),
        chunk_maximum: NonZeroUsize::new(7).unwrap(),
    }
}

/// The bytes of the frame of the type `r#type` whose payload is `payload`.
fn written(r#type: u32, payload: &[u8]) -> Vec<u8> {
    let frame =
        nitori_call::__private::run_sync(Frame::new(VarInt::from_u32(r#type), chunks(payload)))
            .unwrap();
    let mut out = Vec::new();
    out.sync_encode_unpin(frame).unwrap();
    out
}

/// The Type, Length, widths and unread payload of the frame at the start of
/// `input`.
#[call(sync)]
async fn read_head<F: Read<Metadata = ()>>(
    io: &mut impl ReceiverAccess<Family = F>,
) -> (VarIntField<VarInt>, VarIntField<VarInt>, FrameWidths, u64)
where
    <F as Read>::Error: core::fmt::Debug,
{
    // Every type is read on a stream of a list of no parts, which looks
    // none up.
    let mut stream = FrameStream::<HNil, RequestStreamKind, _>::read(&mut *io, Role::Server)
        .await
        .unwrap()
        .unwrap();
    let frame = stream.frame();
    let (length, widths) = (frame.length(), frame.widths());
    let r#type = VarIntField::new(frame.frame_type().value(), widths.type_width()).unwrap();
    (r#type, length, widths, frame.into_payload().remaining())
}

#[test]
fn a_slice_source_gives_type_length_and_payload() {
    let payload = b"hello, world";
    assert_eq!(written(0x00, payload), [&[0x00, 12][..], payload].concat());
}

#[test]
fn the_length_takes_the_shortest_width_and_reads_back() {
    let payload: Vec<u8> = (0..=255).collect();
    for (length, width) in [
        (0, VarIntWidth::One),
        (63, VarIntWidth::One),
        (64, VarIntWidth::Two),
        (256, VarIntWidth::Two),
        (16383, VarIntWidth::Two),
        (16384, VarIntWidth::Four),
    ] {
        let payload: Vec<u8> = payload.iter().copied().cycle().take(length).collect();
        let frame = nitori_call::__private::run_sync(Frame::new(
            VarInt::from_u32(0x01),
            chunks(Bytes::from(payload.clone())),
        ))
        .unwrap();
        assert_eq!(frame.widths(), FrameWidths::new(VarIntWidth::One, width));
        let mut out = Vec::new();
        out.sync_encode_unpin(frame).unwrap();
        let expected = [
            field_bytes(VarIntField::shortest(VarInt::from_u32(0x01))),
            field_bytes(VarIntField::shortest(VarInt::new(length as u64).unwrap())),
            payload.clone(),
        ]
        .concat();
        assert_eq!(out, expected);
        // And the head reads back with the same widths.
        let mut read = &out[..];
        let (_, read_length, widths, remaining) = read.sync_read_head_unpin();
        assert_eq!(widths, FrameWidths::new(VarIntWidth::One, width));
        assert_eq!(read_length.get().get(), length as u64);
        assert_eq!(remaining, length as u64);
        assert_eq!(read, &payload[..]);
    }
}

#[test]
fn a_type_takes_the_shortest_width_too() {
    assert_eq!(written(0x3f, b""), [0x3f, 0x00]);
    assert_eq!(written(0x40, b""), [0x40, 0x40, 0x00]);
    assert_eq!(written(0x4000, b""), [0x80, 0x00, 0x40, 0x00, 0x00]);
}

#[test]
fn a_payload_longer_than_the_copy_buffer_is_written_whole() {
    let payload: Vec<u8> = (0..5000u32).map(|n| (n % 251) as u8).collect();
    assert_eq!(
        written(0x00, &payload),
        [&[0x00, 0x53, 0x88][..], &payload].concat()
    );
}

#[test]
fn an_empty_payload_and_a_type_of_an_extension_are_written() {
    assert_eq!(written(0x21, &[]), [0x21, 0x00]);
}

#[test]
fn a_length_that_does_not_fit_its_width_cannot_be_made() {
    // 63 is the largest length of one byte; the field cannot hold 64.
    let error = VarIntField::new(VarInt::from_u32(64), VarIntWidth::One).unwrap_err();
    assert_eq!(error.value().get(), 64);
    assert_eq!(error.width(), VarIntWidth::One);

    let payload = [0u8; 64];
    assert_eq!(written(0x00, &payload[..63]).len(), 2 + 63);
    // One byte more takes the next width: nothing is left to refuse.
    assert_eq!(written(0x00, &payload).len(), 3 + 64);
}

/// A frame the head of which is already written is the frame read from the
/// wire: what `Frame::new` writes is what `FrameStream` reads.
#[test]
fn what_is_written_is_read_and_written_back_to_the_same_bytes() {
    let bytes = written(0x00, b"hello");
    let mut read = &bytes[..];
    let (r#type, length, widths, _) = read.sync_read_head_unpin();
    assert_eq!(frame_bytes(r#type.get(), widths, &read[..5]), bytes);
    assert_eq!(length.get().get(), 5);
}

#[test]
fn push_promise_writes_the_push_id_before_the_section() {
    let section = b"encoded field section";
    for push_id_width in [VarIntWidth::One, VarIntWidth::Four] {
        let push_id = VarIntField::new(PushId::new(VarInt::from_u32(7)), push_id_width).unwrap();
        let frame = nitori_call::__private::run_sync(Frame::new(
            PushPromiseFrameType,
            PushPromisePayload {
                push_id: ReadValue {
                    value: push_id,
                    metadata: (),
                },
                section: chunks(&section[..]),
            },
        ))
        .unwrap();
        let total = (push_id_width.encoded_len() + section.len()) as u64;
        assert_eq!(frame.length().get().get(), total);
        let mut out = Vec::new();
        out.sync_encode_unpin(frame).unwrap();
        assert_eq!(
            out,
            [
                field_bytes(VarIntField::shortest(VarInt::from_u32(0x05))),
                field_bytes(VarIntField::shortest(VarInt::new(total).unwrap())),
                field_bytes(push_id),
                section.to_vec(),
            ]
            .concat()
        );
        let mut read = &out[..];
        let (r#type, length, _, remaining) = read.sync_read_head_unpin();
        assert_eq!(r#type.get().get(), 0x05);
        assert_eq!(length.get().get(), total);
        assert_eq!(remaining, total);
    }
}

#[test]
fn push_promise_counts_the_push_id_in_the_length() {
    // 62 bytes of section and a one-byte push ID make 63, the largest
    // one-byte Length; one more byte takes the next width.
    let section = [0u8; 63];
    let push_id = ReadValue {
        value: VarIntField::shortest(PushId::new(VarInt::from_u32(1))),
        metadata: (),
    };
    for (section, head) in [
        (&section[..62], &[0x05, 63, 1][..]),
        (&section[..], &[0x05, 0x40, 64, 1][..]),
    ] {
        let frame = nitori_call::__private::run_sync(Frame::new(
            PushPromiseFrameType,
            PushPromisePayload {
                push_id,
                section: chunks(section),
            },
        ))
        .unwrap();
        let mut out = Vec::new();
        out.sync_encode_unpin(frame).unwrap();
        assert_eq!(&out[..head.len()], head);
        assert_eq!(out.len(), head.len() + section.len());
    }
}

const HTTP2_TYPES: [(u32, Http2FrameType); 4] = [
    (0x02, Http2FrameType::Priority),
    (0x06, Http2FrameType::Ping),
    (0x08, Http2FrameType::WindowUpdate),
    (0x09, Http2FrameType::Continuation),
];

#[test]
fn a_frame_of_a_type_of_http2_is_refused_before_any_byte() {
    let payload = b"payload";
    for (value, frame_type) in HTTP2_TYPES {
        for payload in [&payload[..], &[]] {
            let mut source = payload;
            let error = nitori_call::__private::run_sync(Frame::new(
                VarInt::from_u32(value),
                chunks(&mut source),
            ))
            .unwrap_err();
            assert!(
                matches!(&error, NewFrameError::Http2Type { source }
                    if source.frame_type() == frame_type),
                "{error:?}"
            );
            // The source was not read.
            assert_eq!(source, payload);
        }
    }
    // The types next to them are written.
    for value in [0x01, 0x03, 0x07, 0x0a] {
        assert_eq!(written(value, &[]), [value as u8, 0]);
    }
    // So is each type of RFC 9114.
    for frame_type in Http3FrameType::ALL {
        let frame = nitori_call::__private::run_sync(Frame::new(frame_type, chunks(&b""[..])));
        assert!(frame.is_ok());
    }
}

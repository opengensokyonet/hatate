//! Writing frames whose payload comes from a source: DATA, HEADERS, unknown
//! types and PUSH_PROMISE (RFC 9114 §7.1, §7.2.1, §7.2.2, §7.2.5).
#![feature(impl_trait_in_assoc_type)]
mod common;

use bytes::Bytes;
use common::Liar;
use frunk_core::hlist::HNil;
use hatate_wire::frame::{
    Frame, FrameWidths, Http2FrameType, PushId,
    codec::{
        CopyPayloadError, FrameLengthError, WriteFrameError, WriteFrameExt as _,
        WriteFrameHeadError, WritePushPromiseFrameError, WritePushPromiseFrameHostExt as _,
    },
};
use hatate_wire::{
    Role,
    stream::{FrameStream, kind::RequestStreamKind},
};
use nitori_call::{ReceiverAccess, call};
use nitori_io::{ExactLen, Read, Write};
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};

/// Writes a frame with this Type and Length whose payload comes from the
/// second receiver of the host, the output being the first.
#[call(sync)]
async fn write_payload<R: Read<Metadata = ()> + ExactLen<LengthError = !>, F: Write<Report = ()>>(
    out: &mut impl ReceiverAccess<Family = F>,
    payload: &mut impl ReceiverAccess<Family = R>,
    r#type: VarIntField<VarInt>,
    length: VarIntField<VarInt>,
) -> Result<(), WriteFrameError<R::Error, F::Error>>
where
    <R as ExactLen>::Length: TryInto<u64>,
{
    out.write_frame(Frame::new(r#type, length, payload)).await
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
    (
        r#type,
        length,
        widths,
        frame.into_payload().into_parts().1.remaining(),
    )
}

fn length_field(value: u64, width: VarIntWidth) -> VarIntField<VarInt> {
    VarIntField::new(VarInt::new(value).unwrap(), width).unwrap()
}

fn type_field(value: u32, width: VarIntWidth) -> VarIntField<VarInt> {
    VarIntField::new(VarInt::from_u32(value), width).unwrap()
}

fn encoded(value: u64, width: VarIntWidth) -> Vec<u8> {
    let (bytes, len) = VarIntField::new(VarInt::new(value).unwrap(), width)
        .unwrap()
        .to_encoding();
    bytes[..len].to_vec()
}

#[test]
fn a_slice_source_gives_type_length_and_payload() {
    let payload = b"hello, world";
    let mut hosts = (Vec::new(), &payload[..]);
    hosts
        .sync_write_payload_unpin(
            type_field(0x00, VarIntWidth::One),
            length_field(12, VarIntWidth::One),
        )
        .unwrap();
    assert_eq!(hosts.0, [&[0x00, 12][..], payload].concat());
    assert!(hosts.1.is_empty());
}

#[test]
fn a_bytes_source_gives_the_same_frame_at_every_width() {
    let payload: Vec<u8> = (0..=255).collect();
    for type_width in VarIntWidth::ALL {
        for length_width in [VarIntWidth::Two, VarIntWidth::Four, VarIntWidth::Eight] {
            let mut hosts = (Vec::new(), Bytes::from(payload.clone()));
            hosts
                .sync_write_payload_unpin(
                    type_field(0x01, type_width),
                    length_field(256, length_width),
                )
                .unwrap();
            let expected = [
                encoded(0x01, type_width),
                encoded(256, length_width),
                payload.clone(),
            ]
            .concat();
            assert_eq!(hosts.0, expected);
            // And the head reads back with the same widths.
            let mut written = &hosts.0[..];
            let (_, length, widths, remaining) = written.sync_read_head_unpin();
            assert_eq!(widths, FrameWidths::new(type_width, length_width));
            assert_eq!(length.get().get(), 256);
            assert_eq!(remaining, 256);
            assert_eq!(written, &payload[..]);
        }
    }
}

#[test]
fn a_payload_longer_than_the_copy_buffer_is_written_whole() {
    let payload: Vec<u8> = (0..5000u32).map(|n| (n % 251) as u8).collect();
    let mut hosts = (Vec::new(), &payload[..]);
    hosts
        .sync_write_payload_unpin(
            type_field(0x00, VarIntWidth::One),
            length_field(5000, VarIntWidth::Two),
        )
        .unwrap();
    assert_eq!(hosts.0, [&[0x00, 0x53, 0x88][..], &payload].concat());
}

#[test]
fn an_empty_payload_and_a_type_of_an_extension_are_written() {
    let mut hosts = (Vec::new(), &[][..]);
    hosts
        .sync_write_payload_unpin(
            type_field(0x21, VarIntWidth::Two),
            length_field(0, VarIntWidth::One),
        )
        .unwrap();
    assert_eq!(hosts.0, [0x40, 0x21, 0x00]);
}

#[test]
fn a_length_that_does_not_fit_its_width_cannot_be_made() {
    // 63 is the largest length of one byte; the field cannot hold 64.
    let error = VarIntField::new(VarInt::from_u32(64), VarIntWidth::One).unwrap_err();
    assert_eq!(error.value().get(), 64);
    assert_eq!(error.width(), VarIntWidth::One);

    let payload = [0u8; 64];
    let mut hosts = (Vec::new(), &payload[..63]);
    hosts
        .sync_write_payload_unpin(
            type_field(0x00, VarIntWidth::One),
            length_field(63, VarIntWidth::One),
        )
        .unwrap();
    assert_eq!(hosts.0.len(), 2 + 63);
}

#[test]
fn a_length_that_is_not_the_payload_length_is_reported_before_any_byte() {
    let payload = [0u8; 64];
    for length in [0, 63, 65, 1000] {
        let mut hosts = (Vec::new(), &payload[..]);
        let error = hosts
            .sync_write_payload_unpin(
                type_field(0x00, VarIntWidth::One),
                length_field(length, VarIntWidth::Two),
            )
            .unwrap_err();
        assert!(
            matches!(&error, WriteFrameError::Length { source }
                if source.length().get() == length && source.payload() == Some(64)),
            "{error:?}"
        );
        assert_eq!(
            error.to_string(),
            format!("frame payload length is not the Length {length}")
        );
        assert!(hosts.0.is_empty());
        assert_eq!(hosts.1.len(), 64);
    }
}

#[test]
fn a_source_shorter_than_its_reported_length_is_reported() {
    let mut hosts = (Vec::new(), Liar::new(&[1, 2, 3, 4], 10));
    let error = hosts
        .sync_write_payload_unpin(
            type_field(0x00, VarIntWidth::One),
            length_field(10, VarIntWidth::One),
        )
        .unwrap_err();
    assert!(
        matches!(&error, WriteFrameError::Payload {
            source: CopyPayloadError::ShortSource { missing }
        } if missing.get() == 6),
        "{error:?}"
    );
    // The stream is inside the frame: the head and what the source had.
    assert_eq!(hosts.0, [0x00, 10, 1, 2, 3, 4]);
}

#[test]
fn push_promise_writes_the_push_id_before_the_section() {
    let section = b"encoded field section";
    for push_id_width in [VarIntWidth::One, VarIntWidth::Four] {
        let push_id = VarIntField::new(PushId::new(VarInt::from_u32(7)), push_id_width).unwrap();
        let widths = FrameWidths::new(VarIntWidth::Two, VarIntWidth::Two);
        let mut hosts = (Vec::new(), &section[..]);
        hosts
            .sync_write_push_promise_frame_unpin(widths, push_id)
            .unwrap();
        let total = (push_id_width.encoded_len() + section.len()) as u64;
        assert_eq!(
            hosts.0,
            [
                encoded(0x05, VarIntWidth::Two),
                encoded(total, VarIntWidth::Two),
                encoded(7, push_id_width),
                section.to_vec(),
            ]
            .concat()
        );
        let mut written = &hosts.0[..];
        let (r#type, length, _, remaining) = written.sync_read_head_unpin();
        assert_eq!(r#type.get().get(), 0x05);
        assert_eq!(length.get().get(), total);
        assert_eq!(remaining, total);
    }
}

#[test]
fn push_promise_counts_the_push_id_in_the_length() {
    // 62 bytes of section and a one-byte push ID make 63, the largest
    // one-byte Length; one more byte does not fit.
    let section = [0u8; 63];
    let push_id = VarIntField::shortest(PushId::new(VarInt::from_u32(1)));
    let widths = FrameWidths::SHORTEST;
    let mut hosts = (Vec::new(), &section[..62]);
    hosts
        .sync_write_push_promise_frame_unpin(widths, push_id)
        .unwrap();
    assert_eq!(&hosts.0[..3], [0x05, 63, 1]);
    let mut hosts = (Vec::new(), &section[..]);
    let error = hosts
        .sync_write_push_promise_frame_unpin(widths, push_id)
        .unwrap_err();
    assert!(
        matches!(&error, WritePushPromiseFrameError::Length {
            source: FrameLengthError::Width { source }
        } if source.value().get() == 64),
        "{error:?}"
    );
    assert!(hosts.0.is_empty());
}

#[test]
fn push_promise_with_a_short_source_reports_what_is_missing() {
    let push_id = VarIntField::shortest(PushId::new(VarInt::from_u32(1)));
    let mut hosts = (Vec::new(), Liar::new(&[9, 9], 5));
    let error = hosts
        .sync_write_push_promise_frame_unpin(FrameWidths::SHORTEST, push_id)
        .unwrap_err();
    assert!(
        matches!(&error, WritePushPromiseFrameError::Section {
            source: CopyPayloadError::ShortSource { missing }
        } if missing.get() == 3),
        "{error:?}"
    );
    assert_eq!(hosts.0, [0x05, 6, 1, 9, 9]);
}

const HTTP2_TYPES: [(u32, Http2FrameType); 4] = [
    (0x02, Http2FrameType::Priority),
    (0x06, Http2FrameType::Ping),
    (0x08, Http2FrameType::WindowUpdate),
    (0x09, Http2FrameType::Continuation),
];

#[test]
fn a_frame_of_a_type_of_http2_is_refused_before_any_byte() {
    for (value, frame_type) in HTTP2_TYPES {
        for width in VarIntWidth::ALL {
            let mut hosts = (Vec::new(), &[][..]);
            let error = hosts
                .sync_write_payload_unpin(
                    type_field(value, width),
                    length_field(0, VarIntWidth::One),
                )
                .unwrap_err();
            assert!(
                matches!(
                    &error,
                    WriteFrameError::Head {
                        source: WriteFrameHeadError::Http2Type { source }
                    } if source.frame_type() == frame_type
                ),
                "{error:?}"
            );
            assert!(hosts.0.is_empty(), "{value:#x} {width:?}");
        }
    }
    // The types next to them are written.
    for value in [0x01, 0x03, 0x07, 0x0a] {
        let mut hosts = (Vec::new(), &[][..]);
        hosts
            .sync_write_payload_unpin(
                type_field(value, VarIntWidth::One),
                length_field(0, VarIntWidth::One),
            )
            .unwrap();
        assert_eq!(hosts.0, [value as u8, 0]);
    }
}

#[test]
fn a_payload_frame_of_a_type_of_http2_is_refused_before_any_byte() {
    let payload = b"payload";
    for (value, frame_type) in HTTP2_TYPES {
        for width in VarIntWidth::ALL {
            let mut hosts = (Vec::new(), &payload[..]);
            let error = hosts
                .sync_write_payload_unpin(
                    type_field(value, width),
                    length_field(7, VarIntWidth::One),
                )
                .unwrap_err();
            assert!(
                matches!(&error, WriteFrameError::Head {
                    source: WriteFrameHeadError::Http2Type { source }
                } if source.frame_type() == frame_type),
                "{error:?}"
            );
            assert!(hosts.0.is_empty(), "{value:#x} {width:?}");
            // The source was not read either.
            assert_eq!(hosts.1, &payload[..]);
        }
    }
}

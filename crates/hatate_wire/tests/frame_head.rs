//! Frame heads: RFC 9114 §7.1, §7.2.8 and §9.
mod common;

use common::{Dribble, run};
use core::marker::PhantomData;
use frunk_core::{HList, coproduct::Coproduct};
use hatate_wire::{
    error_code::ErrorCode,
    frame::{
        FrameHead, FrameType, FrameWidths, Http2FrameType, Http3FrameType,
        codec::{ReadFrameHeadError, ReadFrameHeadHostExt as _, WriteFrameHeadHostExt as _},
        set::FrameSet,
    },
};
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};

type Parts = HList![hatate_wire::Part];
hatate_wire::assert_claims_valid!(Parts);
type Head = FrameHead<<Parts as FrameSet>::TypeValue>;
type HeadResult = Result<Option<Head>, ReadFrameHeadError<core::convert::Infallible>>;

fn read(mut input: &[u8]) -> HeadResult {
    input.sync_read_frame_head_unpin(PhantomData::<Parts>)
}

fn var_int(value: u64, width: VarIntWidth) -> Vec<u8> {
    let mut wire = Vec::new();
    wire.sync_write_frame_head_unpin(
        VarIntField::new(VarInt::new(value).unwrap(), width).unwrap(),
        VarIntField::shortest(VarInt::from_u32(0)),
    )
    .unwrap();
    wire.pop();
    wire
}

#[test]
fn the_seven_types_of_rfc_9114_are_known() {
    for frame_type in Http3FrameType::ALL {
        let wire = [frame_type.value().get() as u8, 0x03];
        let head = read(&wire).unwrap().unwrap();
        assert_eq!(
            head.frame_type(),
            FrameType::Known(Coproduct::Inl(frame_type))
        );
        assert_eq!(head.length().get().get(), 3);
        assert_eq!(head.widths(), FrameWidths::SHORTEST);
        assert_eq!(head.payload().remaining(), 3);
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
        let head = read(&wire).unwrap().unwrap();
        assert_eq!(
            head.frame_type(),
            FrameType::Unknown(VarInt::new(value).unwrap())
        );
        assert_eq!(head.type_field().width(), width);
    }
}

#[test]
fn a_known_type_in_a_wider_encoding_is_still_known() {
    for width in VarIntWidth::ALL {
        let mut wire = var_int(0x04, width);
        wire.extend([0x00]);
        let head = read(&wire).unwrap().unwrap();
        assert_eq!(
            head.frame_type(),
            FrameType::Known(Coproduct::Inl(Http3FrameType::Settings))
        );
        assert_eq!(head.widths().type_width(), width);
    }
}

#[test]
fn http2_types_are_a_frame_unexpected_error() {
    for (value, frame_type) in [
        (0x02, Http2FrameType::Priority),
        (0x06, Http2FrameType::Ping),
        (0x08, Http2FrameType::WindowUpdate),
        (0x09, Http2FrameType::Continuation),
    ] {
        for width in VarIntWidth::ALL {
            let mut wire = var_int(value, width);
            wire.push(0);
            let error = read(&wire).unwrap_err();
            assert!(
                matches!(&error, ReadFrameHeadError::Http2Type { frame_type: found } if *found == frame_type),
                "{error:?}"
            );
            assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_UNEXPECTED));
        }
    }
}

#[test]
fn a_stream_that_ends_at_a_frame_boundary_has_no_head() {
    assert!(read(&[]).unwrap().is_none());
}

#[test]
fn a_stream_that_ends_inside_the_head_is_a_frame_error() {
    // Inside the Type: first byte promises two, four and eight bytes.
    for wire in [&[0x40][..], &[0x80, 0, 0], &[0xc0, 0, 0, 0, 0, 0, 0]] {
        let error = read(wire).unwrap_err();
        assert!(
            matches!(error, ReadFrameHeadError::Type { .. }),
            "{error:?}"
        );
        assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
    }
    // The Type is complete, the Length is missing or partial.
    for wire in [
        &[0x04][..],
        &[0x04, 0x40],
        &[0x04, 0x80, 0],
        &[0x40, 0x04, 0xc0, 1],
    ] {
        let error = read(wire).unwrap_err();
        assert!(
            matches!(error, ReadFrameHeadError::Length { .. }),
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
            let head = read(&wire).unwrap().unwrap();
            assert_eq!(head.type_field(), type_field);
            assert_eq!(head.length(), length);
            assert_eq!(head.widths(), FrameWidths::new(type_width, length_width));
            let mut again = Vec::new();
            again
                .sync_write_frame_head_unpin(head.type_field(), head.length())
                .unwrap();
            assert_eq!(again, wire);
        }
    }
}

#[test]
fn the_head_reads_the_same_with_a_pending_between_every_byte() {
    let wire = [0xc0, 0, 0, 0, 0, 0, 0, 0x07, 0x80, 0, 0x01, 0x00, 0xaa];
    let expected = read(&wire).unwrap().unwrap();
    let mut host = Dribble::new(&wire, 1);
    let (head, pending) = run(host.read_frame_head_unpin(PhantomData::<Parts>));
    assert_eq!(head.unwrap().unwrap(), expected);
    assert!(pending >= 12, "{pending}");
    assert_eq!(host.rest(), [0xaa]);
}

#[test]
fn only_the_head_is_consumed() {
    let mut input = &[0x01, 0x02, 0xaa, 0xbb, 0x00, 0x00][..];
    let head = input
        .sync_read_frame_head_unpin(PhantomData::<Parts>)
        .unwrap()
        .unwrap();
    assert_eq!(head.length().get().get(), 2);
    assert_eq!(input, [0xaa, 0xbb, 0x00, 0x00]);
}

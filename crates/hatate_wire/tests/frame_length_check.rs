//! A frame is written with a payload of exactly its Length: one that writes
//! more or fewer bytes panics rather than leave a head that does not match.
mod common;

use common::Liar;
use hatate_wire::frame::{DataFrameType, Frame};
use nitori_call::ConstructedAccess;
use nitori_codec::{payload::Buffered, prelude::*};
use nitori_io::calls::ReadValue;
use sakuya_var_int::{VarInt, VarIntField};

fn buffered(
    data: &'static [u8],
    claimed: usize,
) -> Buffered<ConstructedAccess<Liar<'static>>, [u8; 4]> {
    Buffered {
        source: ConstructedAccess::new(Liar::new(data, claimed)),
        buffer: [0; 4],
    }
}

#[test]
#[should_panic(expected = "ended 1 bytes before its Length 3")]
fn a_source_shorter_than_its_length_panics() {
    let frame =
        nitori_call::__private::run_sync(Frame::new(DataFrameType, buffered(b"ab", 3))).unwrap();
    let _ = Vec::new().sync_encode_unpin(frame);
}

#[test]
#[should_panic(expected = "wrote more than its Length 2")]
fn a_source_longer_than_its_length_panics() {
    let frame =
        nitori_call::__private::run_sync(Frame::new(DataFrameType, buffered(b"abc", 2))).unwrap();
    let _ = Vec::new().sync_encode_unpin(frame);
}

#[test]
#[should_panic(expected = "wrote more than its Length 1")]
fn a_payload_swapped_for_a_longer_one_panics() {
    let short = ReadValue {
        value: VarIntField::shortest(VarInt::from_u32(1)),
        metadata: (),
    };
    let frame = nitori_call::__private::run_sync(Frame::new(DataFrameType, short)).unwrap();
    let longer = frame.map_payload(|_| ReadValue {
        value: VarIntField::shortest(VarInt::from_u32(300)),
        metadata: (),
    });
    let _ = Vec::new().sync_encode_unpin(longer);
}

#[test]
fn a_source_that_keeps_its_length_is_written_whole() {
    let frame =
        nitori_call::__private::run_sync(Frame::new(DataFrameType, buffered(b"abc", 3))).unwrap();
    let mut out = Vec::new();
    out.sync_encode_unpin(frame).unwrap();
    assert_eq!(out, b"\x00\x03abc");
}

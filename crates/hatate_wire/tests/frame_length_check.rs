//! A frame is written with a payload of exactly its Length: one that writes
//! more is stopped at the Length and fails with its own error, one that
//! writes fewer fails the frame, and neither panics.
mod common;

use common::{Liar, Quota, run};
use hatate_wire::frame::{DataFrameType, Frame, codec::EncodeFrameError};
use nitori_call::ConstructedAccess;
use nitori_codec::{
    payload::{Buffered, Fill},
    prelude::*,
};
use nitori_io::calls::{CopyIntoLentError, ReadValue};
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
fn a_source_shorter_than_its_length_fails_the_frame() {
    let frame =
        nitori_call::__private::run_sync(Frame::new(DataFrameType, buffered(b"ab", 3))).unwrap();
    let mut out = Vec::new();
    let Err(EncodeFrameError::ShortPayload { source }) = out.sync_encode_unpin(frame) else {
        panic!("expected a short payload");
    };
    assert_eq!((source.length(), source.missing().get()), (3, 1));
    assert_eq!(out, b"\x00\x03ab");
}

#[test]
fn a_source_longer_than_its_length_stops_at_it() {
    let frame =
        nitori_call::__private::run_sync(Frame::new(DataFrameType, buffered(b"abc", 2))).unwrap();
    let mut out = Vec::new();
    assert!(matches!(
        out.sync_encode_unpin(frame),
        Err(EncodeFrameError::Payload { .. })
    ));
    // Nothing beyond the Length reaches the sink.
    assert_eq!(out, b"\x00\x02ab");
}

#[test]
fn a_payload_swapped_for_a_longer_one_stops_at_the_length() {
    let short = ReadValue {
        value: VarIntField::shortest(VarInt::from_u32(1)),
        metadata: (),
    };
    let frame = nitori_call::__private::run_sync(Frame::new(DataFrameType, short)).unwrap();
    let longer = frame.map_payload(|_| ReadValue {
        value: VarIntField::shortest(VarInt::from_u32(300)),
        metadata: (),
    });
    let mut out = Vec::new();
    assert!(matches!(
        out.sync_encode_unpin(longer),
        Err(EncodeFrameError::Payload { .. })
    ));
    // 300 takes two bytes; the Length of 1 holds the first.
    assert_eq!(out, b"\x00\x01\x41");
}

#[test]
fn a_source_that_keeps_its_length_is_written_whole() {
    let frame =
        nitori_call::__private::run_sync(Frame::new(DataFrameType, buffered(b"abc", 3))).unwrap();
    let mut out = Vec::new();
    out.sync_encode_unpin(frame).unwrap();
    assert_eq!(out, b"\x00\x03abc");
}

fn fill(data: &'static [u8], claimed: usize) -> Fill<ConstructedAccess<Liar<'static>>> {
    Fill {
        source: ConstructedAccess::new(Liar::new(data, claimed)),
        chunk_maximum: core::num::NonZeroUsize::new(16).unwrap(),
    }
}

/// A sink that goes `Pending` once full still takes a whole frame that fills
/// it exactly: the payload's last loan is not asked of the sink below.
#[test]
fn a_filled_payload_is_written_to_a_sink_that_is_then_full() {
    let frame =
        nitori_call::__private::run_sync(Frame::new(DataFrameType, fill(b"abc", 3))).unwrap();
    let mut sink = ConstructedAccess::new(Quota::new(5));
    let (result, _) = run(frame.encode_into(&mut sink));
    result.unwrap();
    assert_eq!(sink.get_ref().written(), b"\x00\x03abc");
}

/// A source longer than its Length ends the copy with the copy's no-progress
/// error; what was written is the head and the Length.
#[test]
fn a_filled_source_longer_than_its_length_fails_without_panicking() {
    let frame =
        nitori_call::__private::run_sync(Frame::new(DataFrameType, fill(b"abcd", 3))).unwrap();
    let mut sink = ConstructedAccess::new(Quota::new(100));
    let (result, _) = run(frame.encode_into(&mut sink));
    let Err(EncodeFrameError::Payload {
        source: CopyIntoLentError::WriteZero { .. },
    }) = result
    else {
        panic!("expected a WriteZero payload error");
    };
    assert_eq!(sink.get_ref().written(), b"\x00\x03abc");
}

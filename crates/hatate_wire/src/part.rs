//! The part of RFC 9114, with the registrations of QPACK.
use crate::{
    frame::{Http3FrameType, set::FramePart},
    registry::ClaimedValues,
    settings::{MaxFieldSectionSize, set::SettingsPart},
    stream_type::{Http3StreamType, StreamTypePart},
};
use frunk_core::HList;
use hatate_wire_qpack::{QpackBlockedStreams, QpackMaxTableCapacity};
use sakuya_var_int::VarInt;

/// The part of RFC 9114: its frame types, its settings and QPACK's, and its
/// unidirectional stream types and QPACK's. Every connection's list of
/// parts holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Part;

const fn v(value: u32) -> VarInt {
    VarInt::from_u32(value)
}

impl FramePart for Part {
    type Kind = Http3FrameType;
    type TypeValue = Http3FrameType;
    const FRAME_TYPES: &'static ClaimedValues = &ClaimedValues::new(&[
        v(0x00)..=v(0x01),
        v(0x03)..=v(0x05),
        v(0x07)..=v(0x07),
        v(0x0d)..=v(0x0d),
    ]);

    fn type_value_of(value: VarInt) -> Option<Http3FrameType> {
        Http3FrameType::of(value)
    }

    fn value_of(type_value: Http3FrameType) -> VarInt {
        type_value.value()
    }

    fn kind_of(type_value: Http3FrameType) -> Http3FrameType {
        type_value
    }
}

impl SettingsPart for Part {
    type Settings = HList![
        QpackMaxTableCapacity,
        MaxFieldSectionSize,
        QpackBlockedStreams
    ];
}

impl StreamTypePart for Part {
    type Kind = Http3StreamType;
    type TypeValue = Http3StreamType;
    const STREAM_TYPES: &'static ClaimedValues = &ClaimedValues::new(&[v(0x00)..=v(0x03)]);

    fn type_value_of(value: VarInt) -> Option<Http3StreamType> {
        Http3StreamType::of(value)
    }

    fn value_of(type_value: Http3StreamType) -> VarInt {
        type_value.value()
    }

    fn kind_of(type_value: Http3StreamType) -> Http3StreamType {
        type_value
    }
}

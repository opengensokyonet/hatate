//! The part of RFC 9114, with the registrations of QPACK.
use crate::{
    frame::{
        ControlFrameType, PushFrameType, RequestFrameType,
        set::{FramePart, FramePartOn},
    },
    registry::ClaimedValues,
    settings::{MaxFieldSectionSize, set::SettingsPart},
    stream::kind::{ControlStreamKind, PushStreamKind, RequestStreamKind},
    stream_type::StreamTypePart,
};
use frunk_core::HList;
use hatate_wire_qpack::{QpackBlockedStreams, QpackMaxTableCapacity};
use sakuya_var_int::VarInt;

/// The part of RFC 9114: its frame types, its settings and QPACK's, its
/// unidirectional stream types and QPACK's, and its streams
/// ([`stream::http3`](crate::stream::http3)). Every connection's list of
/// parts holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Part;

const fn v(value: u32) -> VarInt {
    VarInt::from_u32(value)
}

impl FramePart for Part {
    const FRAME_TYPES: &'static ClaimedValues = &ClaimedValues::new(&[
        v(0x00)..=v(0x01),
        v(0x03)..=v(0x05),
        v(0x07)..=v(0x07),
        v(0x0d)..=v(0x0d),
    ]);
}

impl FramePartOn<RequestStreamKind> for Part {
    type FrameType = RequestFrameType;
}

impl FramePartOn<ControlStreamKind> for Part {
    type FrameType = ControlFrameType;
}

impl FramePartOn<PushStreamKind> for Part {
    type FrameType = PushFrameType;
}

impl SettingsPart for Part {
    type Settings = HList![
        QpackMaxTableCapacity,
        MaxFieldSectionSize,
        QpackBlockedStreams
    ];
}

impl StreamTypePart for Part {
    const STREAM_TYPES: &'static ClaimedValues = &ClaimedValues::new(&[v(0x00)..=v(0x03)]);
}

//! The part of RFC 9114, with the registrations of QPACK.
use crate::{
    frame::{Http3FrameType, set::FramePart},
    registry::ClaimedValues,
    settings::{Http3Setting, Http3SettingIdentifier, set::SettingsPart},
    stream_type::{Http3StreamType, StreamTypePart},
};
use core::convert::Infallible;
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};

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
    type Identifier = Http3SettingIdentifier;
    type Setting = Http3Setting;
    type ValueError = Infallible;
    type Occurrences = [bool; 3];
    const SETTING_IDENTIFIERS: &'static ClaimedValues =
        &ClaimedValues::new(&[v(0x01)..=v(0x01), v(0x06)..=v(0x07)]);

    fn identifier_of(value: VarInt) -> Option<Http3SettingIdentifier> {
        Http3SettingIdentifier::of(value)
    }

    fn setting_of(
        identifier: Http3SettingIdentifier,
        identifier_width: VarIntWidth,
        value: VarIntField<VarInt>,
    ) -> Result<Http3Setting, Infallible> {
        Ok(Http3Setting::with_identifier_width(
            identifier,
            identifier_width,
            value,
        ))
    }

    fn identifier(setting: &Http3Setting) -> Http3SettingIdentifier {
        setting.identifier()
    }

    fn fields(setting: &Http3Setting) -> (VarIntField<VarInt>, VarIntField<VarInt>) {
        // invariant: every width holds these identifiers.
        let identifier = VarIntField::new(setting.identifier().value(), setting.identifier_width())
            .expect("every width holds an identifier below 64");
        (identifier, setting.value())
    }

    fn record(occurrences: &mut [bool; 3], identifier: Http3SettingIdentifier) -> bool {
        !core::mem::replace(&mut occurrences[identifier.index()], true)
    }
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

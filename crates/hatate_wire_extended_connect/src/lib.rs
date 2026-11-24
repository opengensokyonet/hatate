//! Extended CONNECT on HTTP/3 ([RFC 9220]): the wire part.
//!
//! The extension adds one setting, SETTINGS_ENABLE_CONNECT_PROTOCOL
//! (0x08), with which a server lets the client send Extended CONNECT
//! requests ([RFC 8441 §3]). Put [`Part`] in a connection's list of parts to
//! read it; without it, the setting is unknown and ignored.
//!
//! [RFC 9220]: https://www.rfc-editor.org/rfc/rfc9220.html
//! [RFC 8441 §3]: https://www.rfc-editor.org/rfc/rfc8441.html#section-3
#![no_std]
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::alloc_instead_of_core
)]

use frunk_core::coproduct::CNil;
use hatate_wire::{
    frame::set::FramePart, registry::ClaimedValues, settings::set::SettingsPart,
    stream_type::StreamTypePart,
};
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};
use snafu::Snafu;

/// The part of Extended CONNECT: one setting, no frame types or stream
/// types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Part;

/// The identifier SETTINGS_ENABLE_CONNECT_PROTOCOL (0x08), the only one this
/// part claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EnableConnectProtocolSettingIdentifier;

impl EnableConnectProtocolSettingIdentifier {
    /// The identifier on the wire.
    pub const VALUE: VarInt = VarInt::from_u32(0x08);
}

/// A SETTINGS_ENABLE_CONNECT_PROTOCOL setting: 0 or 1, with the widths of
/// its identifier and value on the wire. 1 lets the client use Extended
/// CONNECT; a server's own setting has no effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EnableConnectProtocolSetting {
    identifier_width: VarIntWidth,
    value: VarIntField<VarInt>,
}

impl EnableConnectProtocolSetting {
    /// The setting with value 1 if `enabled`, else 0, both in their
    /// shortest encodings.
    pub fn new(enabled: bool) -> Self {
        Self {
            identifier_width: VarIntWidth::One,
            value: VarIntField::shortest(VarInt::from_u32(u32::from(enabled))),
        }
    }

    /// The setting `value` with its identifier at `identifier_width`.
    ///
    /// # Errors
    ///
    /// [`EnableConnectProtocolValueError`] if the value is neither 0 nor 1.
    pub fn with_widths(
        identifier_width: VarIntWidth,
        value: VarIntField<VarInt>,
    ) -> Result<Self, EnableConnectProtocolValueError> {
        if value.get().get() > 1 {
            return Err(EnableConnectProtocolValueError { value: value.get() });
        }
        Ok(Self {
            identifier_width,
            value,
        })
    }

    /// Whether the value is 1.
    pub fn enabled(&self) -> bool {
        self.value.get().get() == 1
    }

    /// The width of the identifier.
    pub const fn identifier_width(&self) -> VarIntWidth {
        self.identifier_width
    }

    /// The value as it is on the wire.
    pub const fn value(&self) -> VarIntField<VarInt> {
        self.value
    }
}

/// A SETTINGS_ENABLE_CONNECT_PROTOCOL value other than 0 or 1.
///
/// [RFC 8441 §3] requires the value to be 0 or 1 and says nothing of a
/// receiver that gets another; this crate rejects it as a connection error
/// of type H3_SETTINGS_ERROR, which RFC 9114 defines for a SETTINGS frame
/// whose contents are invalid ([RFC 9114 §8.1]).
///
/// [RFC 8441 §3]: https://www.rfc-editor.org/rfc/rfc8441.html#section-3
/// [RFC 9114 §8.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-8.1
#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
#[snafu(display("SETTINGS_ENABLE_CONNECT_PROTOCOL is {} rather than 0 or 1", value.get()))]
pub struct EnableConnectProtocolValueError {
    value: VarInt,
}

impl EnableConnectProtocolValueError {
    /// The value received.
    pub const fn value(&self) -> VarInt {
        self.value
    }
}

impl SettingsPart for Part {
    type Identifier = EnableConnectProtocolSettingIdentifier;
    type Setting = EnableConnectProtocolSetting;
    type ValueError = EnableConnectProtocolValueError;
    type Occurrences = bool;
    const SETTING_IDENTIFIERS: &'static ClaimedValues =
        &ClaimedValues::new(&[EnableConnectProtocolSettingIdentifier::VALUE
            ..=EnableConnectProtocolSettingIdentifier::VALUE]);

    fn identifier_of(value: VarInt) -> Option<EnableConnectProtocolSettingIdentifier> {
        (value == EnableConnectProtocolSettingIdentifier::VALUE)
            .then_some(EnableConnectProtocolSettingIdentifier)
    }

    fn setting_of(
        _identifier: EnableConnectProtocolSettingIdentifier,
        identifier_width: VarIntWidth,
        value: VarIntField<VarInt>,
    ) -> Result<EnableConnectProtocolSetting, EnableConnectProtocolValueError> {
        EnableConnectProtocolSetting::with_widths(identifier_width, value)
    }

    fn identifier(
        _setting: &EnableConnectProtocolSetting,
    ) -> EnableConnectProtocolSettingIdentifier {
        EnableConnectProtocolSettingIdentifier
    }

    fn fields(
        setting: &EnableConnectProtocolSetting,
    ) -> (VarIntField<VarInt>, VarIntField<VarInt>) {
        // invariant: every width holds 0x08.
        let identifier = VarIntField::new(
            EnableConnectProtocolSettingIdentifier::VALUE,
            setting.identifier_width,
        )
        .expect("every width holds the identifier 0x08");
        (identifier, setting.value)
    }

    fn record(occurrences: &mut bool, _identifier: EnableConnectProtocolSettingIdentifier) -> bool {
        !core::mem::replace(occurrences, true)
    }
}

impl FramePart for Part {
    type Kind = CNil;
    type TypeValue = CNil;
    const FRAME_TYPES: &'static ClaimedValues = &ClaimedValues::NONE;

    fn type_value_of(_value: VarInt) -> Option<CNil> {
        None
    }

    fn value_of(type_value: CNil) -> VarInt {
        match type_value {}
    }

    fn kind_of(type_value: CNil) -> CNil {
        match type_value {}
    }
}

impl StreamTypePart for Part {
    type Kind = CNil;
    type TypeValue = CNil;
    const STREAM_TYPES: &'static ClaimedValues = &ClaimedValues::NONE;

    fn type_value_of(_value: VarInt) -> Option<CNil> {
        None
    }

    fn value_of(type_value: CNil) -> VarInt {
        match type_value {}
    }

    fn kind_of(type_value: CNil) -> CNil {
        match type_value {}
    }
}

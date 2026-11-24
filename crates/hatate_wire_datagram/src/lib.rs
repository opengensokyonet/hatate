//! HTTP Datagrams on HTTP/3 ([RFC 9297 §2.1]): the wire part.
//!
//! The extension adds the setting SETTINGS_H3_DATAGRAM (0x33), with which an
//! endpoint states that it is willing to receive HTTP/3 datagrams, and the
//! format of those datagrams in the payload of a QUIC DATAGRAM frame: a
//! Quarter Stream ID, then the HTTP Datagram Payload. Put [`Part`] in a
//! connection's list of parts to read the setting.
//!
//! A datagram is read and written whole in memory, as QUIC delivers it:
//! [`read_datagram`] and [`write_datagram`].
//!
//! [RFC 9297 §2.1]: https://www.rfc-editor.org/rfc/rfc9297.html#section-2.1
#![no_std]
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::alloc_instead_of_core
)]

use bytes::{Buf, BufMut};
use frunk_core::coproduct::CNil;
use hatate_wire::{
    error_code::{ErrorCode, ErrorCodeOf},
    frame::set::FramePart,
    registry::ClaimedValues,
    settings::set::SettingsPart,
    stream_type::StreamTypePart,
};
use sakuya_var_int::{
    VarInt, VarIntField, VarIntWidth,
    codec::{ReadVarIntFieldError, read_var_int_field, write_var_int_field},
};
use snafu::{ResultExt, Snafu};

/// H3_DATAGRAM_ERROR (0x33): a datagram is malformed ([RFC 9297 §2.1]).
///
/// [RFC 9297 §2.1]: https://www.rfc-editor.org/rfc/rfc9297.html#section-2.1
pub const H3_DATAGRAM_ERROR: ErrorCode = ErrorCode::new(VarInt::from_u32(0x33));

/// The part of HTTP Datagrams: one setting, no frame types or stream types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Part;

/// The identifier SETTINGS_H3_DATAGRAM (0x33), the only one this part
/// claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct H3DatagramSettingIdentifier;

impl H3DatagramSettingIdentifier {
    /// The identifier on the wire.
    pub const VALUE: VarInt = VarInt::from_u32(0x33);
}

/// A SETTINGS_H3_DATAGRAM setting: 0 or 1, with the widths of its
/// identifier and value on the wire. 1 states that the sender is willing to
/// receive HTTP/3 datagrams ([RFC 9297 §2.1.1]).
///
/// [RFC 9297 §2.1.1]: https://www.rfc-editor.org/rfc/rfc9297.html#section-2.1.1
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct H3DatagramSetting {
    identifier_width: VarIntWidth,
    value: VarIntField<VarInt>,
}

impl H3DatagramSetting {
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
    /// [`H3DatagramValueError`] if the value is neither 0 nor 1.
    pub fn with_widths(
        identifier_width: VarIntWidth,
        value: VarIntField<VarInt>,
    ) -> Result<Self, H3DatagramValueError> {
        if value.get().get() > 1 {
            return Err(H3DatagramValueError { value: value.get() });
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

/// A SETTINGS_H3_DATAGRAM value other than 0 or 1: a connection error of
/// type H3_SETTINGS_ERROR ([RFC 9297 §2.1.1]).
///
/// [RFC 9297 §2.1.1]: https://www.rfc-editor.org/rfc/rfc9297.html#section-2.1.1
#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
#[snafu(display("SETTINGS_H3_DATAGRAM is {} rather than 0 or 1", value.get()))]
pub struct H3DatagramValueError {
    value: VarInt,
}

impl H3DatagramValueError {
    /// The value received.
    pub const fn value(&self) -> VarInt {
        self.value
    }
}

impl SettingsPart for Part {
    type Identifier = H3DatagramSettingIdentifier;
    type Setting = H3DatagramSetting;
    type ValueError = H3DatagramValueError;
    type Occurrences = bool;
    const SETTING_IDENTIFIERS: &'static ClaimedValues = &ClaimedValues::new(&[
        H3DatagramSettingIdentifier::VALUE..=H3DatagramSettingIdentifier::VALUE,
    ]);

    fn identifier_of(value: VarInt) -> Option<H3DatagramSettingIdentifier> {
        (value == H3DatagramSettingIdentifier::VALUE).then_some(H3DatagramSettingIdentifier)
    }

    fn setting_of(
        _identifier: H3DatagramSettingIdentifier,
        identifier_width: VarIntWidth,
        value: VarIntField<VarInt>,
    ) -> Result<H3DatagramSetting, H3DatagramValueError> {
        H3DatagramSetting::with_widths(identifier_width, value)
    }

    fn identifier(_setting: &H3DatagramSetting) -> H3DatagramSettingIdentifier {
        H3DatagramSettingIdentifier
    }

    fn fields(setting: &H3DatagramSetting) -> (VarIntField<VarInt>, VarIntField<VarInt>) {
        // invariant: every width holds 0x33.
        let identifier =
            VarIntField::new(H3DatagramSettingIdentifier::VALUE, setting.identifier_width)
                .expect("every width holds the identifier 0x33");
        (identifier, setting.value)
    }

    fn record(occurrences: &mut bool, _identifier: H3DatagramSettingIdentifier) -> bool {
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

/// A Quarter Stream ID: the ID of the client-initiated bidirectional stream
/// a datagram belongs to, divided by four. At most 2^60 − 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QuarterStreamId(VarInt);

impl QuarterStreamId {
    /// The largest Quarter Stream ID, 2^60 − 1.
    pub const MAX: Self = Self(match VarInt::new((1 << 60) - 1) {
        Ok(value) => value,
        Err(_) => panic!("2^60 - 1 is a variable-length integer"),
    });

    /// The Quarter Stream ID of the stream `stream_id`, or `None` if it is
    /// not a client-initiated bidirectional stream (its two low bits are not
    /// zero).
    pub const fn of_stream_id(stream_id: VarInt) -> Option<Self> {
        if !stream_id.get().is_multiple_of(4) {
            return None;
        }
        match VarInt::new(stream_id.get() / 4) {
            Ok(value) => Some(Self(value)),
            Err(_) => None,
        }
    }

    /// The Quarter Stream ID.
    pub const fn get(self) -> VarInt {
        self.0
    }

    /// The ID of the stream: four times the Quarter Stream ID.
    pub const fn stream_id(self) -> VarInt {
        match VarInt::new(self.0.get() * 4) {
            Ok(value) => value,
            Err(_) => panic!("a Quarter Stream ID times four is below 2^62"),
        }
    }
}

impl TryFrom<VarInt> for QuarterStreamId {
    type Error = QuarterStreamIdError;

    fn try_from(value: VarInt) -> Result<Self, Self::Error> {
        if value <= Self::MAX.0 {
            Ok(Self(value))
        } else {
            Err(QuarterStreamIdError { value })
        }
    }
}

impl From<QuarterStreamId> for VarInt {
    fn from(id: QuarterStreamId) -> Self {
        id.0
    }
}

/// A Quarter Stream ID above 2^60 − 1: a connection error of type
/// [`H3_DATAGRAM_ERROR`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
#[snafu(display("Quarter Stream ID {} exceeds 2^60 - 1", value.get()))]
pub struct QuarterStreamIdError {
    value: VarInt,
}

impl QuarterStreamIdError {
    /// The value received.
    pub const fn value(&self) -> VarInt {
        self.value
    }
}

/// An HTTP/3 datagram: the payload of a QUIC DATAGRAM frame.
///
/// `D` is the type of the HTTP Datagram Payload: the source the datagram
/// was read from, or any [`Buf`] to write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Datagram<D> {
    quarter_stream_id: VarIntField<QuarterStreamId>,
    payload: D,
}

impl<D> Datagram<D> {
    /// The datagram of `quarter_stream_id` carrying `payload`, which may
    /// be empty.
    pub const fn new(quarter_stream_id: VarIntField<QuarterStreamId>, payload: D) -> Self {
        Self {
            quarter_stream_id,
            payload,
        }
    }

    /// The Quarter Stream ID.
    pub const fn quarter_stream_id(&self) -> VarIntField<QuarterStreamId> {
        self.quarter_stream_id
    }

    /// The HTTP Datagram Payload.
    pub const fn payload(&self) -> &D {
        &self.payload
    }

    /// Takes the HTTP Datagram Payload.
    pub fn into_payload(self) -> D {
        self.payload
    }
}

/// Reads an HTTP/3 datagram from the whole payload of a QUIC DATAGRAM frame;
/// the HTTP Datagram Payload is what follows the Quarter Stream ID.
///
/// # Errors
///
/// [`ReadDatagramError`]: the payload is too short for the Quarter Stream
/// ID, or the value exceeds 2^60 − 1.
pub fn read_datagram<S: Buf>(mut source: S) -> Result<Datagram<S>, ReadDatagramError> {
    let quarter_stream_id = read_var_int_field(&mut source).context(ReadDatagramSnafu)?;
    Ok(Datagram {
        quarter_stream_id,
        payload: source,
    })
}

/// The Quarter Stream ID of a datagram could not be read: the payload is too
/// short for it, or it exceeds 2^60 − 1. Either is a connection error of
/// type [`H3_DATAGRAM_ERROR`] ([RFC 9297 §2.1]).
///
/// [RFC 9297 §2.1]: https://www.rfc-editor.org/rfc/rfc9297.html#section-2.1
#[derive(Debug, Snafu)]
#[snafu(display("malformed HTTP/3 datagram"))]
pub struct ReadDatagramError {
    source: ReadVarIntFieldError<QuarterStreamIdError>,
}

impl ReadDatagramError {
    /// The failure of reading the Quarter Stream ID.
    pub const fn read_error(&self) -> &ReadVarIntFieldError<QuarterStreamIdError> {
        &self.source
    }
}

/// Always [`H3_DATAGRAM_ERROR`].
impl ErrorCodeOf<ErrorCode> for ReadDatagramError {
    fn error_code(&self) -> Option<ErrorCode> {
        Some(H3_DATAGRAM_ERROR)
    }
}

/// Writes `datagram`: the Quarter Stream ID at its width, then the payload.
///
/// # Panics
///
/// If `dst` has no room, as [`BufMut::put`] does.
pub fn write_datagram(dst: &mut impl BufMut, datagram: Datagram<impl Buf>) {
    write_var_int_field(dst, datagram.quarter_stream_id);
    dst.put(datagram.payload);
}

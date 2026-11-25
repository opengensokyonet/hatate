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
use frunk_core::{HList, coproduct::CNil};
use hatate_wire::{
    error_code::{ErrorCode, ErrorCodeOf},
    frame::set::{FramePart, FramePartOn},
    registry::ClaimedValues,
    settings::{KeyedSetting, set::SettingsPart},
    stream::{
        class::StreamClass,
        kind::StreamKind,
        part::{StreamPart, StreamVerdict},
    },
    stream_type::StreamTypePart,
};
use nitori_call::ReceiverAccess;
use nitori_io::Read;
use sakuya_var_int::{
    VarInt, VarIntField,
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

/// SETTINGS_H3_DATAGRAM (0x33): 0 or 1. 1 states that the sender is willing
/// to receive HTTP/3 datagrams ([RFC 9297 §2.1.1]).
///
/// [RFC 9297 §2.1.1]: https://www.rfc-editor.org/rfc/rfc9297.html#section-2.1.1
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct H3Datagram {
    value: VarIntField<VarInt>,
}

impl H3Datagram {
    /// The setting with value 1 if `enabled`, else 0, in its shortest
    /// encoding.
    pub fn new(enabled: bool) -> Self {
        Self {
            value: VarIntField::shortest(VarInt::from_u32(u32::from(enabled))),
        }
    }

    /// Whether the value is 1.
    pub fn enabled(&self) -> bool {
        self.value.get().get() == 1
    }

    /// The value as it is on the wire.
    pub const fn value(&self) -> VarIntField<VarInt> {
        self.value
    }
}

impl KeyedSetting for H3Datagram {
    type ValueError = H3DatagramValueError;
    const IDENTIFIER: VarInt = VarInt::from_u32(0x33);

    fn from_value(value: VarIntField<VarInt>) -> Result<Self, H3DatagramValueError> {
        if value.get().get() > 1 {
            return Err(H3DatagramValueError { value: value.get() });
        }
        Ok(Self { value })
    }

    fn value(&self) -> VarIntField<VarInt> {
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
    type Settings = HList![H3Datagram];
}

impl FramePart for Part {
    const FRAME_TYPES: &'static ClaimedValues = &ClaimedValues::NONE;
}

/// No frame types, on any kind of stream.
impl<K: StreamKind> FramePartOn<K> for Part {
    type FrameType = CNil;
}

impl StreamTypePart for Part {
    const STREAM_TYPES: &'static ClaimedValues = &ClaimedValues::NONE;
}

/// No streams of its own, in any class.
impl<C: StreamClass, L> StreamPart<C, L> for Part {
    type Claimed = CNil;
    type Rejection = CNil;
    type Stream<I> = CNil;
    type ReadError<E> = CNil;

    fn judge(_value: VarInt, _skipped: bool) -> StreamVerdict<CNil, CNil> {
        StreamVerdict::NotClaimed
    }

    async fn read<I: ReceiverAccess<Family: Read<Metadata = ()>>>(
        claimed: CNil,
        _field: VarIntField<VarInt>,
        _io: I,
    ) -> Result<CNil, CNil> {
        match claimed {}
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
